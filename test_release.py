import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import prm_release as release
import rule_changes
from schedule import due_slot
import verify_release

def bundle(**entries):
    return {
        "rule-providers": {name: {"payload": payload} for name, payload in entries.items()},
        "rules": [f"RULE-SET,{name},{name}" for name in entries] + ["MATCH,fallback"],
    }


class ScheduleTests(unittest.TestCase):
    def test_due_slot_uses_the_last_shanghai_calendar_trigger(self):
        self.assertEqual(due_slot(datetime(2026, 11, 26, 21, 29, tzinfo=timezone.utc)), "2026-11-26")
        self.assertEqual(due_slot(datetime(2026, 11, 26, 21, 30, tzinfo=timezone.utc)), "2026-11-27")


class RuleChangeTests(unittest.TestCase):
    def test_suffix_rule_does_not_cover_a_different_domain(self):
        prior = bundle(domestic=["DOMAIN-SUFFIX,example.org"])
        candidate = bundle(domestic=["DOMAIN,example.org"])
        result = rule_changes.compare(prior, candidate)
        self.assertEqual(result[0]["status"], "review")
        self.assertEqual(result[0]["samples"], ["home-rule-probe.example.org"])

    def test_exact_covered_by_same_suffix_is_equivalent(self):
        prior = bundle(domestic=["DOMAIN-SUFFIX,example.org", "DOMAIN,api.example.org"])
        candidate = bundle(domestic=["DOMAIN-SUFFIX,example.org"])
        self.assertEqual(rule_changes.compare(prior, candidate), [])

    def test_opted_in_ordinary_coverage_expansion(self):
        prior = bundle(domestic=["DOMAIN-SUFFIX,example.org"])
        candidate = bundle(domestic=["DOMAIN-SUFFIX,example.org", "DOMAIN,new.example.net"])
        result = rule_changes.compare(prior, candidate, ["domestic"])
        self.assertEqual(result[0]["status"], "allowed")

    def test_cidr_partial_deletion_keeps_uncovered_range_visible(self):
        prior = bundle(domestic=["IP-CIDR,192.0.2.0/24,no-resolve"])
        candidate = bundle(domestic=["IP-CIDR,192.0.2.0/25,no-resolve"])
        result = rule_changes.compare(prior, candidate)
        self.assertEqual(result[0]["samples"], ["192.0.2.128–192.0.2.255"])

    def test_removed_no_resolve_changes_domain_resolution(self):
        prior = bundle(domestic=["IP-CIDR6,2001:db8::/120,no-resolve"])
        candidate = bundle(domestic=["IP-CIDR6,2001:db8::/120"])
        result = rule_changes.compare(prior, candidate)
        self.assertEqual(result[0]["kind"], "ipv6-resolved")
        self.assertEqual(result[0]["status"], "review")

    def test_openai_subdomains_require_suffix_coverage(self):
        profile = bundle(
            openai=[f"DOMAIN-SUFFIX,{suffix}" for suffix in verify_release.OPENAI_SUFFIXES],
            domestic=[f"DOMAIN,{host}" for host in verify_release.DOMESTIC_ANCHORS],
        )
        providers = profile["rule-providers"]
        verify_release.check_policy(providers, profile["rules"])
        providers["openai"]["payload"][1] = "DOMAIN,openai.com"
        with self.assertRaisesRegex(ValueError, r"suffix coverage lost: openai\.com"):
            verify_release.check_policy(providers, profile["rules"])


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        with_config = tempfile.TemporaryDirectory()
        self.addCleanup(with_config.cleanup)
        root = Path(with_config.name)
        patch_state = patch.multiple(release, STATE=root, RELEASES=root / "releases")
        patch_state.start()
        self.addCleanup(patch_state.stop)
        release.RELEASES.mkdir()
        self.rule = {"id": "ordinary", "name": "ordinary", "outputs": ["mihomo"], "sources": [
            {"url": "https://raw.githubusercontent.com/org/repo/" + "a" * 40 + "/ordinary.list"}
        ]}

    def test_unapproved_prm_rule_changes_are_rejected(self):
        initial = {"clients": release.CLIENTS, "rules": [self.rule],
                   "update": {"schedule": {"mode": "manual"}}}
        release.checked_config(initial, [self.rule])
        with self.assertRaisesRegex(RuntimeError, "declared baseline"):
            release.checked_config(initial | {"rules": [self.rule | {"ops": [{"type": "exclude_kinds"}]}]}, [self.rule])
        release.write_json(release.STATE / "managed-config.json", initial)
        with self.assertRaisesRegex(RuntimeError, "configuration drift"):
            release.checked_config(initial | {"rules": [self.rule | {"ops": [{"type": "exclude_kinds"}]}]}, [self.rule])

    def test_native_config_operations_cover_add_remove_and_reorder(self):
        wanted = [self.rule | {"id": "new"}, self.rule]
        operations = release.rule_updates([self.rule, self.rule | {"id": "retired"}], wanted)
        self.assertEqual([operation["op"] for operation in operations], ["remove_rule", "add_rule", "reorder_rules"])

    def test_rollback_requires_all_three_replacement_ip_databases(self):
        geo = {name: {"source": "DB-IP Lite"} for name in release.DB_IP}
        self.assertFalse(release.eligible_geo({"geo": geo}))
        geo["GeoIP.dat"] = {"source": release.GEO_IP_REPO}
        self.assertTrue(release.eligible_geo({"geo": geo}))

    def setup_release(self, version, base):
        folder = release.RELEASES / version
        public = folder / "public"
        public.mkdir(parents=True)
        files = ["GeoSite.dat", "GeoIP.dat", "Country.mmdb", "ASN.mmdb"]
        for path in files:
            (public / path).write_text(path)
        (folder / "rules.yaml").write_text("same rules")
        release.write_json(folder / "manifest.json", {"version": version, "base": base, "files": files})
        return public

    def test_unchanged_release_checks_actual_public_files(self):
        old = "20261126T000001000000Z"
        candidate = "20261126T000002000000Z"
        public = self.setup_release(old, "")
        self.setup_release(candidate, old)
        release.point("current", old)
        with patch.object(release, "check_public", side_effect=RuntimeError("missing public file")) as check:
            with self.assertRaisesRegex(RuntimeError, "missing public file"):
                release.publish(candidate)
            check.assert_called_once_with(public)
        self.assertEqual(release.current(), old)

    def test_first_failure_deactivates_unverified_candidate(self):
        candidate = "20261126T000002000000Z"
        self.setup_release(candidate, "")
        release.write_json(release.STATE / "pending.json", {"old": "", "version": candidate})
        release.point("current", candidate)
        with patch.object(release, "check_public", side_effect=RuntimeError("public readback failed")):
            with self.assertRaisesRegex(RuntimeError, "public readback failed"):
                release.recover()
        self.assertEqual(release.current(), "")
        self.assertFalse((release.STATE / "pending.json").exists())

    def test_recovers_nas_activation_after_interrupted_readback(self):
        old = "20261126T000001000000Z"
        candidate = "20261126T000002000000Z"
        self.setup_release(old, "")
        public = self.setup_release(candidate, old)
        release.point("current", candidate)
        pending = release.STATE / "pending.json"
        release.write_json(pending, {"old": old, "version": candidate})
        with patch.object(release, "check_public") as check:
            release.recover()
            check.assert_called_once_with(public)
        self.assertEqual(release.current(), candidate)
        self.assertEqual((release.STATE / "previous").readlink().name, old)
        self.assertFalse(pending.exists())

    def test_unknown_nas_pointer_preserves_pending_record(self):
        old = "20261126T000001000000Z"
        candidate = "20261126T000002000000Z"
        unknown = "20261126T000003000000Z"
        release.point("current", unknown)
        pending = release.STATE / "pending.json"
        release.write_json(pending, {"old": old, "version": candidate})
        with self.assertRaisesRegex(RuntimeError, "unknown release"):
            release.recover()
        self.assertEqual(release.current(), unknown)
        self.assertTrue(pending.exists())

    def test_failed_public_readback_restores_previous_batch(self):
        old = "20261126T000001000000Z"
        candidate = "20261126T000002000000Z"
        public = self.setup_release(old, "")
        self.setup_release(candidate, old)
        release.point("current", candidate)
        pending = release.STATE / "pending.json"
        release.write_json(pending, {"old": old, "version": candidate})
        with patch.object(release, "check_public", side_effect=[RuntimeError("missing file"), None]) as check:
            with self.assertRaisesRegex(RuntimeError, "missing file"):
                release.recover()
            self.assertEqual(check.call_args_list[-1].args, (public,))
        self.assertEqual(release.current(), old)
        self.assertFalse(pending.exists())


if __name__ == "__main__":
    unittest.main()
