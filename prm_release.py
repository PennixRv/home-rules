import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import fcntl
import gzip
from hashlib import sha256
from http.client import IncompleteRead
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from time import monotonic, sleep
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

import rule_changes
import verify_release


BASE = Path(__file__).resolve().parent
STATE = Path(os.environ.get("RULES_STATE", BASE / "state"))
RELEASES = STATE / "releases"
POLICY_DIR = Path(os.environ.get("RULES_CONFIG", BASE))
DB_IP = {"Country.mmdb": "country", "ASN.mmdb": "asn"}
GEO_IP_REPO = "v2fly/geoip"
GEO_DAT = {"GeoSite.dat": "Loyalsoldier/v2ray-rules-dat", "GeoIP.dat": GEO_IP_REPO}
CLIENTS = [{"id": "mihomo", "name": "Mihomo", "template": "mihomo-yaml"}]
GEO_FIELDS = ("geosite", "geoip", "mmdb", "asn")
ORIGIN = os.environ.get("RULES_ORIGIN_URL", "http://origin:8081/active").rstrip("/")
PRM = os.environ.get("PRM_URL", "http://prm:3001").rstrip("/")
VERSION = re.compile(r"\d{8}T\d{12}Z")
TEMPORARY_FAILURE = 75


class ReviewRequired(RuntimeError):
    pass


def transient_network_error(error):
    if isinstance(error, HTTPError):
        return error.code in {408, 429} or 500 <= error.code <= 599
    return isinstance(error, (URLError, TimeoutError, ConnectionError, IncompleteRead))


def request(url, body=None, private=False, limit=64 << 20, timeout=45):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    if private:
        headers["Authorization"] = "Bearer " + os.environ["PRM_ADMIN_TOKEN"]
    with urlopen(Request(url, data=data, headers=headers), timeout=timeout) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise RuntimeError(f"Response exceeded size limit: {url}")
    return raw


def api(path, body=None, timeout=45):
    try:
        raw = request(f"{PRM}/api/v1/{path}", body, private=True, timeout=timeout)
    except HTTPError as exc:
        try:
            error = json.loads(exc.read(16384)).get("error", {})
        except (UnicodeError, ValueError):
            error = {}
        detail = error.get("details")
        raise RuntimeError(f"PRM {path}: HTTP {exc.code}, {error.get('code', '')} "
                           f"{error.get('message', '')} {detail or ''}".strip()) from None
    return json.loads(raw) if raw else None


def revision(repo, branch):
    ref = f"refs/heads/{branch}"
    response = subprocess.check_output(
        ["git", "ls-remote", "--exit-code", f"https://github.com/{repo}.git", ref],
        text=True, timeout=45,
    ).strip().split()
    if len(response) != 2 or response[1] != ref or not re.fullmatch("[a-f0-9]{40}", response[0]):
        raise RuntimeError(f"Unexpected ref for {repo}")
    return response[0]


def sources(policy):
    return {name: (repo, revision(repo, branch)) for name, (repo, branch) in policy["sources"].items()}


def resolve_source(entry, versions):
    if "repository" in entry:
        repository, commit = versions[entry["repository"]]
        path = entry["path"]
        return {key: value for key, value in entry.items() if key not in {"repository", "path"}} | {
            "url": f"https://raw.githubusercontent.com/{repository}/{commit}/{path}",
        }
    if "content" in entry or "ref" in entry:
        return entry
    raise ValueError("Expected a declared repository path, inline content or a provider reference")


def desired_rules(policy, versions):
    result = []
    for name, definition in policy["providers"].items():
        if not re.fullmatch(r"[a-z0-9-]+", name):
            raise ValueError(f"Invalid provider ID: {name}")
        if isinstance(definition, list):
            source, path, _ = definition
            definition = {"sources": [{"repository": source, "path": path}]}
        permitted = {key: definition[key] for key in ("merge", "ops") if key in definition}
        resolved = [resolve_source(entry, versions) for entry in definition["sources"]]
        result.append({"id": name, "name": name, "sources": resolved, "outputs": ["mihomo"]} | permitted)
    return result


def seed(policy):
    config = {
        "clients": CLIENTS,
        "rules": desired_rules(policy, policy["sources"]),
        "update": {"schedule": {"mode": "manual"}},
    }
    data = BASE / "data"
    data.mkdir(exist_ok=True)
    with (data / "config.yaml").open("x") as output:
        yaml.safe_dump(config, output, sort_keys=False)


def write_json(path, data):
    staged = path.with_suffix(".new")
    staged.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    staged.replace(path)


def unpinned(rules):
    def without_revision(entry):
        url = entry.get("url")
        if not isinstance(url, str) or not url.startswith("https://raw.githubusercontent.com/"):
            return entry
        parts = url.split("/", 6)
        if len(parts) != 7:
            raise RuntimeError("Malformed PRM source URL")
        parts[5] = "{revision}"
        return entry | {"url": "/".join(parts)}

    return [rule | {"sources": [without_revision(entry) for entry in rule["sources"]]} for rule in rules]


def checked_config(observed, desired):
    if observed.get("clients") != CLIENTS or observed.get("update", {}).get("schedule") != {"mode": "manual"}:
        raise RuntimeError("Unexpected PRM client or schedule configuration")
    config_path = STATE / "managed-config.json"
    if config_path.exists():
        previous = json.loads(config_path.read_bytes())
        if observed == previous:
            return
        desired_config = previous | {"rules": desired}
        for kind in GEO_FIELDS:
            desired_config.pop(kind, None)
        if observed == desired_config:
            return
        raise RuntimeError("Unexpected PRM configuration drift from the last managed configuration")
    if unpinned(observed.get("rules", [])) != unpinned(desired):
        raise RuntimeError("PRM rule configuration differs from the declared baseline")
    legacy_raw = {"providers": [{"name": "loyalsoldier", "host": True}]}
    legacy_dat = {"providers": [legacy_raw["providers"][0] | {"clients": ["mihomo"]}]}
    for kind in GEO_FIELDS:
        allowed = (None, legacy_dat) if kind in ("geosite", "geoip") else (None, legacy_raw)
        if observed.get(kind) not in allowed:
            raise RuntimeError(f"Unexpected initial PRM {kind} configuration")


def rule_updates(existing, desired):
    by_id = {rule["id"]: rule for rule in existing}
    desired_ids = [rule["id"] for rule in desired]
    operations = [{"op": "remove_rule", "id": rule_id} for rule_id in by_id if rule_id not in desired_ids]
    current_order = [rule_id for rule_id in by_id if rule_id in desired_ids]
    for rule in desired:
        rule_id = rule["id"]
        if rule_id not in by_id:
            operations.append({"op": "add_rule", "value": rule})
            current_order.append(rule_id)
        elif by_id[rule_id] != rule:
            operations.append({"op": "update_rule", "id": rule_id, "value": rule})
    if current_order != desired_ids:
        operations.append({"op": "reorder_rules", "order": desired_ids})
    return operations


def update(policy, report, versions=None, *, resolved=None):
    if versions is None:
        versions = sources(policy)
    report["sources"] = versions
    desired = resolved if resolved is not None else desired_rules(policy, versions)
    initial = api("config")
    running = initial["config"]
    checked_config(running, desired)
    report["previous_provider_layout_matches"] = unpinned(running["rules"]) == unpinned(desired)
    operations = rule_updates(running["rules"], desired)
    for kind in GEO_FIELDS:
        if kind in running:
            operations.append({"op": f"update_{kind}", "value": None})
    if operations:
        api("config/patch", {"version": initial["version"], "ops": operations})
    config = api("config")
    expected = running | {"rules": desired}
    for kind in GEO_FIELDS:
        expected.pop(kind, None)
    if config["config"] != expected:
        raise RuntimeError("PRM effective rules did not match the resolved configuration")
    write_json(STATE / "managed-config.json", expected)
    job = api("updates", {"scope": "all"})["id"]
    report["prm_job"] = job
    deadline = monotonic() + 420
    while api("updates/current") is not None:
        if monotonic() >= deadline:
            raise RuntimeError("PRM update did not finish")
        sleep(2)
    status = api(f"updates/{job}")
    issues = status["issues"]
    failed = {issue["subject"] for issue in issues if issue["stage"] == "rule"}
    partial = (
        status["status"] == "completed_with_errors" and issues
        and all(issue["stage"] == "rule" for issue in issues)
        and failed <= {rule["id"] for rule in desired}
        and status["rules_failed"] == len(failed)
        and status["rules_succeeded"] + len(failed) == len(desired)
    )
    if status["scope"] != "all" or not (partial or (
        status["status"] == "completed" and status["rules_succeeded"] == len(desired) and not issues
    )):
        summary = [f'{issue["stage"]}/{issue["subject"]}: {issue["message"]}' for issue in issues[:4]]
        raise RuntimeError(f"PRM update {job} {status['status']}: {summary or status['warnings'][:4]}")
    if partial:
        report["rule_failures"] = {name: [i["message"] for i in issues if i["subject"] == name] for name in sorted(failed)}
    return versions, config, job


def db_ip_file(public, name, kind, month, prior, prior_geo):
    url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
    target = public / name
    packed = public.parent / f"{name}.gz"
    result = subprocess.run(
        ["curl", "-fsSL", "--max-time", "35", "--max-filesize", str(32 << 20), "--output",
         str(packed), "--write-out", "%{http_code}", url],
        text=True, capture_output=True, timeout=40,
    )
    if result.returncode:
        if result.stdout == "404" and prior_geo.get("source") == "DB-IP Lite":
            shutil.copyfile(prior / name, target)
            return prior_geo | {"pending_month": month}
        raise RuntimeError(f"DB-IP {kind} {month} failed (HTTP {result.stdout or 'unknown'})")
    with gzip.open(packed, "rb") as source:
        data = source.read((64 << 20) + 1)
    packed.unlink()
    if len(data) > 64 << 20 or b"\xab\xcd\xefMaxMind.com" not in data[-131072:]:
        raise ValueError(f"Invalid DB-IP {kind} MMDB")
    target.write_bytes(data)
    return {"source": "DB-IP Lite", "version": month, "url": url, "license": "CC BY 4.0"}


def geo_versions(prior_geo, failures):
    wanted = {}
    for name, repository in GEO_DAT.items():
        try:
            wanted[name] = revision(repository, "release")
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            if prior_geo.get(name, {}).get("source") != repository:
                raise
            wanted[name] = prior_geo[name]["version"]
            failures[name] = str(exc)
    wanted.update(dict.fromkeys(DB_IP, datetime.now(timezone.utc).strftime("%Y-%m")))
    return wanted


def collect_geo(public, prior, prior_geo, wanted=None, failures=None):
    if failures is None:
        failures = {}
    if wanted is None:
        wanted = geo_versions(prior_geo, failures)
    result = {}
    for name in (*GEO_DAT, *DB_IP):
        repository = GEO_DAT.get(name)
        version = wanted[name]
        previous = prior_geo.get(name, {})
        target = public / name
        try:
            if previous.get("version") == version and previous["source"] == (repository or "DB-IP Lite"):
                shutil.copyfile(prior / name, target)
                result[name] = previous
            elif repository:
                url = f"https://raw.githubusercontent.com/{repository}/{version}/{name.lower()}"
                target.write_bytes(request(url))
                result[name] = {"source": repository, "version": version, "url": url}
            else:
                result[name] = db_ip_file(public, name, DB_IP[name], version, prior, previous)
                if "pending_month" in result[name]:
                    failures[name] = f"DB-IP {version} is not available"
        except (OSError, ValueError, RuntimeError, EOFError, IncompleteRead, subprocess.TimeoutExpired) as exc:
            if previous.get("source") != (repository or "DB-IP Lite"):
                raise
            shutil.copyfile(prior / name, target)
            result[name] = previous
            failures[name] = str(exc)
    result["GeoIP.dat"]["license"] = "CC BY-SA 4.0"
    return result


def current():
    link = STATE / "current"
    if not link.is_symlink():
        if link.exists():
            raise RuntimeError("NAS current release path is not a symlink")
        return ""
    target = link.readlink()
    if not VERSION.fullmatch(target.name) or target != Path("releases") / target.name:
        raise RuntimeError("NAS current release points outside the managed batches")
    return target.name


def release_version():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def point(name, version):
    if not version:
        (STATE / name).unlink(missing_ok=True)
        return
    pending = STATE / f".{name}-{os.getpid()}"
    pending.symlink_to(Path("releases") / version)
    pending.replace(STATE / name)


def check_public(release):
    files = release_files(release.parent)
    for name in files:
        if request(f"{ORIGIN}/{name}") != (release / name).read_bytes():
            raise RuntimeError(f"Public content differs: {name}")


def release_files(release):
    metadata = json.loads((release / "manifest.json").read_bytes())
    files = metadata["files"]
    required_geo = {"GeoSite.dat", "GeoIP.dat", *DB_IP}
    if not required_geo.issubset(files) or len(files) != len(set(files)) or not all(
        name in required_geo or re.fullmatch(r"rules/mihomo/[a-z0-9-]+\.yaml", name)
        for name in files
    ):
        raise ValueError("Release file manifest is invalid")
    public = release / "public"
    actual = {
        str(path.relative_to(public)) for path in public.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if actual != set(files):
        raise ValueError("Release files differ from the manifest")
    return files


def recover():
    pending = STATE / "pending.json"
    if not pending.exists():
        return
    record = json.loads(pending.read_bytes())
    old, version = record["old"], record["version"]
    fallback = record.get("fallback", old)
    previous = record.get("previous", old)
    live = current()
    if live not in (old, version, fallback):
        raise RuntimeError("NAS points to an unknown release")
    if live == version:
        try:
            check_public(RELEASES / version / "public")
        except (OSError, RuntimeError, ValueError, IncompleteRead):
            if fallback:
                release_files(RELEASES / fallback)
            point("current", fallback)
            if fallback != old:
                point("previous", "")
            if fallback:
                check_public(RELEASES / fallback / "public")
            pending.unlink()
            raise
        point("previous", previous)
    elif live:
        check_public(RELEASES / live / "public")
        if live != old:
            point("previous", "")
    pending.unlink()


def stage(policy, report, reviewed=None):
    if (STATE / "pending.json").exists():
        raise RuntimeError("Resolve the pending publication before staging")
    version = release_version()
    release = RELEASES / version
    release.mkdir()
    report["candidate"] = version
    try:
        build_release(policy, report, release, reviewed)
    except BaseException:
        shutil.rmtree(release)
        raise
    return version


def eligible_geo(metadata):
    geo = metadata["geo"]
    return (geo.get("GeoIP.dat", {}).get("source") == GEO_IP_REPO
            and all(geo.get(name, {}).get("source") == "DB-IP Lite" for name in DB_IP))


def local_config_versions():
    return {name: sha256((POLICY_DIR / name).read_bytes()).hexdigest()
            for name in ("sources.yaml", "household-rules.yaml", "probes.yaml")}


def automatic_inputs(policy, report, metadata):
    local = local_config_versions()
    if yaml.safe_load((POLICY_DIR / "sources.yaml").read_bytes()) != policy:
        raise RuntimeError("Rule source policy changed before validation")
    observed = {}
    failures = {}
    for name, (repo, branch) in policy["sources"].items():
        try:
            observed[name] = [repo, revision(repo, branch)]
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            previous = metadata["sources"].get(name)
            if not previous or previous[0] != repo:
                raise
            observed[name] = previous
            failures[name] = str(exc)
    geo_failures = {}
    geo = geo_versions(metadata["geo"], geo_failures)
    report.update({"source_failures": failures, "geo_failures": geo_failures})
    return {"sources": observed, "geo": geo, "local_config": local}


def memoizable(report):
    return not any(report.get(key) for key in ("source_failures", "geo_failures", "rule_failures", "output_failures"))


def migration_fallback(old, candidate):
    source = RELEASES / old
    staged = RELEASES / candidate
    metadata = json.loads((source / "manifest.json").read_bytes())
    if eligible_geo(metadata):
        return old
    new = json.loads((staged / "manifest.json").read_bytes())
    if not eligible_geo(new):
        raise RuntimeError("Replacement IP files have not been validated for rollback")
    version = release_version()
    fallback = RELEASES / version
    public = fallback / "public"
    try:
        public.mkdir(parents=True)
        for name in release_files(source):
            origin = staged if name in {"GeoSite.dat", "GeoIP.dat", *DB_IP} else source
            target = public / name
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(origin / "public" / name, target)
        shutil.copyfile(source / "rules.yaml", fallback / "rules.yaml")
        bundle = yaml.safe_load((fallback / "rules.yaml").read_bytes())
        verify_release.check_core(fallback, public, bundle["rule-providers"], bundle["rules"])
        write_json(fallback / "manifest.json", metadata | {"version": version, "base": old, "geo": new["geo"]})
        release_files(fallback)
    except Exception:
        shutil.rmtree(fallback)
        raise
    return version


def provider_inputs(metadata, policy):
    return metadata.get("rule_inputs") or {
        rule["id"]: rule for rule in desired_rules(policy, metadata["sources"])
    }


def fixed_provider_versions(desired, previous):
    def unversioned(entry):
        return unpinned([{"sources": [entry]}])[0]["sources"][0].get("url")

    for rule in desired:
        known = {
            unversioned(entry): entry["url"]
            for entry in previous.get(rule["id"], {}).get("sources", ()) if "url" in entry
        }
        rule["sources"] = [
            entry | {"url": known[unversioned(entry)]} if unversioned(entry) in known else entry
            for entry in rule["sources"]
        ]
    return desired


def read_provider(raw):
    payload = yaml.safe_load(raw)["payload"]
    if not isinstance(payload, list) or not payload or any(not isinstance(item, str) for item in payload):
        raise ValueError("Invalid PRM rule payload")
    return {"type": "inline", "behavior": "classical", "payload": payload}


def dependent_providers(failed, inputs):
    held = set(failed)
    while True:
        urls = {entry["url"] for name in held for entry in inputs[name]["sources"] if "url" in entry}
        more = {
            name for name, rule in inputs.items()
            if any(entry.get("ref") in held or entry.get("url") in urls for entry in rule["sources"])
        } - held
        if not more:
            return held
        held.update(more)


def review_providers(changes, old, bundle):
    changed = {
        name for name, value in bundle["rule-providers"].items()
        if value != old["rule-providers"].get(name)
    }
    failed = set()
    for row in changes:
        if row["status"] in {"review", "conditional"}:
            implicated = {row["previous_provider"], row["candidate_provider"]} & changed
            if not implicated:
                raise ReviewRequired("Routing difference cannot be attributed to a changed provider")
            failed.update(implicated)
    return failed


def allowed_probes(changes, side):
    probes = {}
    for item in changes:
        if item["status"] != "allowed" or item["kind"] not in {"domain", "ipv4", "ipv6"}:
            continue
        provider = item[f"{side}_provider"]
        match = f"RuleSet({provider})" if provider else "Match"
        for sample in item["samples"]:
            addresses = rule_changes.interval(sample) if item["kind"] in {"ipv4", "ipv6"} else ()
            hosts = [f"[{value}]" if value.version == 6 else str(value)
                     for value in addresses] if addresses else [sample]
            for host in hosts:
                probes[host] = (match, item[f"{side}_target"])
    return probes


def build_release(policy, report, release, reviewed=None):
    base = current()
    prior = (RELEASES / base / "public") if base else None
    prior_metadata = json.loads((prior.parent / "manifest.json").read_bytes()) if prior else {}
    prior_geo = prior_metadata.get("geo", {})
    pins = resolved = None
    observed = report.get("input_snapshot")
    if reviewed is not None:
        if not isinstance(reviewed, dict) or reviewed.get("base") != base:
            raise ReviewRequired("Reviewed rules reference a different current batch")
        if not isinstance(reviewed.get("bundle"), dict):
            raise ReviewRequired("Reviewed rules require the complete expected bundle")
        manual_upstream = prior and "sources" in reviewed
        pins = reviewed.get("sources") if manual_upstream or not prior else prior_metadata["sources"]
        if not isinstance(pins, dict) or pins.keys() != policy["sources"].keys() or any(
            not isinstance(pin, (tuple, list)) or len(pin) != 2
            or pin[0] != policy["sources"][key][0]
            or not isinstance(pin[1], str) or not re.fullmatch("[a-f0-9]{40}", pin[1])
            for key, pin in pins.items()
        ):
            raise ReviewRequired("Reviewed rules require fixed revisions for all declared repositories")
        report["reviewed_base"] = base
        if prior and prior_metadata.get("rule_inputs"):
            desired = desired_rules(policy, pins)
            previous = prior_metadata["rule_inputs"]
            if manual_upstream:
                advancing = reviewed.get("advance")
                if (not isinstance(advancing, list) or not advancing
                        or not all(isinstance(name, str) and name in policy["providers"] for name in advancing)):
                    raise ReviewRequired("Name the reviewed rule providers in advance")
                previous = {name: rule for name, rule in previous.items() if name not in advancing}
            resolved = fixed_provider_versions(desired, previous)
    elif prior is None:
        raise ReviewRequired("First publication requires an independent reviewed bundle")

    if observed:
        pins = observed["sources"]
    if resolved is None:
        versions, config, job = update(policy, report, pins)
    else:
        versions, config, job = update(policy, report, pins, resolved=resolved)
    public = release / "public"
    rule_files = public / "rules/mihomo"
    rule_files.mkdir(parents=True, exist_ok=False)
    providers = {}
    old = yaml.safe_load((prior.parent / "rules.yaml").read_bytes()) if prior else None
    held = set(report.get("rule_failures", ()))
    inputs = {rule["id"]: rule for rule in config.get("config", {}).get("rules", ())}
    previous_inputs = provider_inputs(prior_metadata, policy) if prior and not reviewed else {}

    def keep_previous(names):
        if not prior or reviewed is not None:
            raise RuntimeError("Reviewed candidate must compile all rule providers")
        if not prior_metadata.get("rule_inputs") and not report.get("previous_provider_layout_matches"):
            raise RuntimeError("Previous rule layout cannot be verified")
        for name in dependent_providers(names, inputs):
            if name not in previous_inputs or unpinned([previous_inputs[name]]) != unpinned([inputs[name]]):
                raise RuntimeError(f"Previous rule inputs cannot be verified for {name}")
            raw = (prior / "rules/mihomo" / f"{name}.yaml").read_bytes()
            if read_provider(raw) != old["rule-providers"].get(name):
                raise RuntimeError(f"Previous rule content differs from the accepted bundle for {name}")
            (rule_files / f"{name}.yaml").write_bytes(raw)
            providers[name] = old["rule-providers"][name]
            report.setdefault("retained_providers", {})[name] = previous_inputs[name]["sources"]
        return set(report["retained_providers"])

    if held:
        held = keep_previous(held)
    for name in policy["providers"]:
        if name in held:
            continue
        try:
            raw = request(f"{PRM}/rules/mihomo/{name}.yaml")
            providers[name] = read_provider(raw)
        except (OSError, RuntimeError, IncompleteRead, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
            if not prior or reviewed is not None:
                raise
            report.setdefault("output_failures", {})[name] = str(exc)
            held = keep_previous(held | {name})
            continue
        (rule_files / f"{name}.yaml").write_bytes(raw)
    if reviewed is not None and prior is not None:
        for name in (*GEO_DAT, *DB_IP):
            shutil.copyfile(prior / name, public / name)
        geo_versions = prior_geo
    else:
        geo_versions = collect_geo(public, prior, prior_geo, observed["geo"] if observed else None,
                                   report.setdefault("geo_failures", {}))
    report["geo"] = geo_versions
    if (api("updates/current") is not None
            or api("updates?limit=1")["items"][0]["id"] != job or api("config") != config):
        raise RuntimeError("PRM config or output changed during collection")
    household = yaml.safe_load((POLICY_DIR / "household-rules.yaml").read_bytes())
    if not isinstance(household, list) or not household or any(
        not isinstance(rule, str) or "," not in rule or rule.startswith("MATCH,") for rule in household
    ):
        raise ValueError("Invalid household rules")
    rules = [*policy["early_rules"], *household, *policy["rules"]]
    providers = {name: providers[name] for name in policy["providers"]}
    bundle = {"rule-providers": providers, "rules": rules}
    if reviewed is not None and bundle != reviewed["bundle"]:
        raise ReviewRequired("Compiled rules differ from the complete reviewed bundle")
    changes = []
    if prior is not None:
        if reviewed is None and (old["rules"] != rules or old["rule-providers"].keys() != providers.keys()):
            raise ReviewRequired("Changes to routing order, household rules or rule inventory require a reviewed bundle")
        automatic = policy.get("automatic_updates", {})
        legacy = policy.get("automatic_additions", ()) if "automatic_updates" not in policy else ()
        country = nullcontext()
        if reviewed is None and automatic.get("domestic_ip"):
            import maxminddb
            try:
                country = maxminddb.open_database(prior / "Country.mmdb")
            except (OSError, ValueError) as exc:
                report["country_check_unavailable"] = str(exc)
        with country as reader:
            changes = rule_changes.compare(old, bundle, legacy, automatic=automatic, country=reader)
            report["rule_changes"] = changes
            if reviewed is None and any(row["status"] in {"review", "conditional"} for row in changes):
                blocked = review_providers(changes, old, bundle)
                report["reviewed_out"] = changes
                held = keep_previous(held | blocked)
                changes = rule_changes.compare(old, bundle, legacy, automatic=automatic, country=reader)
        report["rule_changes"] = changes
        if reviewed is None and any(change["status"] in {"review", "conditional"} for change in changes):
            raise ReviewRequired("Rule differences require review; see state/last-check.json")
    verify_release.check_core(release, public, providers, rules, converged=True,
                              additional=allowed_probes(changes, "candidate"))
    if prior is not None:
        verify_release.check_core(release, prior, providers, rules, converged=True)
        verify_release.check_core(release, public, old["rule-providers"], old["rules"],
                                  additional=allowed_probes(changes, "previous"))
    (release / "rules.yaml").write_text(yaml.safe_dump(bundle, allow_unicode=True, sort_keys=False))
    actual_inputs = {name: previous_inputs[name] if name in held else value for name, value in inputs.items()}
    metadata = {"version": release.name, "base": base, "sources": versions, "geo": geo_versions, "job": job,
                "rule_inputs": actual_inputs,
                "files": [str(p.relative_to(public)) for p in sorted(public.rglob("*")) if p.is_file()]}
    write_json(release / "manifest.json", metadata)


def publish(version, rollback=False):
    old = current()
    release = RELEASES / version
    metadata = json.loads((release / "manifest.json").read_text())
    files = release_files(release)
    public = release / "public"
    if not rollback and metadata.get("base") != old:
        raise RuntimeError("Staged release was verified against a different current batch")
    if version == old:
        check_public(public)
        return "unchanged"
    if old:
        previous = RELEASES / old
        old_files = json.loads((previous / "manifest.json").read_text())["files"]
        if (files == old_files and (release / "rules.yaml").read_bytes() == (previous / "rules.yaml").read_bytes()
                and all((public / f).read_bytes() == (previous / "public" / f).read_bytes() for f in files)):
            check_public(previous / "public")
            if not rollback:
                shutil.rmtree(release)
            return "unchanged"
    fallback = migration_fallback(old, version) if old else ""
    write_json(STATE / "pending.json", {"old": old, "version": version, "fallback": fallback, "previous": fallback})
    point("current", version)
    recover()
    keep = {current()}
    previous_link = STATE / "previous"
    if previous_link.is_symlink():
        keep.add(previous_link.readlink().name)
    for path in RELEASES.iterdir():
        if VERSION.fullmatch(path.name) and path.is_dir() and not path.is_symlink() and path.name not in keep:
            shutil.rmtree(path)
    return "rolled-back" if rollback else "published"


def run(action, version, policy, report, reviewed=None):
    if reviewed is not None and action != "stage":
        raise ValueError("Reviewed rules may only be staged for explicit promotion")
    if action in ("publish", "promote", "rollback"):
        recover()
    if action in ("promote", "rollback"):
        report["candidate"] = version
        if action == "rollback":
            previous = STATE / "previous"
            if not previous.is_symlink() or previous.readlink().name != version:
                raise RuntimeError("Rollback must name the retained previous batch")
            metadata = json.loads((RELEASES / version / "manifest.json").read_bytes())
            if not eligible_geo(metadata):
                raise RuntimeError("Rollback assets use the retired IP data source")
        return publish(version, rollback=action == "rollback")
    if action == "adopt-config":
        observed = api("config")["config"]
        checked_config(observed, desired_rules(policy, policy["sources"]))
        write_json(STATE / "managed-config.json", observed)
        return "configuration-recorded"
    base = current()
    if action == "publish" and base:
        prior = RELEASES / base
        metadata = json.loads((prior / "manifest.json").read_bytes())
        report["input_snapshot"] = automatic_inputs(policy, report, metadata)
        slot = report.get("slot")
        last_scheduled = STATE / "last-scheduled.json"
        if slot:
            previous = json.loads(last_scheduled.read_bytes()) if last_scheduled.exists() else {}
            if previous.get("public_check_day") != slot[:10]:
                check_public(prior / "public")
            report["public_check_day"] = slot[:10]
            if (
                previous.get("status") in {"published", "unchanged", "review"}
                and previous.get("current_release") == base
                and previous.get("input_snapshot") == report["input_snapshot"]
                and memoizable(previous) and memoizable(report)
            ):
                for key in ("retained_providers", "reviewed_out", "rule_changes", "detail"):
                    if key in previous:
                        report[key] = previous[key]
                report["skipped_build"] = True
                return "review" if previous["status"] == "review" else "unchanged"
    candidate = stage(policy, report, reviewed)
    if action != "publish":
        return "staged"
    if base and report["input_snapshot"]["local_config"] != local_config_versions():
        shutil.rmtree(RELEASES / candidate)
        raise RuntimeError("Local rule inputs changed during validation")
    status = publish(candidate)
    if report.get("slot"):
        report["public_check_day"] = report["slot"][:10]
    return status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["seed", "stage", "publish", "promote", "rollback", "adopt-config"])
    parser.add_argument("version", nargs="?")
    parser.add_argument("--reviewed", type=Path, help="Private YAML with the base and complete expected rules")
    parser.add_argument("--slot", help="Scheduled Shanghai check as YYYY-MM-DDTHH:MM")
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == "seed":
        seed(yaml.safe_load((POLICY_DIR / "sources.yaml").read_bytes()))
        return
    if args.action in ("promote", "rollback") and (not args.version or not VERSION.fullmatch(args.version)):
        parser.error(f"{args.action} requires a version")
    if args.reviewed and args.action != "stage":
        parser.error("--reviewed requires stage")
    if args.slot and (args.action != "publish" or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d", args.slot)):
        parser.error("--slot is only for scheduled publish")
    RELEASES.mkdir(parents=True, exist_ok=True)
    with (STATE / ".publish.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        report = {"started": datetime.now(timezone.utc).isoformat(), "action": args.action,
                  "initial_release": current()}
        if args.slot:
            report["slot"] = args.slot
        try:
            policy = yaml.safe_load((POLICY_DIR / "sources.yaml").read_bytes())
            reviewed = yaml.safe_load(args.reviewed.read_bytes()) if args.reviewed else None
            if args.reviewed and not isinstance(reviewed, dict):
                raise ReviewRequired("Invalid reviewed rules document")
            report["status"] = run(args.action, args.version, policy, report, reviewed)
        except Exception as exc:
            report["status"] = "review" if isinstance(exc, ReviewRequired) else "failed"
            report["detail"] = str(exc)
            if (
                args.action == "publish"
                and report["initial_release"]
                and current() == report["initial_release"]
                and not (STATE / "pending.json").exists()
                and transient_network_error(exc)
            ):
                report["retryable"] = True
                raise SystemExit(TEMPORARY_FAILURE) from exc
            raise
        finally:
            report["finished"] = datetime.now(timezone.utc).isoformat()
            report["current_release"] = current()
            write_json(STATE / "last-check.json", report)
            if args.slot:
                write_json(STATE / "last-scheduled.json", report)
            if report.get("status") in {"published", "unchanged", "rolled-back"}:
                write_json(STATE / "last-success.json", report)
            print("Rule release:", report.get("status", "interrupted"),
                  report.get("candidate", "-"), "current", report["current_release"], flush=True)


if __name__ == "__main__":
    main()
