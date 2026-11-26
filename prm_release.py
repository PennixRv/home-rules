import argparse
import fcntl
import gzip
import json
import os
from datetime import datetime, timezone
from http.client import IncompleteRead
from pathlib import Path
import re
import shutil
import subprocess
from time import monotonic, sleep
from urllib.error import HTTPError
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


class ReviewRequired(RuntimeError):
    pass


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


def update(policy, report, versions=None):
    if versions is None:
        versions = sources(policy)
    report["sources"] = versions
    desired = desired_rules(policy, versions)
    initial = api("config")
    running = initial["config"]
    checked_config(running, desired)
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
            raise TimeoutError("PRM update did not finish")
        sleep(2)
    status = api(f"updates/{job}")
    if status["scope"] != "all" or status["status"] != "completed" or status["rules_succeeded"] != len(desired):
        summary = [f'{issue["stage"]}/{issue["subject"]}: {issue["message"]}' for issue in status["issues"][:4]]
        raise RuntimeError(f"PRM update {job} {status['status']}: {summary or status['warnings'][:4]}")
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


def collect_geo(public, prior, prior_geo):
    result = {}
    for name, repository in GEO_DAT.items():
        commit = revision(repository, "release")
        url = f"https://raw.githubusercontent.com/{repository}/{commit}/{name.lower()}"
        (public / name).write_bytes(request(url))
        result[name] = {"source": repository, "version": commit, "url": url}
    result["GeoIP.dat"]["license"] = "CC BY-SA 4.0"
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    for name, kind in DB_IP.items():
        result[name] = db_ip_file(public, name, kind, month, prior, prior_geo.get(name, {}))
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


def build_release(policy, report, release, reviewed=None):
    base = current()
    prior = (RELEASES / base / "public") if base else None
    prior_metadata = json.loads((prior.parent / "manifest.json").read_bytes()) if prior else {}
    prior_geo = prior_metadata.get("geo", {})
    pins = None
    if reviewed is not None:
        if not isinstance(reviewed, dict) or reviewed.get("base") != base:
            raise ReviewRequired("Reviewed rules reference a different current batch")
        if not isinstance(reviewed.get("bundle"), dict):
            raise ReviewRequired("Reviewed rules require the complete expected bundle")
        pins = prior_metadata["sources"] if prior else reviewed.get("sources")
        if not isinstance(pins, dict) or pins.keys() != policy["sources"].keys() or any(
            not isinstance(pin, (tuple, list)) or len(pin) != 2
            or pin[0] != policy["sources"][key][0]
            or not isinstance(pin[1], str) or not re.fullmatch("[a-f0-9]{40}", pin[1])
            for key, pin in pins.items()
        ):
            raise ReviewRequired("Reviewed rules require fixed revisions for all declared repositories")
        report["reviewed_base"] = base
    elif prior is None:
        raise ReviewRequired("First publication requires an independent reviewed bundle")

    versions, config, job = update(policy, report, pins)
    public = release / "public"
    rule_files = public / "rules/mihomo"
    rule_files.mkdir(parents=True, exist_ok=False)
    providers = {}
    for name in policy["providers"]:
        raw = request(f"{PRM}/rules/mihomo/{name}.yaml")
        payload = yaml.safe_load(raw)["payload"]
        if not isinstance(payload, list) or not payload or any(not isinstance(item, str) for item in payload):
            raise ValueError(f"Invalid PRM payload for {name}")
        providers[name] = {"type": "inline", "behavior": "classical", "payload": payload}
        (rule_files / f"{name}.yaml").write_bytes(raw)
    if reviewed is not None and prior is not None:
        for name in (*GEO_DAT, *DB_IP):
            shutil.copyfile(prior / name, public / name)
        geo_versions = prior_geo
    else:
        geo_versions = collect_geo(public, prior or STATE / "current" / "public", prior_geo)
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
    bundle = {"rule-providers": providers, "rules": rules}
    if reviewed is not None and bundle != reviewed["bundle"]:
        raise ReviewRequired("Compiled rules differ from the complete reviewed bundle")
    verify_release.check_core(release, public, providers, rules, converged=True)
    if prior is not None:
        old = yaml.safe_load((prior.parent / "rules.yaml").read_bytes())
        changes = rule_changes.compare(old, bundle, policy.get("automatic_additions", ()))
        report["rule_changes"] = changes
        if reviewed is None and any(change["status"] in {"review", "conditional"} for change in changes):
            raise ReviewRequired("Rule differences require review; see state/last-check.json")
        verify_release.check_core(release, prior, providers, rules, converged=True)
        verify_release.check_core(release, public, old["rule-providers"], old["rules"])
    (release / "rules.yaml").write_text(yaml.safe_dump(bundle, allow_unicode=True, sort_keys=False))
    metadata = {"version": release.name, "base": base, "sources": versions, "geo": geo_versions, "job": job,
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
    candidate = stage(policy, report, reviewed)
    return publish(candidate) if action == "publish" else "staged"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["seed", "stage", "publish", "promote", "rollback", "adopt-config"])
    parser.add_argument("version", nargs="?")
    parser.add_argument("--reviewed", type=Path, help="Private YAML with the base and complete expected rules")
    args = parser.parse_args()
    os.umask(0o077)
    policy = yaml.safe_load((POLICY_DIR / "sources.yaml").read_bytes())
    if args.action == "seed":
        seed(policy)
        return
    if args.action in ("promote", "rollback") and (not args.version or not VERSION.fullmatch(args.version)):
        parser.error(f"{args.action} requires a version")
    if args.reviewed and args.action != "stage":
        parser.error("--reviewed requires stage")
    RELEASES.mkdir(parents=True, exist_ok=True)
    with (STATE / ".publish.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        report = {"started": datetime.now(timezone.utc).isoformat(), "action": args.action,
                  "initial_release": current()}
        try:
            reviewed = yaml.safe_load(args.reviewed.read_bytes()) if args.reviewed else None
            if args.reviewed and not isinstance(reviewed, dict):
                raise ReviewRequired("Invalid reviewed rules document")
            report["status"] = run(args.action, args.version, policy, report, reviewed)
        except Exception as exc:
            report["status"] = "review" if isinstance(exc, ReviewRequired) else "failed"
            report["detail"] = str(exc)
            raise
        finally:
            report["finished"] = datetime.now(timezone.utc).isoformat()
            report["current_release"] = current()
            write_json(STATE / "last-check.json", report)
            if report.get("status") in {"published", "unchanged", "rolled-back"}:
                write_json(STATE / "last-success.json", report)
            print("Rule release:", report.get("status", "interrupted"),
                  report.get("candidate", "-"), "current", report["current_release"], flush=True)


if __name__ == "__main__":
    main()
