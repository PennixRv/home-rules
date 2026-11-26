from dataclasses import dataclass
from datetime import time
from hashlib import sha256
from ipaddress import ip_address
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml


FILES = ("sources.yaml", "household-rules.yaml", "probes.yaml")
GEO_FILES = ("GeoSite.dat", "GeoIP.dat", "Country.mmdb", "ASN.mmdb")
DB_IP = {"Country.mmdb": "country", "ASN.mmdb": "asn"}
REPOSITORY = r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
BRANCH = r"[A-Za-z0-9_][A-Za-z0-9_.\/-]*"
DOMAIN = r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        keys = set()
        for key, _ in node.value:
            value = self.construct_object(key)
            if not isinstance(value, str) or value in keys:
                raise ValueError(f"line {key.start_mark.line + 1}: duplicate or invalid mapping key")
            keys.add(value)
        return super().construct_mapping(node, deep=deep)


@dataclass(frozen=True)
class Configuration:
    policy: dict
    household: list
    probes: dict
    versions: dict


def schedule_settings(env):
    enabled = env.get("PUBLISH_SCHEDULE_ENABLED", "1")
    if enabled not in {"0", "1"}:
        raise ValueError("PUBLISH_SCHEDULE_ENABLED: expected 0 or 1")
    try:
        zone = ZoneInfo(env.get("PUBLISH_TIMEZONE", ""))
    except (ValueError, ZoneInfoNotFoundError):
        raise ValueError("PUBLISH_TIMEZONE: expected an installed IANA time zone") from None
    slots = env.get("PUBLISH_CHECK_TIMES", "").split(",")
    if len(set(slots)) != len(slots) or not all(
        re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", slot) for slot in slots
    ):
        raise ValueError("PUBLISH_CHECK_TIMES: expected distinct comma-separated HH:MM times")
    return enabled == "1", zone, sorted(time.fromisoformat(slot) for slot in slots)


def require(condition, path, expected):
    if not condition:
        raise ValueError(f"{path}: {expected}")


def mapping(value, path, required=(), optional=()):
    require(isinstance(value, dict), path, "expected a mapping")
    require(set(required) <= value.keys(), path, f"missing fields {sorted(set(required) - value.keys())}")
    extra = value.keys() - set(required) - set(optional)
    require(not extra, path, f"unknown fields {sorted(extra)}")
    return value


def sequence(value, path, *, nonempty=True):
    require(isinstance(value, list) and (value or not nonempty), path, "expected a list of entries")
    return value


def text(value, path, pattern=None):
    require(isinstance(value, str) and value.strip() and (pattern is None or re.fullmatch(pattern, value)),
            path, "invalid or empty value")
    return value


def safe_path(value, path, pattern):
    text(value, path, pattern)
    require(not any(part in {"", ".", ".."} for part in value.split("/")), path, "invalid path segment")


def github(repository, branch, path):
    safe_path(repository, f"{path}.repository", REPOSITORY)
    safe_path(branch, f"{path}.branch", BRANCH)
    require(".." not in branch and not branch.endswith((".", ".lock")), f"{path}.branch", "invalid branch")


def geo_definition(name, definition, path):
    require(isinstance(definition, dict), path, "expected a source definition")
    if definition.get("method") == "github":
        mapping(definition, path, ("method", "repository", "branch", "path", "license"))
        github(definition["repository"], definition["branch"], path)
        safe_path(definition["path"], f"{path}.path", r"[A-Za-z0-9_./-]+")
        require(definition["path"].lower().endswith(".dat" if name.endswith(".dat") else ".mmdb"),
                f"{path}.path", "file format does not match the published database")
        if name != "GeoSite.dat" and definition["repository"].lower() in {
            "loyalsoldier/geoip", "loyalsoldier/v2ray-rules-dat", "maxmind/geoipupdate",
        }:
            raise ValueError(f"{path}.repository: retired IP database source")
    elif definition.get("method") == "db-ip":
        mapping(definition, path, ("method", "kind", "license"))
        require(name in DB_IP and definition["kind"] == DB_IP[name],
                f"{path}.kind", "DB-IP database kind does not match its published role")
    else:
        raise ValueError(f"{path}.method: expected github or db-ip")
    if name != "GeoSite.dat" or definition["license"] is not None:
        text(definition["license"], f"{path}.license")
    return definition


def validate_ops(ops, path):
    for i, operation in enumerate(sequence(ops, path, nonempty=False)):
        location = f"{path}[{i}]"
        require(isinstance(operation, dict), location, "expected an operation")
        kind = operation.get("type")
        if kind in ("include_kinds", "exclude_kinds"):
            mapping(operation, location, ("type", "kinds"))
            for value in sequence(operation["kinds"], f"{location}.kinds"):
                text(value, f"{location}.kinds", r"[a-z_]+")
        elif kind == "filter_values":
            mapping(operation, location, ("type", "pattern"), ("mode",))
            require(operation.get("mode", "keyword") in ("keyword", "suffix", "prefix", "exact", "regex"),
                    f"{location}.mode", "unknown filter mode")
            text(operation["pattern"], f"{location}.pattern")
        else:
            raise ValueError(f"{location}.type: unknown operation")


def validate_providers(policy):
    sources = policy["sources"]
    providers = policy["providers"]
    require(isinstance(sources, dict), "sources", "expected a mapping")
    require(isinstance(providers, dict) and providers, "providers", "expected a nonempty mapping")
    for name, entry in sources.items():
        path = f"sources.{name}"
        require(isinstance(entry, list) and len(entry) == 2, path, "expected [repository, branch]")
        github(*entry, path)
    refs = {}
    for name, entry in providers.items():
        path = f"providers.{name}"
        text(name, path, r"[a-z0-9-]+")
        if isinstance(entry, list):
            require(len(entry) == 3, path, "expected [repository, path, behavior]")
            text(entry[2], f"{path}[2]", r"domain|ipcidr|classical")
            entry = {"sources": [{"repository": entry[0], "path": entry[1]}]}
        mapping(entry, path, ("sources",), ("merge", "ops"))
        if "merge" in entry:
            merge = mapping(entry["merge"], f"{path}.merge", ("strategy",))
            require(merge["strategy"] in ("union", "intersect", "difference"),
                    f"{path}.merge.strategy", "unknown merge strategy")
        if "ops" in entry:
            validate_ops(entry["ops"], f"{path}.ops")
        refs[name] = set()
        for i, source in enumerate(sequence(entry["sources"], f"{path}.sources")):
            location = f"{path}.sources[{i}]"
            require(isinstance(source, dict), location, "expected a source mapping")
            optional = ("label", "ops", "preprocess")
            if "repository" in source:
                mapping(source, location, ("repository", "path"), optional)
                require(text(source["repository"], location) in sources, location, "unknown repository reference")
                safe_path(source["path"], f"{location}.path", r"[A-Za-z0-9_./@+!-]+")
            elif "ref" in source:
                mapping(source, location, ("ref",), optional)
                require(text(source["ref"], location) in providers, location, "unknown provider reference")
                refs[name].add(source["ref"])
            else:
                mapping(source, location, ("content",), optional)
                text(source["content"], f"{location}.content")
            if "ops" in source:
                validate_ops(source["ops"], f"{location}.ops")
            if "label" in source:
                text(source["label"], f"{location}.label")
            if "preprocess" in source:
                require(isinstance(source["preprocess"], str), f"{location}.preprocess", "expected text")
    pending = dict(refs)
    while pending:
        ready = {name for name, deps in pending.items() if not deps}
        require(ready, "providers", f"cyclic provider references: {sorted(pending)}")
        pending = {name: deps - ready for name, deps in pending.items() if name not in ready}


def target_index(fields):
    index = len(fields) - 1
    while index > 1 and fields[index] in {"no-resolve", "src"}:
        index -= 1
    return index


def route_layout(sets, providers, path):
    rules = []
    for name, entries in sets:
        rules.extend(text(line, f"{path}.{name}", r"[^,\n]+,.+")
                     for line in sequence(entries, f"{path}.{name}", nonempty=False))
    kinds = [rule.split(",", 1)[0] for rule in rules]
    require(kinds and kinds[-1] == "MATCH" and "MATCH" not in kinds[:-1], path, "expected one final MATCH")
    targets, refs = set(), {}
    for rule in rules:
        fields = rule.split(",")
        end = target_index(fields)
        target = text(fields[end], path)
        targets.add(target)
        if fields[0] == "RULE-SET":
            require(end == 2 and fields[1] in providers and fields[1] not in refs,
                    path, f"invalid or repeated RULE-SET reference {fields[1]}")
            refs[fields[1]] = target
    require(refs.keys() == providers.keys(), path, f"missing routing references: {sorted(providers.keys() - refs.keys())}")
    return targets, refs


def validate_automation(automatic, refs):
    path = "automatic_updates"
    mapping(automatic, path, ("roles",), ("proxy", "proxy_removals", "services", "domestic_ip", "deferred_direct"))
    roles = mapping(automatic["roles"], f"{path}.roles", ("proxy", "media", "games", "domestic_ip"))
    groups = [text(roles[role], f"{path}.roles.{role}") for role in ("proxy", "media", "games")]
    require(len(set(groups)) == 3 and not (set(groups) & {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}),
            f"{path}.roles", "proxy, media and games need distinct proxy group names")
    domestic = text(roles["domestic_ip"], f"{path}.roles.domestic_ip")
    require(refs.get(domestic) == "DIRECT", f"{path}.roles.domestic_ip", "expected a provider routed to DIRECT")
    for name in sequence(automatic.get("proxy", []), f"{path}.proxy", nonempty=False):
        require(refs.get(text(name, f"{path}.proxy")) == groups[0], f"{path}.proxy", f"unexpected route for {name}")
    services = automatic.get("services", {})
    require(isinstance(services, dict), f"{path}.services", "expected a mapping")
    for name, roots in services.items():
        require(refs.get(name) in groups[1:], f"{path}.services.{name}", "provider must route to media or games")
        for root in sequence(roots, f"{path}.services.{name}"):
            text(root, f"{path}.services.{name}", DOMAIN)
    for key in ("proxy_removals", "domestic_ip"):
        require(isinstance(automatic.get(key, False), bool), f"{path}.{key}", "expected a boolean")
    for value in sequence(automatic.get("deferred_direct", []), f"{path}.deferred_direct", nonempty=False):
        try:
            low, high = map(ip_address, text(value, f"{path}.deferred_direct").split("–"))
            valid = low.version == high.version and low <= high
        except ValueError:
            valid = False
        require(valid, f"{path}.deferred_direct", "expected an ordered address interval")


def validate_probes(probes, targets, refs, automatic):
    mapping(probes, "probes", ("baseline", "converged", "guards", "geo"))
    guards = mapping(probes["guards"], "guards", ("openai_suffixes", "domestic_anchors", "direct_ports"))
    guards = [mapping(guards[guard], f"guards.{guard}", ("provider", "domains") if guard != "direct_ports"
                      else ("provider",)) for guard in ("openai_suffixes", "domestic_anchors", "direct_ports")]
    openai, domestic, ports = guards
    protected = [text(guard["provider"], "guards.provider") for guard in guards]
    require(len(set(protected)) == 3 and all(name in refs for name in protected),
            "guards.provider", "expected distinct declared providers")
    require(not (set(protected) & (set(automatic.get("proxy", [])) | set(automatic.get("services", {})))),
            "guards.provider", "protected providers cannot use automatic proxy or service allowances")
    require(refs[protected[0]] not in {"DIRECT", *[automatic["roles"][role] for role in ("proxy", "media", "games")]},
            "guards.openai_suffixes.provider", "provider must retain its dedicated policy")
    require(all(refs[name] == "DIRECT" for name in protected[1:]),
            "guards.provider", "domestic and mixed-direct guards must cover DIRECT providers")
    for guard, name in ((openai, "openai_suffixes"), (domestic, "domestic_anchors")):
        for domain in sequence(guard["domains"], f"guards.{name}.domains"):
            text(domain, f"guards.{name}.domains", DOMAIN)

    geo = mapping(probes["geo"], "geo", ("rules", "probes"))
    geo_targets, _ = route_layout((("rules", geo["rules"]),), {}, "geo")
    for entries, groups, path in ((probes["baseline"], targets, "baseline"),
                                  (probes["converged"], targets, "converged"),
                                  (geo["probes"], geo_targets, "geo.probes")):
        require(isinstance(entries, dict) and entries, path, "expected a nonempty probe mapping")
        for host, expected in entries.items():
            location = f"{path}.{host}"
            require(isinstance(expected, list) and len(expected) == 2, location, "expected [match, policy group]")
            match, group = map(lambda v: text(v, location), expected)
            require(group in groups, location, "unknown policy group")
            if match.startswith("RuleSet("):
                require(refs.get(match.removeprefix("RuleSet(").removesuffix(")")) == group,
                        location, "unknown rule provider or wrong policy group")
    names = {value[0].lower().split("(", 1)[0] for value in geo["probes"].values()}
    require({"geosite", "geoip", "ipasn", "match"} <= names, "geo.probes", "missing database coverage")
    require(all(any(host.startswith("[") and value[0].startswith(kind + "(")
                    for host, value in geo["probes"].items()) for kind in ("GeoIP", "IPASN")),
            "geo.probes", "missing IPv6 GeoIP or ASN coverage")


def load(root):
    raw = {name: (root / name).read_bytes() for name in FILES}
    parsed = {}
    for name, data in raw.items():
        try:
            parsed[name] = yaml.load(data, Loader=UniqueLoader)
        except (ValueError, yaml.YAMLError) as error:
            mark = getattr(error, "problem_mark", None)
            detail = str(error) if mark is None else f"line {mark.line + 1}: invalid YAML"
            raise ValueError(f"{name}: {detail}") from None

    policy, household, probes = (parsed[name] for name in FILES)
    try:
        mapping(policy, "policy", ("sources", "providers", "early_rules", "rules", "geo_sources", "automatic_updates"))
        validate_providers(policy)
        geo = mapping(policy["geo_sources"], "geo_sources", GEO_FILES)
        for name, definition in geo.items():
            geo_definition(name, definition, f"geo_sources.{name}")
    except ValueError as error:
        raise ValueError(f"sources.yaml:{error}") from None
    sequence(household, "household-rules.yaml")
    try:
        targets, refs = route_layout((("early_rules", policy["early_rules"]), ("household-rules.yaml", household),
                                      ("rules", policy["rules"])), policy["providers"], "rules")
        automatic = policy["automatic_updates"]
        validate_automation(automatic, refs)
    except ValueError as error:
        raise ValueError(f"sources.yaml:{error}") from None
    try:
        validate_probes(probes, targets, refs, automatic)
    except ValueError as error:
        raise ValueError(f"probes.yaml:{error}") from None
    return Configuration(policy, household, probes, {name: sha256(data).hexdigest() for name, data in raw.items()})
