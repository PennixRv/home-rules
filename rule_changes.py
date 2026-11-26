from collections import Counter, defaultdict
from dataclasses import dataclass
from heapq import heappop, heappush
from ipaddress import IPv4Address, IPv6Address, ip_network
from itertools import chain

from verify_release import target_index


@dataclass(frozen=True, order=True)
class Match:
    position: int
    target: str
    provider: str = ""


def domain_suffixes(host):
    labels = host.split(".")
    return (".".join(labels[i:]) for i in range(len(labels)))


class RuleIndex:
    def __init__(self, bundle):
        self.exact = {}
        self.suffix = {}
        self.ip = {4: [], 6: []}
        self.resolved_ip = {4: [], 6: []}
        self.conditional = set()
        self.conditions = {"domain": set(), "ip": set(), "opaque": set()}
        for index, rule in enumerate(bundle["rules"]):
            fields = rule.split(",")
            order = target_index(fields)
            provider = fields[1] if fields[0] == "RULE-SET" else ""
            match = Match(index, fields[order], provider)
            if fields[0] == "MATCH":
                self.fallback = match
                continue
            if provider:
                entries = bundle["rule-providers"][provider]["payload"]
            else:
                entries = [",".join(fields[:order] + fields[order + 1:])]
            for entry in entries:
                kind, _, value = entry.partition(",")
                if kind in ("DOMAIN", "DOMAIN-SUFFIX") and "," not in value:
                    lookup = self.exact if kind == "DOMAIN" else self.suffix
                    lookup.setdefault(value.lower(), match)
                    self.conditions["domain"].add(match)
                elif kind in ("IP-CIDR", "IP-CIDR6") and value.split(",")[1:] in ([], ["no-resolve"]):
                    self.conditions["ip"].add(match)
                    network = ip_network(value.split(",", 1)[0], strict=False)
                    first = int(network.network_address)
                    last = int(network.broadcast_address) + 1
                    self.ip[network.version].append((first, last, match))
                    if "no-resolve" not in fields[order + 1:] and not value.endswith(",no-resolve"):
                        self.resolved_ip[network.version].append((first, last, match))
                else:
                    self.conditional.add((match, entry, ",".join(fields[order + 1:])))
                    self.conditions["opaque"].add(match)

    def domain(self, host):
        return min(
            chain(
                (self.exact.get(host, self.fallback),),
                (self.suffix.get(suffix, self.fallback) for suffix in domain_suffixes(host)),
            )
        )


def ranges(networks, fallback, version):
    """Yield the address boundaries and their first matching route."""
    end = 1 << (32 if version == 4 else 128)
    events = [(0, end, fallback), *networks]
    starts = defaultdict(list)
    points = {end}
    for first, last, match in events:
        starts[first].append((match, last))
        points.update((first, last))
    active = []
    for point in sorted(points):
        if point == end:
            break
        for match, last in starts[point]:
            heappush(active, (match, last))
        while active[0][1] <= point:
            heappop(active)
        yield point, active[0][0]


def compare_ranges(prior, candidate, version, resolved):
    prior_networks = prior.resolved_ip if resolved else prior.ip
    candidate_networks = candidate.resolved_ip if resolved else candidate.ip
    old = dict(ranges(prior_networks[version], prior.fallback, version))
    new = dict(ranges(candidate_networks[version], candidate.fallback, version))
    address = IPv4Address if version == 4 else IPv6Address
    points = sorted(old.keys() | new.keys())
    left, right = old[0], new[0]
    limits = [*points[1:], 1 << (32 if version == 4 else 128)]
    for point, end in zip(points, limits):
        left = old.get(point, left)
        right = new.get(point, right)
        if left != right:
            yield f"{address(point)}–{address(end - 1)}", left, right


def compare(prior_bundle, candidate_bundle, automatic_additions=()):
    prior = RuleIndex(prior_bundle)
    candidate = RuleIndex(candidate_bundle)
    summary = Counter()
    samples = defaultdict(list)

    def record(status, kind, condition, old, new):
        key = (status, kind, old.target, new.target, old.provider, new.provider)
        summary[key] += 1
        if len(samples[key]) < 6:
            samples[key].append(condition)

    def compare_match(kind, condition, old, new):
        if old == new:
            return
        other = "ip" if kind.startswith("domain") else "domain"
        first, last = sorted((old.position, new.position))
        intervening = set()
        for index in (prior, candidate):
            intervening.update(
                match.target for match in index.conditions[other] | index.conditions["opaque"]
                if first <= match.position < last
            )
        if intervening - {old.target, new.target}:
            status = "conditional"
        elif old.target == new.target:
            status = "equivalent"
        elif old == prior.fallback and new.provider in automatic_additions:
            status = "allowed"
        else:
            status = "review"
        record(status, kind, condition, old, new)

    for match, entry, flags in sorted(prior.conditional ^ candidate.conditional):
        record("conditional", "opaque", f"{entry} {flags}".strip(), match, match)

    suffixes = prior.suffix.keys() | candidate.suffix.keys()
    names = prior.exact.keys() | candidate.exact.keys() | suffixes
    for host in sorted(names):
        compare_match("domain", host, prior.domain(host), candidate.domain(host))
        if host in suffixes:
            branch = f"home-rule-probe.{host}"
            while branch in names:
                branch = "x-" + branch
            compare_match("domain-suffix", branch, prior.domain(branch), candidate.domain(branch))
    for resolved in (False, True):
        for version in (4, 6):
            kind = f"ipv{version}-resolved" if resolved else f"ipv{version}"
            for address, old, new in compare_ranges(prior, candidate, version, resolved):
                compare_match(kind, address, old, new)

    return [
        {"status": key[0], "kind": key[1], "previous_target": key[2], "candidate_target": key[3],
         "previous_provider": key[4], "candidate_provider": key[5], "count": count, "samples": samples[key]}
        for key, count in sorted(summary.items())
    ]
