import os
import shutil
import socket
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep

import yaml

from mihomo import mihomo_binary


OPENAI_SUFFIXES = ("chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com")
GEO_PROBES = {
    "chatgpt.com": ("GeoSite(category-ai-!cn)", "PROBE"),
    "store.steampowered.com": ("GeoSite(category-games)", "PROBE"),
    "www.google.com": ("GeoSite(google)", "PROBE"),
    "223.5.5.5": ("GeoIP(cn)", "PROBE"),
    "1.1.1.1": ("IPASN(13335)", "PROBE"),
    "[2400:3200::1]": ("GeoIP(cn)", "PROBE"),
    "[2606:4700:4700::1111]": ("IPASN(13335)", "PROBE"),
    "9.9.9.9": ("Match", "PROBE"),
}
DOMESTIC_ANCHORS = ("baidu.com", "bilibili.com", "qq.com", "taobao.com", "weibo.com")


def target_index(fields):
    index = len(fields) - 1
    while index > 1 and fields[index] in {"no-resolve", "src"}:
        index -= 1
    return index


def check_policy(providers, rules):
    kinds = [rule.split(",", 1)[0] for rule in rules]
    if not kinds or kinds[-1] != "MATCH" or "MATCH" in kinds[:-1]:
        raise ValueError("Expected one final MATCH")
    references = [rule.split(",", 2)[1] for rule in rules if rule.startswith("RULE-SET,")]
    unique = set(references)
    if unique != providers.keys():
        raise ValueError(f"Rule provider inventory differs from routing references: {sorted(unique ^ providers.keys())}")
    if len(unique) != len(references):
        raise ValueError("A rule provider appears more than once in routing")
    openai = set(providers.get("openai", {}).get("payload", ()))
    for suffix in OPENAI_SUFFIXES:
        if f"DOMAIN-SUFFIX,{suffix}" not in openai:
            raise ValueError(f"OpenAI domain suffix coverage lost: {suffix}")
    entries = {tuple(item.split(",")[:2]) for item in providers["domestic"]["payload"]}
    for host in DOMESTIC_ANCHORS:
        labels = host.split(".")
        suffixes = (".".join(labels[i:]) for i in range(len(labels)))
        if ("DOMAIN", host) not in entries and not any(
            ("DOMAIN-SUFFIX", suffix) in entries for suffix in suffixes
        ):
            raise ValueError(f"Domestic domain coverage lost: {host}")


def check_core(root, geo, providers, rules, converged=False):
    check_policy(providers, rules)
    if converged:
        port_conditions = ("DST-PORT,", "SRC-PORT,")
        if any(item.startswith(port_conditions) for item in providers["direct-mixed"]["payload"]):
            raise ValueError("An independent port condition remains in the mixed direct provider")
    config = Path(os.environ.get("RULES_CONFIG", Path(__file__).resolve().parent))
    probe_config = yaml.safe_load((config / "probes.yaml").read_bytes())
    probes = probe_config["baseline"]
    if converged:
        probes = probes | probe_config["converged"]
    if not probes or any(
        not isinstance(host, str) or not isinstance(expected, list) or len(expected) != 2
        or not all(isinstance(item, str) and item for item in expected)
        for host, expected in probes.items()
    ):
        raise ValueError("Invalid routing probes")
    binary = mihomo_binary()
    with TemporaryDirectory(dir=root) as temporary:
        probe_dir = Path(temporary)
        for name in ("GeoSite.dat", "GeoIP.dat", "Country.mmdb", "ASN.mmdb"):
            shutil.copyfile(geo / name, probe_dir / name)
        run_probes(binary, probe_dir, providers, rules, False, probes)
        geo_rules = [
            "GEOSITE,category-ai-!cn,PROBE",
            "GEOSITE,category-games,PROBE",
            "GEOSITE,google,PROBE",
            "GEOIP,CN,PROBE,no-resolve",
            "IP-ASN,13335,PROBE,no-resolve",
            "MATCH,PROBE",
        ]
        for dat_mode in (True, False):
            run_probes(binary, probe_dir, {}, geo_rules, dat_mode, GEO_PROBES)


def run_probes(binary, root, providers, rules, dat_mode, probes):
    targets = {}
    rewritten = []
    for rule in rules:
        fields = rule.split(",")
        index = target_index(fields)
        target = fields[index]
        fields[index] = targets.setdefault(target, f"verify-{len(targets)}")
        rewritten.append(",".join(fields))

    expected = {}
    for host, (rule, target) in probes.items():
        if target not in targets:
            raise ValueError(f"Expected policy {target} for {host} is missing")
        expected[host] = (f"match {rule} using {targets[target]}[").lower()

    with socket.socket() as reserving:
        reserving.bind(("127.0.0.1", 0))
        port = reserving.getsockname()[1]
    config = {
        "mode": "rule", "geodata-mode": dat_mode, "log-level": "info",
        "allow-lan": False, "mixed-port": port, "bind-address": "127.0.0.1",
        "geox-url": dict.fromkeys(("mmdb", "geoip", "geosite", "asn"), "http://127.0.0.1:1/"),
        "rule-providers": providers, "rules": rewritten,
        "proxy-groups": [{"name": name, "type": "select", "proxies": ["REJECT"]} for name in targets.values()],
    }
    config_file = root / "probe.yaml"
    config_file.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
    log = root / "probe.log"
    with log.open("w") as output:
        core = subprocess.Popen([binary, "-d", root, "-f", config_file], stdout=output, stderr=output)
        try:
            deadline = monotonic() + 12
            while True:
                try:
                    socket.create_connection(("127.0.0.1", port), 0.25).close()
                    break
                except OSError:
                    if monotonic() >= deadline or core.poll() is not None:
                        raise ValueError("Mihomo rule probes could not start") from None
                    sleep(0.1)
            missing = list(probes)
            deadline = monotonic() + 5
            while missing:
                for host in missing:
                    with socket.create_connection(("127.0.0.1", port), 2) as probe:
                        probe.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
                        with probe.makefile("rb") as response:
                            status = response.readline()
                            if b" 200 " not in status:
                                raise ValueError(f"Mihomo rejected CONNECT for {host}: {status!r}")
                            while response.readline() not in (b"\r\n", b""):
                                pass
                            try:
                                probe.sendall(b"probe")
                                response.read(1)
                            except ConnectionResetError:
                                pass
                results = log.read_text().lower().splitlines()
                missing = [host for host, match in probes.items() if not any(
                    f"--> {host}:443" in line and expected[host] in line for line in results
                )]
                if not missing:
                    break
                if monotonic() >= deadline or core.poll() is not None:
                    details = [
                        line[line.index("-->"):] for line in results if "-->" in line
                        and any(f"--> {host}:443" in line for host in missing)
                    ]
                    policies = {host: probes[host] for host in missing}
                    raise ValueError(f"Unexpected Mihomo rule or policy (dat={dat_mode}): {policies}; {details}")
                sleep(0.1)
        finally:
            core.terminate()
            try:
                core.wait(timeout=5)
            except subprocess.TimeoutExpired:
                core.kill()
                core.wait()
