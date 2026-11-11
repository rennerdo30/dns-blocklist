#!/usr/bin/env python3
"""Check whether the domains of a blocklist are actually blocked by your DNS.

Each domain is resolved through the system resolver (or a specific DNS server with --server) and
compared with an unfiltered reference resolver:

  blocked       sinkhole answer (0.0.0.0, ::, 127.0.0.1, --block-ip) or NXDOMAIN while the
                reference resolver still resolves the domain
  not blocked   resolves to a real address -> the domain gets through your filter
  dead          does not resolve anywhere (domain no longer exists; not counted)
  error         timeouts / resolver failures

Examples:
  python3 scripts/check.py                              # 1000 random domains from the published list
  python3 scripts/check.py --sample 0                   # check every domain (slow)
  python3 scripts/check.py --list dist/domains-lite.txt --server 192.168.1.1
  python3 scripts/check.py --fail-under 95 --json report.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import locale
import logging
import os
import random
import secrets
import socket
import struct
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build import USER_AGENT, parse_line, read_domain_file  # noqa: E402

LOG = logging.getLogger("check")

DEFAULT_LIST_URL = "https://raw.githubusercontent.com/rennerdo30/dns-blocklist/lists/domains.txt"
DEFAULT_REFERENCE_SERVER = "1.1.1.1"
DEFAULT_SAMPLE_SIZE = 1000
DEFAULT_WORKERS = 64
DEFAULT_TIMEOUT_SECONDS = 3.0
DNS_PORT = 53
DNS_RETRIES = 2
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_CLASS_IN = 1
DNS_RCODE_NXDOMAIN = 3
DNS_MAX_UDP_SIZE = 4096
SINKHOLE_ADDRESSES = {"0.0.0.0", "::", "127.0.0.1", "::1"}
MAX_LISTED_LEAKS = 25
DOWNLOAD_TIMEOUT_SECONDS = 120

BLOCKED, NOT_BLOCKED, DEAD, ERROR = "blocked", "not_blocked", "dead", "error"

MESSAGES = {
    "en": {
        "loading": "Loading list from {source}",
        "loaded": "{total} domains in list, checking {count}",
        "resolver": "Resolver under test: {resolver} | reference: {reference}",
        "dns_broken": "Your DNS does not resolve {domain}; is the resolver reachable? Aborting.",
        "summary": "Result",
        "blocked": "Blocked",
        "not_blocked": "Not blocked",
        "dead": "Dead (resolves nowhere)",
        "error": "Errors / timeouts",
        "rate": "Block rate (of live domains)",
        "leaks": "Domains that are NOT blocked (first {n}):",
        "hint_ip": "Hint: many answers point to {ip}. If that is your router's block page, rerun with --block-ip {ip}",
        "fail": "Block rate {rate:.1f}% is below --fail-under {limit}%",
        "report": "JSON report written to {path}",
    },
    "de": {
        "loading": "Lade Liste von {source}",
        "loaded": "{total} Domains in der Liste, prüfe {count}",
        "resolver": "Geprüfter Resolver: {resolver} | Referenz: {reference}",
        "dns_broken": "Dein DNS löst {domain} nicht auf; ist der Resolver erreichbar? Abbruch.",
        "summary": "Ergebnis",
        "blocked": "Blockiert",
        "not_blocked": "Nicht blockiert",
        "dead": "Tot (nirgends auflösbar)",
        "error": "Fehler / Timeouts",
        "rate": "Blockrate (aktive Domains)",
        "leaks": "Domains, die NICHT blockiert werden (erste {n}):",
        "hint_ip": "Hinweis: Viele Antworten zeigen auf {ip}. Falls das die Sperrseite deines Routers ist, erneut mit --block-ip {ip} ausführen",
        "fail": "Blockrate {rate:.1f}% liegt unter --fail-under {limit}%",
        "report": "JSON-Bericht gespeichert unter {path}",
    },
}
CONTROL_DOMAINS = ("google.com", "cloudflare.com")


def detect_language() -> str:
    lang = os.environ.get("LC_ALL") or os.environ.get("LANG") or (locale.getlocale()[0] or "")
    return "de" if lang.lower().startswith("de") else "en"


# --------------------------------------------------------------------------- minimal DNS client
class DnsError(Exception):
    pass


def _encode_name(domain: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in domain.split(".")) + b"\0"


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def dns_query(server: str, domain: str, qtype: int, timeout: float) -> tuple[int, list[str]]:
    """Send one UDP query. Returns (rcode, addresses)."""
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    query_id = secrets.randbits(16)
    packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + _encode_name(domain) + struct.pack(
        ">HH", qtype, DNS_CLASS_IN)
    last_error: Exception | None = None
    for _ in range(DNS_RETRIES):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendto(packet, (server, DNS_PORT))
                while True:
                    data, _ = sock.recvfrom(DNS_MAX_UDP_SIZE)
                    if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == query_id:
                        break
            except OSError as error:
                last_error = error
                continue
        _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
        offset = 12
        for _ in range(qdcount):
            offset = _skip_name(data, offset) + 4
        addresses = []
        for _ in range(ancount):
            offset = _skip_name(data, offset)
            rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rtype == DNS_TYPE_A and rdlength == 4:
                addresses.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == DNS_TYPE_AAAA and rdlength == 16:
                addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))
        return flags & 0x000F, addresses
    raise DnsError(f"no answer from {server}: {last_error}")


def resolve_direct(server: str, domain: str, timeout: float) -> list[str] | None:
    """Addresses from a specific server; [] for NXDOMAIN/no data. Raises DnsError on timeout."""
    rcode, addresses = dns_query(server, domain, DNS_TYPE_A, timeout)
    if rcode == DNS_RCODE_NXDOMAIN:
        return []
    if not addresses:
        _, addresses = dns_query(server, domain, DNS_TYPE_AAAA, timeout)
    return addresses


def resolve_system(domain: str) -> list[str]:
    """Addresses from the OS resolver (what applications see); [] if it does not resolve."""
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        if error.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)):
            return []
        raise DnsError(str(error)) from error
    return sorted({info[4][0].split("%")[0] for info in infos})


# --------------------------------------------------------------------------- checking
def classify(domain: str, args: argparse.Namespace, sinkholes: set[str]) -> dict:
    result = {"domain": domain}
    try:
        answers = (resolve_direct(args.server, domain, args.timeout) if args.server
                   else resolve_system(domain))
    except DnsError as error:
        return result | {"status": ERROR, "detail": str(error)}
    result["answers"] = answers
    if answers and all(a in sinkholes for a in answers):
        return result | {"status": BLOCKED}
    if answers:
        return result | {"status": NOT_BLOCKED}
    # No answer locally: blocked via NXDOMAIN, or the domain is simply gone?
    try:
        reference = resolve_direct(args.reference, domain, args.timeout)
    except DnsError as error:
        return result | {"status": ERROR, "detail": f"reference: {error}"}
    return result | {"status": BLOCKED if reference else DEAD, "reference": reference}


def load_domains(source: str) -> list[str]:
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            text = response.read().decode("utf-8", errors="replace")
        domains = {d for d, exc in map(parse_line, text.splitlines()) if d and not exc}
    else:
        domains = read_domain_file(Path(source))
    return sorted(domains)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", default=DEFAULT_LIST_URL, help="URL or file (domains, hosts or adblock format)")
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE_SIZE, help="random domains to check, 0 = all")
    parser.add_argument("--seed", type=int, help="random seed for a reproducible sample")
    parser.add_argument("--server", help="query this DNS server directly instead of the system resolver")
    parser.add_argument("--reference", default=DEFAULT_REFERENCE_SERVER, help="unfiltered resolver for comparison")
    parser.add_argument("--block-ip", action="append", default=[], help="extra sinkhole/block-page IP (repeatable)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="seconds per DNS query")
    parser.add_argument("--fail-under", type=float, help="exit 1 if the block rate (%%) is below this value")
    parser.add_argument("--json", type=Path, help="write a detailed JSON report to this file")
    parser.add_argument("--lang", choices=sorted(MESSAGES), default=detect_language())
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level, format="%(levelname)-7s %(message)s")
    msg = MESSAGES[args.lang]
    sinkholes = SINKHOLE_ADDRESSES | {str(ipaddress.ip_address(ip)) for ip in args.block_ip}

    LOG.info(msg["loading"].format(source=args.list))
    domains = load_domains(args.list)
    selected = domains if args.sample <= 0 or args.sample >= len(domains) else \
        random.Random(args.seed).sample(domains, args.sample)
    LOG.info(msg["loaded"].format(total=len(domains), count=len(selected)))
    LOG.info(msg["resolver"].format(resolver=args.server or "system", reference=args.reference))

    for control in CONTROL_DOMAINS:
        check = classify(control, args, sinkholes)
        if check["status"] != NOT_BLOCKED:
            LOG.error(msg["dns_broken"].format(domain=control))
            return 2

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda d: classify(d, args, sinkholes), selected))

    counts = {s: sum(r["status"] == s for r in results) for s in (BLOCKED, NOT_BLOCKED, DEAD, ERROR)}
    live = counts[BLOCKED] + counts[NOT_BLOCKED]
    rate = 100.0 * counts[BLOCKED] / live if live else 100.0
    leaks = sorted(r["domain"] for r in results if r["status"] == NOT_BLOCKED)

    print(f"\n{msg['summary']}")
    for status in (BLOCKED, NOT_BLOCKED, DEAD, ERROR):
        print(f"  {msg[status]:<30} {counts[status]:>8}")
    print(f"  {msg['rate']:<30} {rate:>7.1f}%")
    if leaks:
        print("\n" + msg["leaks"].format(n=MAX_LISTED_LEAKS))
        for domain in leaks[:MAX_LISTED_LEAKS]:
            answers = next(r["answers"] for r in results if r["domain"] == domain)
            print(f"  {domain:<50} {', '.join(answers)}")
        common: dict[str, int] = {}
        for r in results:
            if r["status"] == NOT_BLOCKED:
                for a in r["answers"]:
                    common[a] = common.get(a, 0) + 1
        top_ip, top_count = max(common.items(), key=lambda kv: kv[1])
        if top_count >= max(5, len(leaks) // 2):
            print("\n" + msg["hint_ip"].format(ip=top_ip))

    if args.json:
        report = {"list": args.list, "resolver": args.server or "system", "reference": args.reference,
                  "counts": counts, "block_rate": round(rate, 2), "results": results}
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        LOG.info(msg["report"].format(path=args.json))

    if args.fail_under is not None and rate < args.fail_under:
        LOG.error(msg["fail"].format(rate=rate, limit=args.fail_under))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
