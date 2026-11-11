#!/usr/bin/env python3
"""Download public ad/tracker/malware blocklists and merge them into DNS-ready lists.

Accepted upstream formats (detected per line):
  * hosts files            0.0.0.0 example.com
  * plain domain lists     example.com
  * adblock domain rules   ||example.com^      (rules with modifiers or paths are skipped)
  * adblock exceptions     @@||example.com^    (honoured as allowlist entries)

Outputs (in the output directory):
  domains.txt / domains-lite.txt   one exact domain per line (Pi-hole, AdGuard Home, UniFi, pfBlockerNG)
  hosts.txt   / hosts-lite.txt     0.0.0.0 <domain>
  adblock.txt / adblock-lite.txt   ||domain^, redundant subdomains removed (AdGuard Home, uBlock Origin)
  stats.json                       per-source counts and failures
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import logging
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

LOG = logging.getLogger("build")

USER_AGENT = "dns-blocklist-builder/1.0 (+https://github.com/rennerdo30/dns-blocklist)"
HTTP_TIMEOUT_SECONDS = 90
HTTP_RETRIES = 3
RETRY_BACKOFF_SECONDS = 5
MAX_PARALLEL_DOWNLOADS = 6
MAX_DOMAIN_LENGTH = 253
# Refuse to publish if the merged list shrinks below this fraction of the last published one.
MIN_RATIO_TO_PREVIOUS = 0.5
# Refuse to publish if more than this fraction of sources failed to download.
MAX_FAILED_SOURCE_RATIO = 0.5
SINK_ADDRESS = "0.0.0.0"
REPO_URL = "https://github.com/rennerdo30/dns-blocklist"

LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
ADBLOCK_RE = re.compile(r"^(@@)?\|\|([^/^$*|]+)\^(\$(important|all|document|doc))?$")
COMMENT_PREFIXES = ("#", "!", "[", ";")
INLINE_COMMENT_RE = re.compile(r"\s#")


def normalize_domain(raw: str) -> str | None:
    """Return a lowercase, validated domain or None if the token is not a blockable domain."""
    domain = raw.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if not domain or len(domain) > MAX_DOMAIN_LENGTH or "." not in domain:
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    labels = domain.split(".")
    if not all(LABEL_RE.match(label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return domain


def parse_line(line: str) -> tuple[str | None, bool]:
    """Parse one upstream line. Returns (domain, is_exception)."""
    line = line.strip()
    if not line or line.startswith(COMMENT_PREFIXES):
        return None, False
    # Adblock cosmetic/scriptlet rules (example.com##.ad, #@#, #?#, #$#) are not domain rules.
    if "#" in line and not INLINE_COMMENT_RE.search(line):
        return None, False
    # Strip inline comments used by hosts files ("0.0.0.0 example.com  # note").
    line = INLINE_COMMENT_RE.split(line, 1)[0].strip()
    if not line:
        return None, False

    if line.startswith(("||", "@@||")):
        match = ADBLOCK_RE.match(line)
        if not match:
            return None, False
        return normalize_domain(match.group(2)), bool(match.group(1))

    tokens = line.split()
    if len(tokens) >= 2:
        try:
            ipaddress.ip_address(tokens[0])
        except ValueError:
            return None, False
        # Hosts lines may list several names; the common lists use exactly one.
        return normalize_domain(tokens[1]), False
    if len(tokens) == 1:
        return normalize_domain(tokens[0]), False
    return None, False


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500 and error.code != 429:
                raise RuntimeError(f"{url} returned HTTP {error.code}") from error
            last_error = error
            LOG.warning("Download attempt %d/%d failed for %s: %s", attempt, HTTP_RETRIES, url, error)
            if attempt < HTTP_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last_error = error
            LOG.warning("Download attempt %d/%d failed for %s: %s", attempt, HTTP_RETRIES, url, error)
            if attempt < HTTP_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    raise RuntimeError(f"giving up on {url}: {last_error}")


def process_source(source: dict) -> dict:
    result = {"name": source["name"], "url": source["url"], "lite": source.get("lite", False)}
    try:
        text = fetch(source["url"])
    except RuntimeError as error:
        LOG.error("Source failed: %s (%s)", source["name"], error)
        result.update(ok=False, error=str(error), domains=set(), exceptions=set())
        return result
    domains: set[str] = set()
    exceptions: set[str] = set()
    for line in text.splitlines():
        domain, is_exception = parse_line(line)
        if domain:
            (exceptions if is_exception else domains).add(domain)
    LOG.info("%-45s %8d domains, %5d exceptions", source["name"], len(domains), len(exceptions))
    result.update(ok=True, domains=domains, exceptions=exceptions)
    return result


def read_domain_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        domain, _ = parse_line(line)
        if domain:
            found.add(domain)
    return found


def remove_covered_subdomains(domains: set[str]) -> list[str]:
    """Drop entries whose parent domain is also listed (valid for ||domain^ semantics only)."""
    kept = []
    for domain in domains:
        parts = domain.split(".")
        if not any(".".join(parts[i:]) in domains for i in range(1, len(parts) - 1)):
            kept.append(domain)
    return sorted(kept)


def header(title: str, count: int, generated: str, comment: str) -> str:
    lines = [
        f"Title: {title}",
        f"Homepage: {REPO_URL}",
        f"Last modified: {generated}",
        "Update frequency: every 6 hours",
        f"Entries: {count}",
    ]
    return "".join(f"{comment} {line}\n" for line in lines) + f"{comment}\n"


def write_outputs(out_dir: Path, suffix: str, domains: set[str], generated: str) -> dict:
    ordered = sorted(domains)
    compressed = remove_covered_subdomains(domains)
    label = "lite" if suffix else "full"
    files = {
        f"domains{suffix}.txt": header(f"DNS blocklist ({label}, domains)", len(ordered), generated, "#")
        + "\n".join(ordered) + "\n",
        f"hosts{suffix}.txt": header(f"DNS blocklist ({label}, hosts)", len(ordered), generated, "#")
        + "\n".join(f"{SINK_ADDRESS} {d}" for d in ordered) + "\n",
        f"adblock{suffix}.txt": header(f"DNS blocklist ({label}, adblock)", len(compressed), generated, "!")
        + "\n".join(f"||{d}^" for d in compressed) + "\n",
    }
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8")
        LOG.info("Wrote %s (%.1f MB)", name, len(content.encode()) / 1_000_000)
    return {"domains": len(ordered), "adblock_rules": len(compressed)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument("--config-dir", type=Path, default=root / "config")
    parser.add_argument("--out-dir", type=Path, default=root / "dist")
    parser.add_argument("--previous-stats", type=Path, help="stats.json of the last published build")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level, format="%(levelname)-7s %(message)s")

    sources = json.loads((args.config_dir / "sources.json").read_text(encoding="utf-8"))["sources"]
    allow = read_domain_file(args.config_dir / "allowlist.txt")
    extra = read_domain_file(args.config_dir / "blocklist.txt")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_DOWNLOADS) as pool:
        results = list(pool.map(process_source, sources))

    failed = [r for r in results if not r["ok"]]
    if len(failed) > len(results) * MAX_FAILED_SOURCE_RATIO:
        LOG.error("%d of %d sources failed; not publishing", len(failed), len(results))
        return 1

    exceptions = set().union(*(r["exceptions"] for r in results)) | allow
    full = (set().union(*(r["domains"] for r in results)) | extra) - exceptions
    lite = (set().union(*(r["domains"] for r in results if r["lite"])) | extra) - exceptions

    canaries = read_domain_file(args.config_dir / "canaries.txt")
    leaked = sorted(canaries & full)
    if leaked:
        LOG.error("Essential domains would be blocked: %s; not publishing", ", ".join(leaked))
        for r in results:
            hits = sorted(canaries & r["domains"])
            if hits:
                LOG.error("  listed by %s: %s", r["name"], ", ".join(hits))
        return 1

    if args.previous_stats and args.previous_stats.exists():
        try:
            previous = json.loads(args.previous_stats.read_text(encoding="utf-8"))["full"]["domains"]
        except (json.JSONDecodeError, KeyError) as error:
            LOG.warning("Ignoring unreadable previous stats: %s", error)
        else:
            if len(full) < previous * MIN_RATIO_TO_PREVIOUS:
                LOG.error("Merged list shrank from %d to %d domains; not publishing", previous, len(full))
                return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = {
        "generated": generated,
        "full": write_outputs(args.out_dir, "", full, generated),
        "lite": write_outputs(args.out_dir, "-lite", lite, generated),
        "sources": [
            {k: r.get(k) for k in ("name", "url", "lite", "ok", "error")} | {"domains": len(r["domains"])}
            for r in results
        ],
    }
    (args.out_dir / "stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    LOG.info("Full: %d domains, lite: %d domains, %d source(s) failed",
             len(full), len(lite), len(failed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
