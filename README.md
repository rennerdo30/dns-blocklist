# dns-blocklist

A merged, de-duplicated DNS blocklist built from the well-known Pi-hole / AdGuard / uBlock lists.
GitHub Actions rebuilds it **every 6 hours**, so you can add it as a dynamic list to your
router or DNS server.

## Subscribe

Use the raw URLs from the `lists` branch:

| List | Format | Use with |
| --- | --- | --- |
| [`domains.txt`](https://raw.githubusercontent.com/rennerdo30/dns-blocklist/lists/domains.txt) | one domain per line | Pi-hole, AdGuard Home, UniFi, pfBlockerNG, Technitium |
| [`hosts.txt`](https://raw.githubusercontent.com/rennerdo30/dns-blocklist/lists/hosts.txt) | `0.0.0.0 domain` | hosts-file based blockers, dnsmasq `addn-hosts` |
| [`adblock.txt`](https://raw.githubusercontent.com/rennerdo30/dns-blocklist/lists/adblock.txt) | `\|\|domain^` (subdomains included) | AdGuard Home, AdGuard DNS, uBlock Origin |

Every list also has a `-lite` variant (`domains-lite.txt`, `hosts-lite.txt`, `adblock-lite.txt`)
of roughly 80k entries for devices with limited memory or list-size limits.
[`stats.json`](https://raw.githubusercontent.com/rennerdo30/dns-blocklist/lists/stats.json)
shows the entry counts and the status of every source.

**UniFi firewall:** when you use a list in a firewall rule, set the action to **Reject**, not
**Block**. Block silently drops packets, so apps wait for every blocked request to time out (the
Steam store, for example, stops loading). Reject refuses the connection immediately and pages load
normally.

The `lists` branch is force-pushed as a single commit on each update, so the repository does not
grow over time.

## Sources

See [`config/sources.json`](config/sources.json). Full list: all sources. Lite list: StevenBlack
Unified Hosts, Peter Lowe's list and AdAway.

From adblock-syntax lists (EasyList, EasyPrivacy, AdGuard DNS filter) only plain domain rules
(`||domain^`) are used; cosmetic rules and rules with paths or modifiers are ignored. Exception
rules (`@@||domain^`) are honoured.

## Safety checks

The build refuses to publish (the previous lists stay online) when:

- more than half of the sources fail to download,
- the merged list shrinks to less than half of the previous build, or
- any domain from [`config/canaries.txt`](config/canaries.txt) (google.com, github.com, …) ends up in the list.

## Customize

- `config/allowlist.txt` – domains that are never blocked
- `config/blocklist.txt` – extra domains that are always blocked
- `config/sources.json` – upstream lists (`"lite": true` adds a source to the lite variant)

Build locally (Python 3.10+, no dependencies):

```sh
python3 scripts/build.py --out-dir dist
```

## Check your DNS

`scripts/check.py` tests whether your DNS actually blocks the list. It resolves a random sample of
domains through the system resolver and compares the answers with an unfiltered resolver
(1.1.1.1 by default):

- **blocked** – sinkhole answer (`0.0.0.0`, `::`, `127.0.0.1`, block pages in reserved ranges such as UniFi's `203.0.113.250`) or NXDOMAIN although the domain exists
- **not blocked** – resolves to a real address
- **dead** – the domain no longer exists anywhere (not counted in the block rate)

```sh
python3 scripts/check.py                                  # 1000 random domains via system DNS
python3 scripts/check.py --server 192.168.1.1             # ask the router directly
python3 scripts/check.py --list domains-lite.txt --sample 0   # every domain of a local file
python3 scripts/check.py --block-ip 192.168.1.1           # router answers with a block-page IP
python3 scripts/check.py --fail-under 95 --json report.json
```

The block rate should be close to 100% once the list is active in your router. Output language
follows your locale (`--lang en|de`).

## Deutsch

Zusammengeführte DNS-Blockliste aus den bekannten Pi-hole-, AdGuard- und uBlock-Listen, die per
GitHub Actions alle 6 Stunden neu erstellt wird. Die oben genannten Raw-URLs aus dem Branch
`lists` können direkt als dynamische Liste im Router oder DNS-Server eingetragen werden.
Für Geräte mit begrenztem Speicher gibt es `-lite`-Varianten (ca. 80.000 Einträge).
In der UniFi-Firewall als Aktion **Reject** statt **Block** verwenden, sonst warten Apps (z. B. der
Steam-Store) auf Timeouts.
Mit `python3 scripts/check.py` lässt sich prüfen, ob dein DNS die Liste tatsächlich blockiert.

## License

GPL-3.0 (several upstream lists are GPL-3.0). Each upstream list keeps its own license; see
`config/sources.json`.
