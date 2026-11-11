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

## Deutsch

Zusammengeführte DNS-Blockliste aus den bekannten Pi-hole-, AdGuard- und uBlock-Listen, die per
GitHub Actions alle 6 Stunden neu erstellt wird. Die oben genannten Raw-URLs aus dem Branch
`lists` können direkt als dynamische Liste im Router oder DNS-Server eingetragen werden.
Für Geräte mit begrenztem Speicher gibt es `-lite`-Varianten (ca. 80.000 Einträge).

## License

GPL-3.0 (several upstream lists are GPL-3.0). Each upstream list keeps its own license; see
`config/sources.json`.
