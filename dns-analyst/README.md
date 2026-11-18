# DNS analyst (tables: dns, iocs)

Team ID: `10`

## Files
- `dns_detections.py`: all 7 DNS hunts. Reads `bearcorp.db` directly. Needs pandas.
- `findings.json`: 167 findings, passes `berkeley_hackathon_validate.py`.
- `findings_detail.csv`: same findings plus the hunt number and evidence (domain, lookup count).

## Run
```
python dns_detections.py --db dataset/bearcorp.db --team 10 --out findings.json
```
Takes a few minutes (loads 5.3M dns rows + 4.5M host DNS_QUERY rows).

## For the dashboard
```python
from dns_detections import load, run_detections, SETTINGS
data = load("dataset/bearcorp.db")          # slow, do once
df = run_detections(data, {**SETTINGS, "dga_min_nx_names": 30})   # fast to re-run with new settings
```
`df` columns: category, timestamp, host, user, process, hunt, evidence.

## Findings by hunt
| Hunt | Category | # |
|---|---|---|
| 1 Known-bad domains | Known-bad indicators | 12 |
| 2 Lookalike domains | Deceptive domains | 10 |
| 3 DNS exfil (TXT/AAAA) | Data theft | 21 |
| 4 Commands in DNS | Command and control | 17 |
| 5 Made-up domains | Reconnaissance | 27 |
| 6 New/shifting domains + beacons | Command and control | 65 |
| 7 Spread-out subdomain sweep | Reconnaissance | 15 |

## Notes for teammates
- Attacker implant process is `sync_helper`; attacker servers are in 198.18.0.0/15.
- User = last LOGIN on that host at or before the event (as in the brief's example).
- Leads outside DNS:
  - Endpoint (hunt 7, Malware delivery): `updates.nexusos-patch.com` (fake update site, process `updater`), `freewarevault.net`, `crackarchive.net`, `driversoft-portal.net`, `freevault-downloads.net`, `installer-bundle.net`.
  - Web (Data theft): `backup-agent` to `offsite-vault.net`, `dead-drop-share.net`, `docvault-store.net`, `cloudsync-warehouse.net`; `sync_helper` to `docarchive-store.net`, `nightly-cdn-pull.net`.
  - Web (hunt 4, C2): `miner_worker` to `hashhaven.net`; `invoice_viewer` to `config-sync-svc.net`, `healthcheck-svc.net`, `telemetry-sync-svc.net`.
- Left out on purpose (normal traffic): `threatstop.net`/`shieldops.net` security lookups, the `dirb` scan on SRV-02, DKIM/SPF TXT records.
