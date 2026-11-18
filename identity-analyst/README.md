# Identity analyst (tables: auth, vpn, ldap, fw, proxy, host)

Team ID: `10`

## Files
- `identity_detections.py`: all 12 hunts. Reads `bearcorp.db` directly. Standard library only (no pandas).
- `findings.json`: 138 findings, passes `berkeley_hackathon_validate.py`.
- `findings_detail.csv`: same findings plus the hunt number and evidence.

## Run
```
python identity_detections.py --db dataset/bearcorp.db --team 10 --out findings.json
```
Takes under a minute.

## For the dashboard
```python
from identity_detections import run_detections, SETTINGS
rows = run_detections("dataset/bearcorp.db", {**SETTINGS, "vpn_min_up_down_ratio": 3})
```
Each row has: category, timestamp, host, user, process, hunt, evidence.

## Findings by hunt
| Hunt | Category | # |
|---|---|---|
| 1 SSO brute force (one outside IP vs one user, then success) | Credential abuse | 10 |
| 2 SSO spray bursts from 198.18.77.9, each ending in a success | Credential abuse | 10 |
| 3 ssh as `svc-` account, or as `admin-` at night | Credential abuse | 16 |
| 4 Kerberoasting (`/tmp/tgs.py`, then many service tickets) | Credential abuse | 10 |
| 5 Kerberos failures for accounts not in `users` | Reconnaissance | 3 |
| 6 LDAP wildcard sweeps (`uid=*`, `memberOf=*`, ...) | Reconnaissance | 8 |
| 7 Server port probing (`python3 scan.py --slow`, `masscan`) | Reconnaissance | 8 |
| 8 Repeated `threat-intel-block` denials | Command and control | 12 |
| 9 Python reverse shell to 198.18.9.13:4444 | Command and control | 1 |
| 10 VPN sessions uploading > 1.5x what they download | Data theft | 8 |
| 11 smbclient share copy, wmic hidden process, winrs/winexe as admin or with a hash, xfreerdp as admin without MFA, ssh `StrictHostKeyChecking=no` as admin | Lateral movement | 36 |
| 12 Payloads from untrusted sites, loader + stage2, fake `updates.nexusos-patch.com` | Malware delivery | 16 |

## Notes for teammates
- User = last LOGIN on that host at or before the event (same rule as dns-analyst). For outside-in events (SSO, VPN) with no workstation involved, host = the victim's assigned workstation and user = the victim.
- Timestamps: SSO hunts use the first failed login of the burst; Kerberoasting uses the first ticket request (about 5s after the `tgs.py` command); LDAP, probing, firewall and malware hunts use the first event per host.
- Overlap with dns-analyst: hunt 8 reports WS-9650, WS-1438, WS-7525, WS-5182 under Command and control, which dns-analyst also has. Keep one copy when merging if the scorer counts duplicates.
- Less certain, trim first if we are over a cap: hunt 11's 4 `ssh -o StrictHostKeyChecking=no` rows (ssh was not in the brief for lateral movement), hunt 7's 3 `masscan` rows (fast, not slow), hunt 9 (could be Host intrusion signs instead), hunt 10's frank116 (only 1.7x).
- Left out on purpose: 174 `tool-setup.exe` downloads from `staging-downloads.nexusos.com` (the real vendor's site, one per host, looks like a normal rollout).
- Not yet covered (leads from dns-analyst): Data theft over the web (`backup-agent` to `offsite-vault.net` etc.) and C2 from `miner_worker` / `invoice_viewer`.
