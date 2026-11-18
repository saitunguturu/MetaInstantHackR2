# Identity analyst (tables: auth, vpn, ldap, fw, host)

Team ID: `10`

## Files
- `identity_detections.py`: all 7 identity hunts from the brief. Reads `bearcorp.db` directly. Standard library only (no pandas).
- `findings.json`: 132 findings, passes `berkeley_hackathon_validate.py`.
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
| Hunt | What we found | Category | # |
|---|---|---|---|
| 1 MFA fatigue | 10-27 sso fails from one 198.18.91.x address in under 30 min, then that address gets in | Credential abuse | 10 |
| 2 Directory dumps | LDAP wildcard sweeps (`uid=*`, `memberOf=*`, `servicePrincipalName=*`) | Reconnaissance | 8 |
| 2 Blocked connections | Repeated `threat-intel-block` denials to 198.18.70.x (process `sync_helper`) | Command and control | 12 |
| 3 VPN uploads | Sessions uploading > 1.5x what they download | Data theft | 8 |
| 3 Password spraying | 198.18.77.9: 10 bursts of 13-35 users, each ending with one account getting in | Credential abuse | 10 |
| 4 SSH as svc-/admin- | `ssh svc-...@` from workstations, and `ssh admin-...@` between 00:00-06:00 UTC | Credential abuse | 16 |
| 5 Kerberos ticket bursts | `python3 /tmp/tgs.py --spns all`, then 8-16 service tickets within seconds | Credential abuse | 10 |
| 5 Fake accounts | Kerberos fails for ~20 accounts each not in `users`, from 3 workstations | Reconnaissance | 3 |
| 6 Remote access | smbclient `recurse; mget *`, wmic `process call create`, winrs/winexe as admin- or with a hash, xfreerdp + rdp sign-in as admin- without MFA | Lateral movement | 32 |
| 6 Slow port probing | `python3 scan.py --slow`: 10 server ports over ~45 min | Reconnaissance | 5 |
| 7 Impossible travel | VPN from 203.0.113.x then 198.18.88.x within 40-53 min | Credential abuse | 10 |
| 7 Slow spraying | 198.18.77.11-.18: one try per user, < 2.5/hour over 0.8-4.3 days, ending in one success | Credential abuse | 8 |

## How fields are chosen
- User = last LOGIN on that host at or before the event (same rule as dns-analyst).
- For outside-in events (sso, vpn) there is no workstation involved, so host = the victim's assigned workstation and user = the victim.
- Timestamps follow the brief: hunt 1 and both spray hunts use the first failed login; impossible travel uses the first VPN login; firewall uses each host's first denial; Kerberoasting uses the first ticket request (about 5 s after the python3 command); LDAP and probing use the first event per host.

## Notes for teammates
- Left out on purpose: 6 users with 10+ sso fails from a home address (203.0.113.x) that never got in; their later "success" is a normal workstation login hours later. Also `masscan` scans (fast, not slow), daytime `ssh -o StrictHostKeyChecking=no admin-...` (not in the brief's lateral movement list), and the python reverse shell on WS-9116 and malware downloads (endpoint/web, not identity).
- Weakest rows if we need to trim: slow spray from 198.18.77.15 (0.8 days, just under "one to four"), VPN upload for frank116 (1.7x vs 4-17x for the rest), LDAP sweep on WS-0283 (16 wildcards vs 22-33).
