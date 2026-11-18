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
| Hunt | What we found | Submission Category | # |
|---|---|---|---|
| 1. MFA fatigue | 10 users: 13-27 sso fails from one 198.18.91.x address within 30 min, then that address gets in. Time = first fail. | Credential abuse | 10 |
| 2. Directory dumps and blocked connections | 8 hosts running LDAP wildcard sweeps (`uid=*`, `memberOf=*`, `servicePrincipalName=*`). 12 hosts denied 8 times each by `threat-intel-block` (process `sync_helper`), one finding per host at its first denial. | Reconnaissance (8), Command and control (12) | 20 |
| 3. VPN uploads and password spraying | 8 VPN sessions uploading > 1.5x what they download. 198.18.77.9 spraying sso in 10 bursts of 13-35 users, each ending with one account getting in; time = first fail of the burst. | Data theft (8), Credential abuse (10) | 18 |
| 4. Service accounts and admins over SSH | 10 workstation `ssh svc-...@` commands and 6 `ssh admin-...@` commands between 00:00-06:00 UTC; logged-in user, process `bash`. | Credential abuse | 16 |
| 5. Kerberos ticket bursts and fake accounts | 10 users requesting 8-16 service tickets within seconds of `python3 /tmp/tgs.py --spns all`. 3 workstations failing Kerberos for ~20 accounts each that are not in `users`. Process `kerberos`. | Credential abuse (10), Reconnaissance (3) | 13 |
| 6. Remote access to new servers | 32 CMD rows: smbclient `recurse; mget *` (10), wmic `process call create` (6), winrs as admin- (5), winexe with a password hash (1), xfreerdp with an admin- rdp sign-in without MFA (10). 5 workstations slowly probing 10 server ports over ~45 min (`python3 scan.py --slow`). | Lateral movement (32), Reconnaissance (5) | 37 |
| 7. Impossible travel and slow spraying | 10 users on VPN from 203.0.113.x then 198.18.88.x within 40-53 min; time = first login. 8 outside addresses (198.18.77.11-.18) trying one sso login per user, < 2.5/hour over 0.8-4.3 days, before one works; time = first attempt. | Credential abuse (18) | 18 |
| **Total** | | | **132** |

## How fields are chosen
- User = last LOGIN on that host at or before the event (same rule as dns-analyst).
- For outside-in events (sso, vpn) there is no workstation involved, so host = the victim's assigned workstation and user = the victim.
- Timestamps follow the brief: hunt 1 and both spray hunts use the first failed login; impossible travel uses the first VPN login; firewall uses each host's first denial; Kerberoasting uses the first ticket request (about 5 s after the python3 command); LDAP and probing use the first event per host.

## Notes for teammates
- Left out on purpose: 6 users with 10+ sso fails from a home address (203.0.113.x) that never got in; their later "success" is a normal workstation login hours later. Also `masscan` scans (fast, not slow), daytime `ssh -o StrictHostKeyChecking=no admin-...` (not in the brief's lateral movement list), and the python reverse shell on WS-9116 and malware downloads (endpoint/web, not identity).
- Weakest rows if we need to trim: slow spray from 198.18.77.15 (0.8 days, just under "one to four"), VPN upload for frank116 (1.7x vs 4-17x for the rest), LDAP sweep on WS-0283 (16 wildcards vs 22-33).
