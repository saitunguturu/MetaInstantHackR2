"""Identity analyst detections for the Bearcorp threat hunt (brief hunts 1-7).

Reads bearcorp.db directly (tables: auth, vpn, ldap, fw, host, users, assets)
and writes findings.json plus findings_detail.csv. Standard library only.

Usage:
    python identity_detections.py --db dataset/bearcorp.db --team 10
    python identity_detections.py --db dataset/bearcorp.db --team 10 --out findings_identity.json

Thresholds live in SETTINGS so a dashboard can import run_detections(db, settings)
and re-run with different values.
"""
import argparse, csv, json, sqlite3
from collections import Counter
from datetime import datetime, timedelta

SETTINGS = {
    "mfa_min_fails": 10,              # H1: failed sso logins for one user...
    "mfa_window_min": 30,             # H1: ...within this many minutes, then a success
    "ldap_min_wildcards": 10,         # H2: wildcard LDAP searches per host
    "vpn_min_up_down_ratio": 1.5,     # H3: upload / download ratio
    "spray_gap_min": 10,              # H3: a quiet gap this long ends a spray burst
    "spray_min_users": 10,            # H3: distinct users tried in one burst
    "night_end_hour_utc": 6,          # H4: admin- ssh before this hour counts as night
    "kerberoast_window_s": 120,       # H5: ticket requests within this long after the python3 command
    "probe_min_targets": 10,          # H6: distinct server ip:port pairs probed by one program
    "probe_min_minutes": 10,          # H6: "slow" = probing spread over at least this long
    "travel_window_min": 60,          # H7: two VPN logins from different networks within this long
    "slow_spray_min_users": 20,       # H7: distinct users tried from one outside address
    "slow_spray_max_per_hour": 2.5,   # H7: average attempts per hour
    "slow_spray_min_days": 0.75,      # H7: spread over at least ~a day...
    "slow_spray_max_days": 4.5,       # H7: ...and at most ~four days
}

RECON_LDAP = ("(memberOf=*)", "(uid=*)", "(adminCount=1)", "(objectClass=user)",
              "(objectClass=computer)", "(servicePrincipalName=*)")
P = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
ISO = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
net16 = lambda ip: ".".join(ip.split(".")[:2])
OUTSIDE = "src NOT LIKE 'WS-%' AND src NOT LIKE 'LAB-%' AND src NOT LIKE '10.%'"


def run_detections(db, S=SETTINGS):
    con = sqlite3.connect(db)
    q = lambda sql, *a: con.execute(sql, a).fetchall()
    owner = dict(q("SELECT user, workstation FROM users"))
    F = []

    def user_at(host, ts):
        # last user to log in on that host at or before ts (same rule as dns-analyst)
        r = q("SELECT user FROM host WHERE host=? AND event='LOGIN' AND ts<=? ORDER BY ts DESC LIMIT 1", host, ts)
        return r[0][0] if r else None

    def host_for_ip(ip, ts):
        r = q("SELECT host FROM host WHERE event='IP_ASSIGNED' AND target=? AND ts<=? ORDER BY ts DESC LIMIT 1", ip, ts)
        return r[0][0] if r else None

    def add(cat, hunt, ts, host, process, evidence, user=None):
        F.append({"category": cat, "timestamp": ts, "host": host,
                  "user": user or user_at(host, ts), "process": process,
                  "hunt": hunt, "evidence": [evidence]})

    # H1 MFA fatigue: 10+ failed sso logins for one user within 30 minutes, then a success.
    # Reported at the first failure; host = the user's assigned workstation.
    win = timedelta(minutes=S["mfa_window_min"])
    fails = {}
    for ts, user, src, res in q("SELECT ts, user, src, result FROM auth WHERE service='sso' ORDER BY user, ts"):
        f = fails.setdefault(user, [])
        if res == "fail":
            f.append((ts, src)); continue
        # the fails must come from the address that then gets in, and the success must follow within the window
        recent = [x for x in f if x[1] == src and P(ts) - P(x[0]) <= win]
        if len(recent) >= S["mfa_min_fails"]:
            add("Credential abuse", 1, recent[0][0], owner[user], "sso",
                f"{len(recent)} sso fails from {recent[0][1]} in {S['mfa_window_min']} min, then success at {ts}", user)
        fails[user] = []

    # H2a LDAP wildcard sweeps (uid=*, memberOf=*, servicePrincipalName=* ...). Reported at the first search.
    marks = ",".join("?" * len(RECON_LDAP))
    for host, ts, n in q(f"""SELECT host, MIN(ts), SUM(filter LIKE '%=*)') FROM ldap
              WHERE filter IN ({marks}) GROUP BY host
              HAVING SUM(filter LIKE '%=*)') >= ? ORDER BY 2""", *RECON_LDAP, S["ldap_min_wildcards"]):
        user = q("SELECT user FROM ldap WHERE host=? AND ts=?", host, ts)[0][0]
        add("Reconnaissance", 2, ts, host, "ldapsearch", f"{n} wildcard LDAP searches", user)

    # H2b Repeated threat-intel-block denials; host/process from the NET_CONNECT at the same moment.
    for ts, src, dst, n in q("""SELECT MIN(ts), src_ip, dst_ip, COUNT(*) FROM fw WHERE rule='threat-intel-block'
                                GROUP BY src_ip ORDER BY 1"""):
        host, proc = q("SELECT host, process FROM host WHERE event='NET_CONNECT' AND ts=? AND target LIKE ?", ts, dst + ":%")[0]
        add("Command and control", 2, ts, host, proc, f"{n} threat-intel-block denials {src} -> {dst}")

    # H3a VPN sessions that upload far more than they download.
    for ts, user, src, up, down in q("SELECT ts, user, src_ip, bytes_up, bytes_down FROM vpn WHERE 1.0*bytes_up/bytes_down > ? ORDER BY ts",
                                     S["vpn_min_up_down_ratio"]):
        add("Data theft", 3, ts, owner[user], "vpn", f"VPN from {src}: {up/1e9:.2f} GB up vs {down/1e9:.2f} GB down", user)

    # H3b Password spraying in bursts from one outside address; each burst ends with one account getting in.
    # Reported for that account at the first failure of its burst.
    gap = timedelta(minutes=S["spray_gap_min"])
    burst, last = [], None
    def close(b):
        if b and b[-1][3] == "success" and len({r[2] for r in b}) >= S["spray_min_users"]:
            src, ts, user, _ = b[-1]
            add("Credential abuse", 3, b[0][1], owner[user], "sso",
                f"spray burst from {src}: {len(b)-1} users failed, then {user} got in at {ts}", user)
    for r in q(f"SELECT src, ts, user, result FROM auth WHERE service='sso' AND {OUTSIDE} ORDER BY src, ts"):
        t = P(r[1])
        if burst and (r[0] != burst[-1][0] or t - last > gap):
            close(burst); burst = []
        burst.append(r); last = t
    close(burst)

    # H4 ssh from a workstation as a service account, or as an admin account at night.
    for ts, host, cmd in q("""SELECT ts, host, target FROM host WHERE event='CMD' AND host LIKE 'WS-%'
                              AND (target LIKE 'ssh %svc-%' OR target LIKE 'ssh %admin-%') ORDER BY ts"""):
        if "svc-" in cmd or int(ts[11:13]) < S["night_end_hour_utc"]:
            add("Credential abuse", 4, ts, host, "bash", cmd)

    # H5a Kerberoasting: odd python3 command, then the logged-in user requests many service tickets in seconds.
    for ts, host, cmd in q("SELECT ts, host, target FROM host WHERE event='CMD' AND target LIKE 'python3 /tmp/tgs.py%' ORDER BY ts"):
        user = user_at(host, ts)
        end = ISO(P(ts) + timedelta(seconds=S["kerberoast_window_s"]))
        t = q("""SELECT MIN(ts), COUNT(DISTINCT target) FROM auth WHERE service='kerberos' AND target!='-'
                 AND user=? AND ts BETWEEN ? AND ?""", user, ts, end)[0]
        add("Credential abuse", 5, t[0], host, "kerberos", f"{t[1]} service tickets after `{cmd}` at {ts}", user)

    # H5b Kerberos failures for accounts that do not exist (user enumeration). One per source host.
    for src, ts, n in q("""SELECT src, MIN(ts), COUNT(DISTINCT user) FROM auth WHERE service='kerberos'
                           AND result='fail' AND user NOT IN (SELECT user FROM users) GROUP BY src ORDER BY 2"""):
        add("Reconnaissance", 5, ts, host_for_ip(src, ts), "kerberos", f"{n} unknown accounts tried from {src}")

    # H6a Lateral movement with attack signs; report the workstation's CMD row.
    lm = [("smbclient", "target LIKE 'smbclient%' AND target LIKE '%recurse%' AND target LIKE '%mget *%'"),
          ("wmic", "target LIKE 'wmic%' AND target LIKE '%process call create%'"),
          ("winrs", "target LIKE 'winrs%' AND target LIKE '%admin-%'"),
          ("winexe", "target LIKE 'winexe%' AND (target LIKE '%admin-%' OR target LIKE '%aad3b435%')")]
    for proc, cond in lm:
        for ts, host, cmd in q(f"SELECT ts, host, target FROM host WHERE event='CMD' AND {cond} ORDER BY ts"):
            add("Lateral movement", 6, ts, host, proc, cmd[:120])
    # xfreerdp: only when the matching rdp sign-in is an admin- account without MFA.
    for ats, auser, src, srv in q("""SELECT ts, user, src, target FROM auth WHERE service='rdp'
                                     AND user LIKE 'admin-%' AND mfa='no' AND result='success' ORDER BY ts"""):
        ws = host_for_ip(src, ats)
        ip = q("SELECT ip FROM assets WHERE upper(hostname)=upper(?)", srv)[0][0]
        ts, cmd = q("""SELECT ts, target FROM host WHERE host=? AND event='CMD' AND target LIKE 'xfreerdp%'
                       AND target LIKE ? AND ts<=? ORDER BY ts DESC LIMIT 1""", ws, f"%/v:{ip} %", ats)[0]
        add("Lateral movement", 6, ts, ws, "xfreerdp", f"{cmd} (rdp sign-in as {auser}, no MFA)")

    # H6b Slow probing of many server ports; the program comes from NET_CONNECT rows.
    for host, proc, ts, end, n in q("""SELECT host, process, MIN(ts), MAX(ts), COUNT(DISTINCT target)
                                       FROM host WHERE event='NET_CONNECT' AND target LIKE '10.2.%' GROUP BY host, process
                                       HAVING COUNT(DISTINCT target) >= ? ORDER BY 3""", S["probe_min_targets"]):
        mins = (P(end) - P(ts)).total_seconds() / 60
        if mins >= S["probe_min_minutes"]:
            add("Reconnaissance", 6, ts, host, proc, f"{n} server ip:port pairs probed by {proc} over {mins:.0f} min")

    # H7a Impossible travel: VPN logins from two different networks within an hour; use the first login.
    tw = timedelta(minutes=S["travel_window_min"])
    prev = {}
    for ts, user, src in q("SELECT ts, user, src_ip FROM vpn ORDER BY user, ts"):
        p = prev.get(user)
        if p and net16(p[1]) != net16(src) and P(ts) - P(p[0]) <= tw:
            add("Credential abuse", 7, p[0], owner[user], "vpn", f"VPN from {p[1]} then {src} at {ts}", user)
        prev[user] = (ts, src)

    # H7b Slow spraying: one outside address, a few sso tries an hour or fewer over 1-4 days, before one works.
    # Reported for the account that got in, at the address's first attempt.
    for src, first, last, n, users, succ in q(f"""SELECT src, MIN(ts), MAX(ts), COUNT(*), COUNT(DISTINCT user),
                                               SUM(result='success') FROM auth WHERE service='sso' AND {OUTSIDE}
                                               GROUP BY src HAVING SUM(result='success')=1 AND COUNT(DISTINCT user)>=?""",
                                              S["slow_spray_min_users"]):
        days = (P(last) - P(first)).total_seconds() / 86400
        user, sts = q("SELECT user, ts FROM auth WHERE service='sso' AND src=? AND result='success'", src)[0]
        if sts == last and S["slow_spray_min_days"] <= days <= S["slow_spray_max_days"] \
                and n / (days * 24) <= S["slow_spray_max_per_hour"]:
            add("Credential abuse", 7, first, owner[user], "sso",
                f"slow spray from {src}: {n-1} fails over {days:.1f} days, then {user} got in at {sts}", user)

    con.close()
    seen, out = set(), []
    for f in F:
        k = (f["category"], f["host"], f["timestamp"])
        if k not in seen:
            seen.add(k); out.append(f)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--team", required=True)
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args()
    rows = run_detections(args.db)
    with open(args.out.replace(".json", "_detail.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, ["category", "timestamp", "host", "user", "process", "hunt", "evidence"])
        w.writeheader(); w.writerows(rows)
    json.dump({"team_id": args.team, "findings": [{k: v for k, v in r.items() if k != "hunt"} for r in rows]},
              open(args.out, "w"), indent=1)
    for (h, c), n in sorted(Counter((r["hunt"], r["category"]) for r in rows).items()):
        print(f"{h:>3} {c:<22} {n}")
    print(f"{len(rows)} findings -> {args.out}")
