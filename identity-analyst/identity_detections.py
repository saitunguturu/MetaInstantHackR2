"""Identity analyst detections for the Bearcorp threat hunt (hunts 1-12).

Reads bearcorp.db directly (tables: auth, vpn, ldap, fw, proxy, host, users, assets)
and writes findings.json plus findings_detail.csv. Standard library only.

Usage:
    python identity_detections.py --db dataset/bearcorp.db --team 10
    python identity_detections.py --db dataset/bearcorp.db --team 10 --out findings_identity.json

Thresholds live in SETTINGS so a dashboard can import run_detections(db, settings)
and re-run with different values.
"""
import argparse, csv, json, sqlite3
from datetime import datetime, timedelta

SETTINGS = {
    "brute_min_fails": 10,            # H1: SSO failures from one address against one user
    "spray_gap_minutes": 10,          # H2: a quiet gap this long ends a spray burst
    "spray_min_users": 10,            # H2: distinct users tried in one burst
    "night_end_hour_utc": 6,          # H3: admin- ssh before this hour counts as night
    "kerberoast_window_s": 120,       # H4: ticket requests within this long after tgs.py
    "ldap_min_wildcards": 10,         # H6: wildcard LDAP searches per host
    "probe_min_ports": 10,            # H7: distinct server ip:port pairs probed by one program
    "vpn_min_up_down_ratio": 1.5,     # H10: upload / download ratio
    "trusted_vendor_domain": "nexusos.com",   # H12: real update vendor (its own sites are ignored)
    "payload_exts": [".exe", ".dll", ".scr", ".hta"],
}

RECON_LDAP = ("(memberOf=*)", "(uid=*)", "(adminCount=1)", "(objectClass=user)",
              "(objectClass=computer)", "(servicePrincipalName=*)")
P = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")


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

    # H1 SSO brute force: one outside address, one user, many fails, then a success.
    # Reported at the first failure; host = the victim's assigned workstation.
    for src, user, nf, first_fail, succ in q("""
        SELECT src, MIN(user), SUM(result='fail'), MIN(CASE WHEN result='fail' THEN ts END),
               MAX(CASE WHEN result='success' THEN ts END)
        FROM auth WHERE service='sso' AND src NOT LIKE 'WS-%' AND src NOT LIKE 'LAB-%'
        GROUP BY src HAVING COUNT(DISTINCT user)=1""") :
        if succ and nf >= S["brute_min_fails"] and succ > first_fail:
            add("Credential abuse", 1, first_fail, owner[user], "sso",
                f"{nf} SSO fails from {src} then success at {succ}", user)

    # H2 SSO spray: one outside address tries many users in bursts; each burst ends with a success.
    # Reported for the account that got in, at the burst's first failure.
    gap = timedelta(minutes=S["spray_gap_minutes"])
    rows = q("""SELECT src, ts, user, result FROM auth WHERE service='sso'
                AND src NOT LIKE 'WS-%' AND src NOT LIKE 'LAB-%' ORDER BY src, ts""")
    burst, last = [], None
    def close(b):
        if b and b[-1][3] == "success" and len({r[2] for r in b}) >= S["spray_min_users"]:
            src, ts, user, _ = b[-1]
            add("Credential abuse", 2, b[0][1], owner[user], "sso",
                f"spray from {src}: {len(b)-1} users failed, then {user} got in at {ts}", user)
    for r in rows:
        t = P(r[1])
        if burst and (r[0] != burst[-1][0] or t - last > gap):
            close(burst); burst = []
        burst.append(r); last = t
    close(burst)

    # H3 ssh from a workstation as a service account, or as an admin account at night.
    for ts, host, cmd in q("""SELECT ts, host, target FROM host WHERE event='CMD'
                              AND (target LIKE 'ssh %svc-%' OR target LIKE 'ssh %admin-%')
                              AND target NOT LIKE 'ssh -o StrictHostKeyChecking=no%' ORDER BY ts"""):
        if "svc-" in cmd or int(ts[11:13]) < S["night_end_hour_utc"]:
            add("Credential abuse", 3, ts, host, "bash", cmd)

    # H4 Kerberoasting: tgs.py runs, then the logged-in user requests many service tickets in seconds.
    for ts, host, cmd in q("SELECT ts, host, target FROM host WHERE event='CMD' AND target LIKE 'python3 /tmp/tgs.py%' ORDER BY ts"):
        user = user_at(host, ts)
        end = (P(ts) + timedelta(seconds=S["kerberoast_window_s"])).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        t = q("""SELECT MIN(ts), COUNT(DISTINCT target) FROM auth WHERE service='kerberos' AND target!='-'
                 AND user=? AND ts BETWEEN ? AND ?""", user, ts, end)[0]
        add("Credential abuse", 4, t[0], host, "kerberos", f"{t[1]} service tickets after `{cmd}` at {ts}", user)

    # H5 Kerberos failures for accounts that do not exist (user enumeration). One per source host.
    for src, ts, n in q("""SELECT src, MIN(ts), COUNT(DISTINCT user) FROM auth WHERE service='kerberos'
                           AND result='fail' AND user NOT IN (SELECT user FROM users) GROUP BY src ORDER BY 2"""):
        add("Reconnaissance", 5, ts, host_for_ip(src, ts), "kerberos", f"{n} unknown accounts tried from {src}")

    # H6 LDAP wildcard sweeps (uid=*, memberOf=*, servicePrincipalName=* ...). Reported at the first search.
    marks = ",".join("?" * len(RECON_LDAP))
    for host, ts, n in q(f"""SELECT host, MIN(ts), SUM(filter LIKE '%=*)') FROM ldap
              WHERE filter IN ({marks}) GROUP BY host
              HAVING SUM(filter LIKE '%=*)') >= ? ORDER BY 2""", *RECON_LDAP, S["ldap_min_wildcards"]):
        user = q("SELECT user FROM ldap WHERE host=? AND ts=?", host, ts)[0][0]
        add("Reconnaissance", 6, ts, host, "ldapsearch", f"{n} wildcard LDAP searches", user)

    # H7 Port probing of servers; the probing program comes from NET_CONNECT rows.
    for host, proc, ts, n in q("""SELECT host, process, MIN(ts), COUNT(DISTINCT target)
                                  FROM host WHERE event='NET_CONNECT' AND target LIKE '10.2.%' GROUP BY host, process
                                  HAVING COUNT(DISTINCT target) >= ? ORDER BY 3""", S["probe_min_ports"]):
        add("Reconnaissance", 7, ts, host, proc, f"{n} server ip:port pairs probed by {proc}")

    # H8 Repeated threat-intel-block denials; host/process from the NET_CONNECT at the same moment.
    for ts, src, dst, n in q("""SELECT MIN(ts), src_ip, dst_ip, COUNT(*) FROM fw WHERE rule='threat-intel-block'
                                GROUP BY src_ip ORDER BY 1"""):
        host, proc = q("SELECT host, process FROM host WHERE event='NET_CONNECT' AND ts=? AND target LIKE ?", ts, dst + ":%")[0]
        add("Command and control", 8, ts, host, proc, f"{n} threat-intel-block denials {src} -> {dst}")

    # H9 Python reverse shell.
    for ts, host, cmd in q("SELECT ts, host, target FROM host WHERE event='CMD' AND target LIKE 'python3 -c%socket%connect%'"):
        add("Command and control", 9, ts, host, "bash", cmd[:120])

    # H10 VPN sessions that upload far more than they download.
    for ts, user, src, up, down in q("SELECT ts, user, src_ip, bytes_up, bytes_down FROM vpn WHERE 1.0*bytes_up/bytes_down > ? ORDER BY ts",
                                     S["vpn_min_up_down_ratio"]):
        add("Data theft", 10, ts, owner[user], "vpn", f"VPN from {src}: {up/1e9:.2f} GB up vs {down/1e9:.2f} GB down", user)

    # H11 Lateral movement with attack signs.
    lm = [("smbclient", "target LIKE 'smbclient%' AND target LIKE '%recurse%' AND target LIKE '%mget *%'"),
          ("wmic", "target LIKE 'wmic%' AND target LIKE '%process call create%'"),
          ("winrs", "target LIKE 'winrs%' AND target LIKE '%admin-%'"),
          ("winexe", "target LIKE 'winexe%' AND (target LIKE '%admin-%' OR target LIKE '%aad3b435%')"),
          ("bash", "target LIKE 'ssh -o StrictHostKeyChecking=no admin-%'")]
    for proc, cond in lm:
        for ts, host, cmd in q(f"SELECT ts, host, target FROM host WHERE event='CMD' AND {cond} ORDER BY ts"):
            add("Lateral movement", 11, ts, host, proc, cmd[:120])
    # xfreerdp: only when the matching rdp sign-in is an admin- account without MFA.
    for ats, auser, src, srv in q("""SELECT ts, user, src, target FROM auth WHERE service='rdp'
                                     AND user LIKE 'admin-%' AND mfa='no' AND result='success' ORDER BY ts"""):
        ws = host_for_ip(src, ats)
        ip = q("SELECT ip FROM assets WHERE upper(hostname)=upper(?)", srv)[0][0]
        ts, cmd = q("""SELECT ts, target FROM host WHERE host=? AND event='CMD' AND target LIKE 'xfreerdp%'
                       AND target LIKE ? AND ts<=? ORDER BY ts DESC LIMIT 1""", ws, f"%/v:{ip} %", ats)[0]
        add("Lateral movement", 11, ts, ws, "xfreerdp", f"{cmd} (rdp sign-in as {auser}, no MFA)")

    # H12 Malware delivery: payloads from untrusted sites, loader + second stage, fake update site.
    vend = S["trusted_vendor_domain"]
    ext = " OR ".join(f"url LIKE '%{e}'" for e in S["payload_exts"])
    bad = {d for (d,) in q(f"SELECT DISTINCT domain FROM proxy WHERE ({ext}) AND domain NOT LIKE ?", "%." + vend)}
    bad |= {d for (d,) in q("SELECT DISTINCT domain FROM proxy WHERE domain LIKE ? AND domain NOT LIKE ?",
                            "%" + vend.split(".")[0] + "%", "%." + vend)}
    marks = ",".join("?" * len(bad))
    for src, dom, ts, urls, n in q(f"""SELECT src_ip, domain, MIN(ts), GROUP_CONCAT(DISTINCT url), COUNT(*) FROM proxy
                                       WHERE domain IN ({marks}) GROUP BY src_ip, domain ORDER BY 3""", *sorted(bad)):
        host, proc = q("SELECT host, process FROM host WHERE event='DNS_QUERY' AND target=? AND ts=?", dom, ts)[0]
        add("Malware delivery", 12, ts, host, proc, f"{dom}{urls.split(',')[0]} ({n} requests; files: {urls})")

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
    from collections import Counter
    for (h, c), n in sorted(Counter((r["hunt"], r["category"]) for r in rows).items()):
        print(f"{h:>3} {c:<22} {n}")
    print(f"{len(rows)} findings -> {args.out}")
