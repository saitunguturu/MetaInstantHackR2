"""DNS analyst detections for the Bearcorp threat hunt (hunts 1-7).

Reads bearcorp.db directly (tables: dns, iocs, host, users) and writes findings.json.

Usage:
    python dns_detections.py --db dataset/bearcorp.db --team 10
    python dns_detections.py --db dataset/bearcorp.db --team 10 --out findings_dns.json

Thresholds live in SETTINGS so a dashboard can import run_detections(db, settings)
and re-run with different values.
"""
import argparse, bisect, json, sqlite3
import pandas as pd

SETTINGS = {
    "lookalike_max_edit_distance": 2,     # H2: edits away from "bearcorp"
    "exfil_min_unique_names": 50,         # H3: unique TXT/AAAA names per source per domain
    "exfil_max_sources": 50,              # H3: ignore domains used company-wide
    "c2_long_name_len": 60,               # H4: query length counted as "very long"
    "c2_min_long_names": 50,              # H4: long unique names under one domain
    "c2_txt_min_answer_len": 40,          # H4: TXT answer length that looks encoded
    "c2_txt_min_repeats": 10,             # H4: repeated TXT lookups of one name
    "c2_big_answer_len": 200,             # H4: oversized answer length
    "rare_domain_max_lookups": 6,         # H5/H6: domains seen this rarely count as "never-seen"
    "dga_min_nx_names": 15,               # H5: NXDOMAIN made-up names per source
    "dga_min_rows_per_host": 10,          # H5: drop hosts that only match a few reused names
    "subdomain_guess_min": 20,            # H5: NXDOMAIN subdomains of one domain from one source
    "newdomain_burst_min": 20,            # H6: new resolving domains per source
    "newdomain_tlds": ["club", "online", "site", "store"],
    "fastflux_min_ips": 20,               # H6: distinct A answers for one name
    "fastflux_max_sources": 10,
    "beacon_domains": ["statuscheck-svc.net", "healthmon-svc.net", "watchdog-svc.net",
                       "devicemetrics.net", "fleetmetrics.net", "fleetwatch.net",
                       "nightly-metrics.net", "offhours-backup.net", "timesheet-cloud.net",
                       "shiftplanner-cloud.net", "shadowmetrics.net"],
    "beacon_process": "sync_helper",
    "sweep_min_names": 5,                 # H7: per host, a few names...
    "sweep_max_names": 19,                # ...but not a lot
    "sweep_min_hosts": 3,                 # H7: several hosts on the same domain
    "ignore_domains": ["threatstop.net", "shieldops.net"],  # security tooling lookups
}

REG = r"([^.]+\.[^.]+)$"


def load(db):
    con = sqlite3.connect(db)
    dns = pd.read_sql("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns", con)
    hq = pd.read_sql("SELECT ts, host, process, target FROM host WHERE event = 'DNS_QUERY'", con)
    lg = pd.read_sql("SELECT ts, host, user FROM host WHERE event = 'LOGIN' ORDER BY ts", con)
    iocs = pd.read_sql("SELECT type, value FROM iocs", con)
    users = pd.read_sql("SELECT user, workstation FROM users", con)
    con.close()
    dns["q"] = dns["query"].str.lower()
    dns["reg"] = dns.q.str.extract(REG)[0]
    dns["qlen"] = dns.q.str.len()
    dns["alen"] = dns.answer.fillna("").str.len()
    hq["t"] = hq.target.str.lower()
    hq["reg"] = hq.t.str.extract(REG)[0]
    logins = {h: (list(g.ts), list(g.user)) for h, g in lg.groupby("host")}
    owner = dict(zip(users.workstation, users.user))
    return dns, hq, iocs, logins, owner


def lev(a, b):
    p = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        c = [i]
        for j, cb in enumerate(b, 1):
            c.append(min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (ca != cb)))
        p = c
    return p[-1]


def run_detections(data, S=SETTINGS):
    dns, hq, iocs, logins, owner = data
    F = []

    def user_at(host, ts):
        # last user to log in on that host at or before ts (same as the brief's worked example)
        if host in logins:
            tss, us = logins[host]
            i = bisect.bisect_right(tss, ts)
            if i:
                return us[i - 1]
        return owner.get(host, "none")

    def add(cat, hunt, rows, note):
        # one finding per host+process, timed at its first lookup
        for (host, proc), g in rows.groupby(["host", "process"]):
            ts = g.ts.min()
            F.append(dict(category=cat, timestamp=ts, host=host, user=user_at(host, ts),
                          process=proc, hunt=hunt,
                          evidence=[f"{note}: {g.t.iloc[0]} ({len(g)} lookups)"]))

    # rare domains: the "never-seen" pool used by hunts 5-7
    cnt = dns.groupby("reg").size()
    tail = dns[dns.reg.isin(cnt[cnt <= S["rare_domain_max_lookups"]].index)].copy()
    tail["tld"] = tail.reg.str.split(".").str[-1]
    rare_regs = set(tail.reg)

    # H1 known-bad domains
    bad = set(iocs[iocs.type == "domain"].value.str.lower())
    add("Known-bad indicators", 1, hq[hq.t.isin(bad)], "IOC domain")

    # H2 lookalike company domains
    def lookalike(q):
        if q == "bearcorp.com" or q.endswith(".bearcorp.com"):
            return False
        if "xn--" in q:
            return True
        parts = q.split(".")
        if len(parts) < 2:
            return False
        lab = parts[-2]
        return ("bearcorp" in lab or "bear-corp" in lab) or \
            (abs(len(lab) - 8) <= S["lookalike_max_edit_distance"] and
             lev(lab, "bearcorp") <= S["lookalike_max_edit_distance"])
    looks = {q for q in dns.q.unique() if lookalike(q)}
    add("Deceptive domains", 2, hq[hq.t.isin(looks)], "lookalike domain")

    # H3 data smuggled out through DNS (many unique TXT/AAAA names under one domain)
    tx = dns[dns.qtype.isin(["TXT", "AAAA"])]
    x = tx.groupby(["reg", "src_ip"]).agg(n=("q", "size"), uq=("q", "nunique")).reset_index()
    x = x[(x.uq >= S["exfil_min_unique_names"]) & (x.uq / x.n > 0.9)]
    x = x[x.groupby("reg").src_ip.transform("nunique") < S["exfil_max_sources"]]
    for reg in x.reg.unique():
        qs = set(tx[(tx.reg == reg) & tx.src_ip.isin(set(x[x.reg == reg].src_ip))].q)
        add("Data theft", 3, hq[hq.t.isin(qs)], "DNS exfil")

    # H4 commands hidden in DNS
    a = dns[(dns.qtype == "A") & (dns.qlen >= S["c2_long_name_len"])].groupby("reg").q.nunique()
    for reg in a[a >= S["c2_min_long_names"]].index:
        if reg not in S["ignore_domains"]:
            add("Command and control", 4, hq[hq.reg == reg], "long A-record names")
    t = dns[(dns.qtype == "TXT") & (dns.alen >= S["c2_txt_min_answer_len"])].groupby(["q", "src_ip"]).size()
    t = t[t >= S["c2_txt_min_repeats"]].reset_index()
    t = t[t.groupby("q").src_ip.transform("nunique") <= 10]   # skip org-wide DKIM/SPF
    for q in t.q.unique():
        add("Command and control", 4, hq[hq.t == q], "repeated TXT w/ encoded answer")
    big = dns[dns.alen >= S["c2_big_answer_len"]].groupby("reg").src_ip.nunique()
    for reg in big[big <= 10].index:
        add("Command and control", 4, hq[hq.reg == reg], "oversized DNS answers")

    # H5 made-up domains: NXDOMAIN bursts / slow DGA, and subdomain guessing
    nx = tail[tail.rcode == "NXDOMAIN"]
    c = nx.groupby("src_ip").q.nunique()
    qs = set(nx[nx.src_ip.isin(c[c >= S["dga_min_nx_names"]].index)].q)
    rows = hq[hq.t.isin(qs)]
    per = rows.groupby("host").size()
    add("Reconnaissance", 5, rows[rows.host.isin(per[per >= S["dga_min_rows_per_host"]].index)],
        "NXDOMAIN made-up names")
    sub = dns[dns.rcode == "NXDOMAIN"].groupby(["reg", "src_ip"]).q.nunique()
    sub = sub[sub >= S["subdomain_guess_min"]].reset_index()
    for reg in set(sub.reg) - rare_regs:
        r = hq[(hq.reg == reg) & (hq.process == "net_scan")]
        per = r.groupby("host").size()
        add("Reconnaissance", 5, r[r.host.isin(per[per >= S["subdomain_guess_min"]].index)],
            "subdomain guessing")

    # H6 new and shifting domains
    nb = tail[(tail.rcode == "NOERROR") & tail.tld.isin(S["newdomain_tlds"])]
    c = nb.groupby("src_ip").q.nunique()
    qs = set(nb[nb.src_ip.isin(c[c >= S["newdomain_burst_min"]].index)].q)
    add("Command and control", 6, hq[hq.t.isin(qs)], "burst of new resolving domains")
    ok = dns[(dns.rcode == "NOERROR") & (dns.qtype == "A")].groupby("q").agg(
        ans=("answer", "nunique"), srcs=("src_ip", "nunique"))
    for q in ok[(ok.ans >= S["fastflux_min_ips"]) & (ok.srcs <= S["fastflux_max_sources"])].index:
        add("Command and control", 6, hq[hq.t == q], "fast-flux domain")
    ioc_ips = set(dns[dns.q.isin(bad)].answer)
    sib = set(dns[dns.answer.isin(ioc_ips)].q) - bad
    add("Command and control", 6, hq[hq.t.isin(sib)], "shares IP with IOC domain")
    add("Command and control", 6,
        hq[hq.reg.isin(S["beacon_domains"]) & (hq.process == S["beacon_process"])], "periodic beacon")

    # H7 spread-out subdomain sweep
    s = dns[dns.rcode == "NXDOMAIN"].groupby(["reg", "src_ip"]).q.nunique().reset_index()
    s = s[(s.q >= S["sweep_min_names"]) & (s.q <= S["sweep_max_names"])]
    g = s.groupby("reg").src_ip.nunique()
    regs = [r for r in g[g >= S["sweep_min_hosts"]].index if r not in rare_regs]
    add("Reconnaissance", 7, hq[hq.reg.isin(regs) & (hq.process == "net_scan")],
        "distributed subdomain sweep")

    df = pd.DataFrame(F)
    return df.drop_duplicates(["category", "host", "timestamp"]) if len(df) else df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--team", required=True)
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args()
    df = run_detections(load(args.db))
    print(df.groupby(["hunt", "category"]).size().to_string())
    df.to_csv(args.out.replace(".json", "_detail.csv"), index=False)
    json.dump({"team_id": args.team,
               "findings": df.drop(columns=["hunt"]).to_dict("records")},
              open(args.out, "w"), indent=1)
    print(f"{len(df)} findings -> {args.out}")
