
#!/usr/bin/env python3
"""Bearcorp Role 2: Web Analyst.

Usage:
python3 role2_web.py --db dataset/bearcorp.db --team-id 966201019600420

Outputs:
  findings.json
  web_review.csv

Python standard library only.
"""

import argparse
import bisect
import collections
import csv
import datetime
import ipaddress
import json
import math
import os
import re
import sqlite3
import statistics
import sys

P = argparse.ArgumentParser()
P.add_argument("--db", default="dataset/bearcorp.db")
P.add_argument("--team-id", required=True)
P.add_argument("--out", default="findings.json")
P.add_argument("--review", default="web_review.csv")
P.add_argument("--min-upload-mb", type=float, default=8)
P.add_argument("--min-query-length", type=int, default=150)
P.add_argument("--min-checkins", type=int, default=8)
A = P.parse_args()

if A.team_id.strip().lower() in (
    "your-team-id", "your-team-name", ""
):
    sys.exit("Set your actual team ID.")

if not os.path.exists(A.db):
    sys.exit("Database missing: " + A.db)

con = sqlite3.connect(
    "file:" + os.path.abspath(A.db) + "?mode=ro",
    uri=True
)
con.row_factory = sqlite3.Row


def stamp(s):
    try:
        return datetime.datetime.fromisoformat(
            str(s).replace("Z", "+00:00")
        ).timestamp()
    except (ValueError, TypeError):
        return None


def timestamp(s):
    t = stamp(s)
    if t is None:
        return str(s)
    return datetime.datetime.fromtimestamp(
        t, datetime.timezone.utc
    ).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def entropy(s):
    if not s:
        return 0
    cc = collections.Counter(s)
    return -sum(
        (n / len(s)) * math.log2(n / len(s))
        for n in cc.values()
    )


def is_ip(s):
    if not s:
        return False
    if not (s[0].isdigit() or ":" in s):
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def suspicious_ua(v):
    x = (v or "").strip().lower()
    if not x or x in ("-", "none", "null"):
        return True
    return any(k in x for k in (
        "python-requests", "curl/", "wget/",
        "powershell", "go-http-client",
        "libwww-perl", "aiohttp", "urllib",
        "httpclient", "java/", "scrapy",
        "okhttp", "bot/"
    ))


def long_encoded_query(s):
    q = s.split("?", 1)[-1] if "?" in s else ""
    if len(q) < A.min_query_length:
        return False
    values = [
        x.split("=", 1)[-1]
        for x in q.split("&")
    ]
    return any(
        len(v) > 100
        and entropy(v) > 4.0
        and len(set(v)) >= 15
        for v in values
    )


print("Loading exact URL IOCs...", flush=True)

iocs = set()
for row in con.execute(
    "SELECT value FROM iocs WHERE lower(type)='url'"
):
    iocs.add(str(row[0]).strip())

domain_ips = collections.defaultdict(set)
domain_requests = collections.Counter()

upload = []
badurl = []
encoded = []
odd = []

series = collections.defaultdict(list)
series_count = collections.Counter()

MAX_GROUPS = 20000

print("Scanning proxy once...", flush=True)

c = 0

for r in con.execute(
    "SELECT ts,src_ip,method,domain,url,status,"
    "bytes_out,bytes_in,user_agent FROM proxy"
):
    c += 1

    if c % 1000000 == 0:
        print(
            "  proxy rows:",
            format(c, ","),
            flush=True
        )

    ts, ip, method, domain, url, status, bout, bin_, ua = r

    ip = str(ip or "")
    domain = str(domain or "").lower().rstrip(".")
    url = str(url or "")
    method = str(method or "").upper()
    bout = int(bout or 0)
    bin_ = int(bin_ or 0)

    domain_requests[domain] += 1

    ips = domain_ips[domain]
    if len(ips) < 40:
        ips.add(ip)

    raw = (
        str(ts), ip, domain, url,
        method, bout, bin_, str(ua or "")
    )

    # Hunt 1: large uploads
    if (
        method in ("POST", "PUT")
        and bout >= A.min_upload_mb * 1048576
    ):
        upload.append(raw)

    # Hunt 2: exact known-bad URL
    if ("http://" + domain + url) in iocs:
        badurl.append(raw)

    # Hunt 3: encoded data in URL
    if long_encoded_query(url):
        encoded.append(raw)

    # Hunt 4: suspicious user-agent or IP destination
    if suspicious_ua(ua) or is_ip(domain):
        if len(odd) < 20000:
            odd.append(raw)

    # Time-series information for hunts 5, 6, and 7
    if bout < 100000 and bin_ < 200000 and len(url) < 180:
        key = (
            ip, domain, method,
            url.split("?", 1)[0]
        )

        if key in series or len(series) < MAX_GROUPS:
            series_count[key] += 1
            v = series[key]

            if len(v) < 20:
                v.append((
                    stamp(ts),
                    str(ts),
                    url,
                    bout,
                    bin_,
                    str(ua or "")
                ))

print(
    "Proxy rows scanned:",
    format(c, ","),
    "; distinct domains:",
    len(domain_ips),
    flush=True
)

# ----------------------------------------
# DETECTION CANDIDATES
# ----------------------------------------

candidates = []


def add(kind, cat, r, detail, rank=1):
    candidates.append({
        "hunt": kind,
        "category": cat,
        "ts": r[0],
        "ip": r[1],
        "domain": r[2],
        "url": r[3],
        "method": r[4],
        "bytes_out": r[5],
        "detail": detail,
        "rank": rank
    })


# Hunt 2: known-bad URLs
for r in badurl:
    add(
        "2 known-bad URL",
        "Known-bad indicators",
        r,
        "exact URL IOC",
        5
    )


# Hunt 1: large uploads to rare destinations
for r in upload:
    rare = len(domain_ips[r[2]]) <= 8

    if rare and r[5] >= A.min_upload_mb * 1048576:
        add(
            "1 rare upload",
            "Data theft",
            r,
            f"{r[5]/1048576:.1f} MiB uploaded; "
            f"{len(domain_ips[r[2]])} source IPs",
            3
        )


# Hunt 3: encoded query parameters
for r in encoded:
    if len(domain_ips[r[2]]) <= 12:
        add(
            "3 encoded query",
            "Data theft",
            r,
            "long high-entropy query parameter",
            3
        )


# Hunt 4: unusual web traffic
odd_groups = collections.defaultdict(list)

for r in odd:
    if (
        len(domain_ips[r[2]]) <= 8
        and r[5] < 100000
        and (suspicious_ua(r[7]) or is_ip(r[2]))
    ):
        key = (r[1], r[2], r[7])
        v = odd_groups[key]

        if len(v) < 100:
            v.append(r)

for grp in odd_groups.values():
    if len(grp) >= 4:
        add(
            "4 odd web traffic",
            "Command and control",
            min(grp, key=lambda r: r[0]),
            f"{len(grp)} unusual requests",
            2
        )


# Hunt 5: periodic check-ins
for key, events in series.items():
    ip, domain, method, path = key

    if (
        len(events) < A.min_checkins
        or len(domain_ips[domain]) > 12
    ):
        continue

    valid = sorted(
        (x for x in events if x[0] is not None),
        key=lambda x: x[0]
    )

    if len(valid) < A.min_checkins:
        continue

    times = [v[0] for v in valid]

    gaps = [
        b - a
        for a, b in zip(times, times[1:])
        if 60 <= b - a <= 21600
    ]

    if len(gaps) < A.min_checkins - 2:
        continue

    interval = statistics.median(gaps)

    if interval < 120 or interval > 10800:
        continue

    close = sum(
        abs(g - interval) <= max(18, interval * .09)
        for g in gaps
    )

    if close / len(gaps) < .80:
        continue

    r = (
        valid[0][1],
        ip,
        domain,
        valid[0][2],
        method,
        valid[0][3],
        valid[0][4],
        valid[0][5]
    )

    if long_encoded_query(r[3]):
        continue

    add(
        "5 regular check-ins",
        "Command and control",
        r,
        f"{len(valid)} requests every "
        f"{interval/60:.1f} minutes",
        3
    )


# Hunt 6: rotating check-ins
by_domain = collections.defaultdict(list)

for key, events in series.items():
    ip, domain, method, path = key

    if not 3 <= len(domain_ips[domain]) <= 15:
        continue

    for v in events[:10]:
        if v[0] is not None and v[3] < 100000:
            by_domain[(domain, method, path)].append((
                v[0], v[1], ip, v[2],
                method, v[3], v[4], v[5]
            ))

for (domain, method, path), events in by_domain.items():
    if len(events) < 5:
        continue

    seq = sorted(events)

    transitions = [
        (b[0] - a[0], a, b)
        for a, b in zip(seq, seq[1:])
        if a[2] != b[2]
    ]

    hourly = [
        x for x in transitions
        if 2700 <= x[0] <= 4500
    ]

    if (
        len(hourly) < 4
        or len({a[2] for _, a, _ in hourly}) < 3
    ):
        continue

    seen = set()

    for _, a, b in hourly:
        if a[2] in seen:
            continue

        seen.add(a[2])

        r = (
            a[1], a[2], domain, a[3],
            a[4], a[5], a[6], a[7]
        )

        add(
            "6 rotating check-ins",
            "Command and control",
            r,
            f"{len(hourly)} hourly transitions "
            "between clients",
            3
        )


# Hunt 7: suspicious cloud storage activity
cloud = re.compile(
    r"(drive|dropbox|onedrive|sharepoint|"
    r"box\.com|storage|cloud|files)",
    re.I
)

for key, events in series.items():
    ip, domain, method, path = key

    if not cloud.search(domain):
        continue

    if len(domain_ips[domain]) < 12:
        continue

    if (
        "/status" not in path.lower()
        and not (
            method in ("GET", "PUT")
            and (
                "sync" in path.lower()
                or "chunk" in path.lower()
            )
        )
    ):
        continue

    valid = sorted(
        (x for x in events if x[0] is not None),
        key=lambda x: x[0]
    )

    if len(valid) < 5:
        continue

    gaps = [
        b[0] - a[0]
        for a, b in zip(valid, valid[1:])
    ]

    matched = sum(
        2700 <= g <= 4500 or 6500 <= g <= 7900
        for g in gaps
    )

    if (
        matched < 4
        or matched / max(1, len(gaps)) < .75
    ):
        continue

    v = valid[0]

    r = (
        v[1], ip, domain,
        v[2], method, v[3], v[4], v[5]
    )

    add(
        "7 cloud check-ins",
        "Command and control",
        r,
        f"{len(valid)} periodic cloud requests",
        3
    )

print(
    "Raw candidates:",
    len(candidates),
    flush=True
)

# ----------------------------------------
# HOST ATTRIBUTION
# ----------------------------------------

wanted_domains = {
    x["domain"] for x in candidates
}

wanted_ips = {
    x["domain"]
    for x in candidates
    if is_ip(x["domain"])
}

dns_by_domain = collections.defaultdict(list)
conn_by_ip = collections.defaultdict(list)
ip_history = collections.defaultdict(list)
login_history = collections.defaultdict(list)

print(
    "Scanning host sensor for attribution...",
    flush=True
)

for e in con.execute(
    "SELECT ts,host,event,user,process,target "
    "FROM host WHERE event IN "
    "('DNS_QUERY','NET_CONNECT','IP_ASSIGNED','LOGIN')"
):
    ts, host, ev, user, process, target = e

    t = stamp(ts)

    if t is None:
        continue

    target = str(target or "").lower().rstrip(".")

    if ev == "DNS_QUERY" and target in wanted_domains:
        dns_by_domain[target].append((
            t, str(host), str(process)
        ))

    elif ev == "NET_CONNECT":
        destination = target.rsplit(":", 1)[0]

        if destination in wanted_ips:
            conn_by_ip[destination].append((
                t, str(host), str(process)
            ))

    elif ev == "IP_ASSIGNED":
        ip_history[target].append((
            t, str(host)
        ))

    elif (
        ev == "LOGIN"
        and user
        and str(user).strip().lower()
        not in ("", "-", "none")
    ):
        login_history[str(host)].append((
            t, str(user)
        ))

for d in (
    ip_history,
    login_history,
    dns_by_domain,
    conn_by_ip
):
    for v in d.values():
        v.sort()

nat_ips = {
    r[0]
    for r in con.execute(
        "SELECT DISTINCT nat_ip FROM nat"
    )
}

valid_hosts = {
    r[0]
    for r in con.execute(
        "SELECT hostname FROM assets"
    )
}

valid_users = {
    str(r[0]).lower()
    for r in con.execute(
        "SELECT user FROM users"
    )
}


def active_ip_hosts(ip, t):
    xs = ip_history.get(ip, [])

    if not xs:
        return set()

    idx = bisect.bisect_right(
        xs, (t, chr(0x10ffff))
    ) - 1

    if idx < 0:
        return set()

    return {xs[idx][1]}


def resolve(row):
    t = stamp(row["ts"])
    domain = row["domain"]
    ip = row["ip"]

    if t is None:
        return None, "bad timestamp"

    if is_ip(domain):
        observations = conn_by_ip.get(domain, [])
    else:
        observations = dns_by_domain.get(domain, [])

    nearby = [
        e for e in observations
        if abs(e[0] - t) <= 7200
    ]

    if not nearby:
        return None, "no matching endpoint event"

    near = min(
        abs(e[0] - t) for e in nearby
    )

    nearrows = [
        e for e in nearby
        if abs(e[0] - t) <= max(180, near + 60)
    ]

    if ip not in nat_ips:
        plausible = active_ip_hosts(ip, t)

        if plausible:
            nearrows = [
                e for e in nearrows
                if e[1] in plausible
            ]

    distinct = {
        (e[1], e[2]) for e in nearrows
    }

    if len(distinct) != 1:
        return None, "ambiguous host/process"

    host, process = next(iter(distinct))

    if host not in valid_hosts:
        return None, "unknown host"

    logins = login_history.get(host, [])

    pos = bisect.bisect_right(
        logins, (t, chr(0x10ffff))
    ) - 1

    if pos < 0:
        return None, "no login found"

    user = logins[pos][1]

    if user.lower() not in valid_users:
        return None, "unknown user"

    return (host, user, process), ""


# ----------------------------------------
# GENERATE FINDINGS
# ----------------------------------------

out = []
review = []
dedup = set()

print("Resolving candidates...", flush=True)

for x in sorted(
    candidates,
    key=lambda x: (-x["rank"], x["ts"])
):
    resolved, reason = resolve(x)
    verdict = "unresolved"

    if resolved:
        host, user, process = resolved

        bucket = int(stamp(x["ts"]) // 1200)

        key = (
            x["category"],
            host,
            user.lower(),
            process.lower(),
            x["domain"],
            x["hunt"],
            bucket
        )

        if key not in dedup:
            dedup.add(key)

            out.append({
                "category": x["category"],
                "timestamp": timestamp(x["ts"]),
                "host": host,
                "user": user,
                "process": process
            })

            verdict = "included"
        else:
            verdict = "duplicate episode"

    review.append({
        "hunt": x["hunt"],
        "verdict": verdict,
        "reason": reason,
        "timestamp": timestamp(x["ts"]),
        "source_ip": x["ip"],
        "domain": x["domain"],
        "url": x["url"][:220],
        "bytes_out": x["bytes_out"],
        "detail": x["detail"],
        "host": resolved[0] if resolved else "",
        "user": resolved[1] if resolved else "",
        "process": resolved[2] if resolved else ""
    })


# Deduplicate identical scoring fields
unique = {
    tuple(
        f[k] for k in (
            "category",
            "timestamp",
            "host",
            "user",
            "process"
        )
    ): f
    for f in out
}

out = list(unique.values())

# Write findings.json
with open(A.out, "w") as f:
    json.dump(
        {
            "team_id": A.team_id,
            "findings": out
        },
        f,
        indent=2
    )

# Write review CSV
with open(A.review, "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "hunt",
            "verdict",
            "reason",
            "timestamp",
            "source_ip",
            "domain",
            "url",
            "bytes_out",
            "detail",
            "host",
            "user",
            "process"
        ]
    )
    writer.writeheader()
    writer.writerows(review)

print(
    "Wrote",
    A.out,
    "with",
    len(out),
    "findings; review",
    A.review,
    flush=True
)

print(
    "Counts by hunt:",
    dict(
        collections.Counter(
            r["hunt"]
            for r in review
            if r["verdict"] == "included"
        )
    )
)

print(
    "IMPORTANT: Review web_review.csv "
    "for false positives before submission."
)

con.close()
