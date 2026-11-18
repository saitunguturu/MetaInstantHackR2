#!/usr/bin/env python3
"""Read-only Bearcorp endpoint hunts. Python standard library only.

Run: python3 endpoint_detect.py --config endpoint_config.json
Dashboard API: run_detection(database_path, configuration) -> report dictionary.
Findings have exactly the five submission fields. Evidence stays in a sidecar.
The implementation never executes commands found in logs.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import urlsplit

FIELDS = ("category", "timestamp", "host", "user", "process")
INTRUSION = "Host intrusion signs"
MALWARE = "Malware delivery"
THEFT = "Data theft"
HUNT_NAMES = {
    1: "Persistence and cleanup", 2: "Hands-on-keyboard",
    3: "Temp-folder programs and scanners", 4: "Credential theft and USB exfiltration",
    5: "Downloads piped into shells", 6: "Unsigned programs and unattended activity",
    7: "Risky downloads",
}
INTERNAL = tuple(ipaddress.ip_network(x) for x in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10"))


def seconds(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def external(target):
    """The fixture uses 198.18/15 and documentation ranges as outside IPs.

    ipaddress.is_global/is_private would incorrectly suppress those fixture IPs.
    """
    try:
        address = ipaddress.ip_address(target.rsplit(":", 1)[0].strip("[]"))
    except ValueError:
        return False
    return not address.is_multicast and not any(address in n for n in INTERNAL)


def signature(target):
    return dict(re.findall(r"(parent|hash|signed)=([^\s]+)", target))


def rows(con, query, args=()):
    for row in con.execute(query, args):
        yield dict(row)


class SessionIndex:
    """As-of host session state; never consult a future login or workstation owner.

    Latest active login wins for concurrent sessions. A logout removes only its
    matching user, so an older remote session cannot log out another user.
    Row IDs resolve same-millisecond transitions for host events.
    """
    def __init__(self, events):
        grouped = defaultdict(list)
        for event in events:
            grouped[event["host"]].append(event)
        self.keys, self.states, self.sources = {}, {}, {}
        for host, history in grouped.items():
            history.sort(key=lambda r: (r["ts"], r["rowid"]))
            active = {}
            keys, states, sources = [], [], []
            for event in history:
                user = event["user"]
                if event["event"] == "LOGIN":
                    active[user] = event
                elif user in {"-", "none", ""}:
                    active.clear()
                else:
                    active.pop(user, None)
                current = max(active.values(), key=lambda r: (r["ts"], r["rowid"]), default=None)
                keys.append((event["ts"], event["rowid"]))
                states.append(current["user"] if current else "none")
                sources.append(current or event)
            self.keys[host], self.states[host], self.sources[host] = keys, states, sources

    def at(self, host, ts, rowid=10**18):
        i = bisect_right(self.keys.get(host, []), (ts, rowid)) - 1
        return self.states[host][i] if i >= 0 else "none"

    def evidence(self, event):
        host = event["host"]
        i = bisect_right(self.keys.get(host, []), (event["ts"], event.get("rowid", 10**18))) - 1
        return self.sources[host][i] if i >= 0 else None


class Findings:
    def __init__(self, sessions):
        self.sessions = sessions
        self.records = []
        self.exact = {}
        self.review = []
        self.suppressed = Counter()

    def add(self, hunt, rule, category, event, evidence=(), confidence="high"):
        if not event.get("process") or event["process"] == "-":
            self.hold(hunt, rule, event, "No observed process; no process will be invented")
            return
        finding = dict(zip(FIELDS, (category, event["ts"], event["host"],
            self.sessions.at(event["host"], event["ts"], event.get("rowid", 10**18)), event["process"])))
        key = tuple(finding.values())
        if key in self.exact:
            self.suppressed["exact_duplicate_finding"] += 1
            return
        record = {"finding": finding, "hunt": hunt, "rule": rule, "confidence": confidence,
                  "source": {"table": "host", **event},
                  "session_evidence": self.sessions.evidence(event), "supporting_events": list(evidence)}
        self.records.append(record)
        self.exact[key] = record

    def hold(self, hunt, rule, event, reason):
        self.review.append({"hunt": hunt, "rule": rule, "event": event, "reason": reason})


def shell_url(command):
    match = re.search(r"https?://[^\s'\"|;]+", command)
    return match.group() if match else ""


def command_match(event, cfg):
    """Independent command actions; do not coalesce different commands in a session."""
    cmd, process = event["target"], event["process"]
    low = cmd.lower()
    if ("authorized_keys" in low and re.search(r">|\b(?:cp|tee|install)\b", low)) or (
        re.search(r"(?:crontab|/etc/cron)", low) and re.search(r"echo|>>|@reboot|crontab\s+(?:-(?:\s|$)|/)", low)
    ) or re.search(r"(?:^|[;&]\s*)(?:sudo\s+)?useradd\b", low) or (
        ".bashrc" in low and re.search(r">|\btee\b", low)
    ) or re.search(r"history\s+-[a-z]*c|unset\s+histfile", low) or (
        "/var/log/" in low and re.search(r"\b(?:rm|shred|truncate)\s", low)
    ):
        return 1, "persistence_or_cleanup", INTRUSION
    encoded = re.search(r"\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:/bin/)?(?:ba)?sh\b", low)
    reverse = "/dev/tcp/" in low or bool(re.search(r"\b(?:nc|ncat|netcat)\b.*\s-[a-z]*e\s+/(?:bin|usr/bin)/(?:ba)?sh", low))
    reverse |= all(token in low for token in ("socket", ".connect(", "dup2", "subprocess"))
    if reverse:
        return 2, "reverse_shell", INTRUSION
    if encoded and re.search(r"[A-Za-z0-9+/=]{%d,}" % cfg["encoded_min_characters"], cmd):
        return 2, "encoded_shell_execution", INTRUSION
    if re.search(r"\bfind\s+/\s.*-perm\s+(?:-4000|/4000|4000|-[u+]s)", low):
        return 2, "suid_privilege_discovery", INTRUSION
    if "169.254.169.254" in low and re.search(r"\b(?:curl|wget)\b", low):
        return 2, "cloud_metadata_credentials", INTRUSION
    if re.search(r"\b(?:nmap|masscan)\b", low):
        if event["host"] not in cfg["approved_scanner_hosts"] and (
            re.search(r"\d+\.\d+\.\d+\.\d+/\d+", low) or re.search(r"\s-p(?:-|1-\d{3,})", low)
        ):
            return 3, "network_scanner", "Reconnaissance"
    if re.search(r"\bping\b", low):
        size, count = re.search(r"\s-s\s+(\d+)", low), re.search(r"\s-c\s+(\d+)", low)
        dest = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", low)
        if size and count and dest and int(size[1]) >= cfg["ping_min_payload_bytes"] and int(count[1]) >= cfg["ping_min_count"] and external(dest[-1] + ":0"):
            return 3, "large_packet_ping_tunnel", "Command and control"
    if not any(re.search(p, cmd) for p in cfg["temp_install_allow_patterns"] + cfg["cross_role_command_patterns"]):
        # A path in an argument or a cron line alone is not execution.
        if re.search(r"(?:^|[;&|]\s*|\bnohup\s+)(?:/tmp/|/dev/shm/)[^\s;&|]+", cmd) or (
            re.search(r"\b(?:python[23]?|perl|ruby|(?:ba)?sh)\s+(?:/tmp/|/dev/shm/)[^\s]+", cmd)
        ):
            return 3, "temporary_program_execution", MALWARE
    # Only file-content reads/copies; ls/stat of /etc/shadow is metadata.
    for part in re.split(r"\s*(?:&&|\|\||[;|])\s*", low):
        read = re.match(r"(?:sudo\s+)?(?:cat|cp|head|tail|less|more|strings|sqlite3)\s+", part)
        secret = re.search(r"(?:\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)(?![\w.]|\.pub)|/etc/(?:shadow-?|gshadow)(?!\w)|\.aws/credentials|\.azure/accesstokens\.json|gcloud/credentials\.db|chrome/[^;]*(?:cookies|login\\? data))", part)
        if read and secret:
            return 4, "secret_file_access", INTRUSION
    if re.search(r"\b(?:curl|wget)\b.*\|\s*(?:/bin/)?(?:ba)?sh\b", low):
        if shell_url(cmd) not in cfg["trusted_shell_urls"]:
            plugin = process not in {"bash", "sh", "zsh", "dash"}
            return 5, "plugin_download_shell" if plugin else "download_shell", INTRUSION if plugin else MALWARE
    if re.search(r"\bssh\b.*stricthostkeychecking\s*=\s*no", low):
        return 6, "ssh_host_key_checks_disabled", INTRUSION
    return None


def command_hunts(con, cfg, findings):
    stats, variants, examples = Counter(), Counter(), defaultdict(list)
    archives, ips = [], []
    last_command = {}
    enabled = set(cfg["enabled_hunts"])
    # Single table scan: inventory process variants, examine all CMDs, record IP history.
    for event in rows(con, "SELECT rowid,* FROM host WHERE event IN ('CMD','PROC_START','IP_ASSIGNED')"):
        stats[event["event"]] += 1
        if event["event"] == "IP_ASSIGNED":
            ips.append(event)
            continue
        if event["event"] == "PROC_START":
            key = (event["process"], event["target"])
            variants[key] += 1
            if variants[key] <= cfg["rare_variant_max_starts"]:
                examples[key].append(event)
            else:
                examples.pop(key, None)
            continue
        cmd = event["target"]
        if re.match(r"(?:tar|zip|7z)\s", cmd):
            archives.append(event)
        match = command_match(event, cfg)
        if match and match[0] in enabled:
            hunt, rule, category = match
            key = (hunt, rule, event["host"], event["process"],
                   findings.sessions.at(event["host"], event["ts"], event["rowid"]), cmd)
            previous = last_command.get(key)
            now = seconds(event["ts"])
            if previous is not None and 0 <= now - previous <= cfg["command_repeat_seconds"]:
                findings.suppressed["repeated_same_command"] += 1
            else:
                findings.add(hunt, rule, category, event)
                last_command[key] = now
        elif shell_url(cmd) in cfg["trusted_shell_urls"]:
            findings.suppressed["trusted_training_shell_setup"] += 1
        elif any(re.search(p, cmd) for p in cfg["temp_install_allow_patterns"]):
            findings.suppressed["normal_temporary_package_install"] += 1
        elif any(re.search(p, cmd) for p in cfg["cross_role_command_patterns"]):
            findings.hold(3, "cross_role_ticket_dump", event, "Credential-abuse evidence for Identity Analyst; avoid wrong-category submission")
        elif cmd == "cat ~/.ssh/id_rsa.pub":
            findings.suppressed["normal_public_key_read"] += 1
        elif cmd == "cat /etc/passwd" or cmd.startswith("ls -l /etc/shadow"):
            findings.suppressed["public_or_metadata_password_file_access"] += 1
        elif re.search(r"\b(?:nmap|masscan)\b", cmd) and event["host"] in cfg["approved_scanner_hosts"]:
            findings.suppressed["approved_scanner_host"] += 1
    return stats, variants, examples, archives, ips


def archive_hunt(con, cfg, findings, archives):
    copies = defaultdict(list)
    usb_inventory = Counter()
    for event in rows(con, "SELECT rowid,* FROM usb"):
        usb_inventory[event["action"]] += 1
        if event["action"] == "copy":
            copies[event["host"]].append(event)
    for archive in archives:
        when = seconds(archive["ts"])
        user = findings.sessions.at(archive["host"], archive["ts"], archive["rowid"])
        linked = [c for c in copies[archive["host"]]
                  if 0 <= seconds(c["ts"]) - when <= cfg["usb_archive_window_seconds"]
                  and c["mb"] >= cfg["usb_min_mb"]
                  and (c["user"] in {"-", "none", user})]
        if linked:
            findings.add(4, "archive_then_large_usb_copy", THEFT, archive,
                         [{"table": "usb", **c} for c in sorted(linked, key=lambda r: r["ts"])])
        elif re.search(r"\s/tmp/\.[^\s]+\s+/home/\s+/etc/", archive["target"]):
            if cfg["include_hidden_sensitive_staging"]:
                findings.add(4, "hidden_archive_of_home_and_system_secrets", THEFT, archive,
                             confidence="medium")
            else:
                findings.hold(4, "hidden_sensitive_archive_without_transfer", archive,
                              "Sensitive staging is observed, but no qualifying transfer corroborates Data theft; excluded by precision policy")
        else:
            findings.suppressed["archive_without_theft_corroboration"] += 1
    return dict(usb_inventory)


def network_hunt(con, cfg, findings, variants, examples, progress):
    totals, baselines = Counter(), {}
    for (process, target), count in variants.items():
        totals[process] += count
        info = signature(target)
        if info.get("signed") == "yes" and count >= cfg["common_process_min_starts"]:
            if process not in baselines or count > baselines[process][1]:
                baselines[process] = (info.get("hash"), count)
    anomalies = defaultdict(list)
    for key, events in examples.items():
        process, target = key
        info = signature(target)
        unusual_hash = process in baselines and info.get("hash") != baselines[process][0] and variants[key] / totals[process] <= cfg["rare_hash_max_fraction"]
        if info.get("signed") == "no" or unusual_hash:
            for event in events:
                anomalies[(event["host"], process)].append(event)
    for events in anomalies.values():
        events.sort(key=lambda e: (e["ts"], e["rowid"]))
    first_connections = {}
    unattended, destination_hosts, all_start_boundaries = defaultdict(list), defaultdict(set), defaultdict(list)
    stats = Counter()
    candidates = set(cfg["unattended_processes"])
    progress("Scanning network activity for process anomalies and unattended sessions")
    for event in rows(con, "SELECT rowid,* FROM host WHERE event IN ('NET_CONNECT','PROC_START')"):
        key = (event["host"], event["process"])
        if event["event"] == "PROC_START":
            if key in anomalies:
                all_start_boundaries[key].append((event["ts"], event["rowid"]))
            continue
        stats["NET_CONNECT"] += 1
        if not (key in anomalies or event["process"] in candidates):
            continue
        if not external(event["target"]):
            continue
        if key in anomalies:
            for start in anomalies[key]:
                delta = seconds(event["ts"]) - seconds(start["ts"])
                if 0 <= delta <= cfg["process_connect_window_seconds"]:
                    old = first_connections.get(start["rowid"])
                    if old is None or (event["ts"], event["rowid"]) < (old["ts"], old["rowid"]):
                        first_connections[start["rowid"]] = event
        if event["process"] in candidates:
            destination_hosts[event["target"]].add(event["host"])
            if findings.sessions.at(event["host"], event["ts"], event["rowid"]) == "none":
                unattended[(event["host"], event["process"], event["target"])].append(event)
    for key, starts in anomalies.items():
        boundaries = sorted(all_start_boundaries[key])
        for start in starts:
            first = first_connections.get(start["rowid"])
            if first:
                # If a signed instance starts before this connection, attribution is ambiguous.
                i = bisect_right(boundaries, (start["ts"], start["rowid"]))
                if i < len(boundaries) and boundaries[i] <= (first["ts"], first["rowid"]):
                    findings.hold(6, "process_instance_ambiguity", start, "A newer process start precedes the external connection")
                    continue
                findings.add(6, "anomalous_program_first_external_connection", MALWARE, first,
                             [{"table": "host", **start}, {"baseline": baselines.get(key[1]), "variant_count": variants[(key[1], start["target"])]}])
            else:
                findings.hold(6, "unsigned_program_without_external_connection", start,
                              "Unsigned alone is insufficient; no external connection in the attribution window")
    for (host, process, destination), events in unattended.items():
        if len(destination_hosts[destination]) > cfg["unattended_destination_max_hosts"]:
            findings.suppressed["unattended_common_destination"] += len(events)
            continue
        for group in campaigns(events, cfg["unattended_campaign_gap_seconds"]):
            if len(group) >= cfg["unattended_min_events"] and seconds(group[-1]["ts"]) - seconds(group[0]["ts"]) >= cfg["unattended_min_span_seconds"]:
                findings.add(6, "repeated_unattended_external_activity", INTRUSION, group[0],
                             [{"table": "host", **e} for e in group[1:]] +
                             [{"event_count": len(group), "destination_host_count": len(destination_hosts[destination])}])
            else:
                findings.suppressed["weak_unattended_activity"] += len(group)
    return dict(stats), [{"process": p, "target": t, "count": n} for (p, t), n in variants.most_common()]


def campaigns(events, gap_seconds):
    group = []
    for event in sorted(events, key=lambda e: (e["ts"], e["rowid"])):
        if group and seconds(event["ts"]) - seconds(group[-1]["ts"]) > gap_seconds:
            yield group
            group = []
        group.append(event)
    if group:
        yield group


class AddressIndex:
    def __init__(self, ips, nat):
        self.host_events, self.ip_hosts, self.nat = defaultdict(list), defaultdict(set), defaultdict(list)
        for event in ips:
            self.host_events[event["host"]].append((event["ts"], event["target"]))
            self.ip_hosts[event["target"]].add(event["host"])
        for events in self.host_events.values():
            events.sort()
        for row in nat:
            self.nat[row["nat_ip"]].append(row)

    def ip_at(self, host, ts):
        events = self.host_events.get(host, [])
        i = bisect_right(events, (ts, chr(0x10ffff))) - 1
        return events[i][1] if i >= 0 else None

    def matches(self, host, proxy):
        internal = self.ip_at(host, proxy["ts"])
        if not internal:
            return False
        if internal == proxy["src_ip"]:
            return True
        return any(n["internal_ip"] == internal and n["start"] <= proxy["ts"] < n["end"]
                   for n in self.nat.get(proxy["src_ip"], []))


def trusted_domain(domain, suffixes):
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in suffixes)


def lookalike_update(domain, cfg):
    if domain in cfg["trusted_update_domains"] or trusted_domain(domain, cfg["trusted_download_suffixes"]):
        return False
    if "updat" not in domain:
        return False
    parts = domain.split(".")
    brand_label = parts[-2] if len(parts) >= 2 else domain
    return any(brand in brand_label or SequenceMatcher(None, brand_label, brand).ratio() >= 0.75
               for brand in cfg["update_brand_tokens"])


def download_hunt(con, cfg, findings, ips, progress):
    progress("Reading only executable and update proxy candidates; correlating host/IP/NAT history")
    address = AddressIndex(ips, list(rows(con, "SELECT * FROM nat")))
    # Broad discovery avoids hard-coding attacker domains. Shared proxy table is read-only.
    trusted_placeholders = ",".join("?" for _ in cfg["trusted_update_domains"])
    query = f"""SELECT rowid,* FROM proxy WHERE
       lower(url) LIKE '%.exe%' OR lower(url) LIKE '%.dll%' OR
       lower(url) LIKE '%.scr%' OR lower(url) LIKE '%.hta%' OR
       (lower(domain) LIKE '%updat%' AND domain NOT IN ({trusted_placeholders}))"""
    candidates, inventory = [], Counter()
    for event in rows(con, query, cfg["trusted_update_domains"]):
        inventory[(event["domain"], event["url"].split("?")[0])] += 1
        if trusted_domain(event["domain"], cfg["trusted_download_suffixes"]):
            findings.suppressed["trusted_vendor_download"] += 1
            continue
        path = urlsplit(event["url"]).path.lower()
        executable = bool(re.search(r"\.(?:exe|dll|scr|hta)$", path))
        update = lookalike_update(event["domain"], cfg)
        if event["method"] == "GET" and 200 <= event["status"] < 300 and (
            (executable and event["bytes_in"] >= cfg["download_min_bytes"]) or update
        ):
            candidates.append(event)
    by_domain = defaultdict(list)
    for event in candidates:
        by_domain[event["domain"]].append(event)
    matched_groups = defaultdict(list)
    for domain, proxy_events in by_domain.items():
        sensor = list(rows(con, "SELECT rowid,* FROM host WHERE target=? AND event='DNS_QUERY' ORDER BY ts", (domain,)))
        if len({e["host"] for e in sensor}) > cfg["download_domain_max_hosts"]:
            findings.suppressed["download_domain_not_rare"] += len(proxy_events)
            continue
        continuation = {}
        for proxy in sorted(proxy_events, key=lambda p: (p["ts"], p["rowid"])):
            eligible = [event for event in sensor if
                        0 <= seconds(proxy["ts"]) - seconds(event["ts"]) <= cfg["host_proxy_window_seconds"]
                        and address.matches(event["host"], proxy)]
            if not eligible and proxy["src_ip"] not in address.nat:
                # Continue a previously attributed request stream only on an active,
                # direct host IP. NAT reuse requires fresh sensor evidence.
                previous = continuation.get(proxy["src_ip"])
                if previous and 0 <= seconds(proxy["ts"]) - seconds(previous[0]["ts"]) <= cfg["proxy_continuation_gap_seconds"] and address.matches(previous[1]["host"], proxy):
                    eligible = [previous[1]]
            if not eligible:
                findings.hold(7, "unattributed_proxy_download", proxy, "No preceding host sensor match with active IP/NAT mapping")
                continue
            closest = max(eligible, key=lambda e: (e["ts"], e["rowid"]))
            tied = {(e["host"], e["process"]) for e in eligible if e["ts"] == closest["ts"]}
            if len(tied) != 1:
                findings.hold(7, "ambiguous_proxy_process", proxy, "Several host/process matches at the same time")
                continue
            continuation[proxy["src_ip"]] = (proxy, closest)
            matched_groups[(closest["host"], closest["process"], domain)].append((proxy, closest))
    for (host, process, domain), matches in matched_groups.items():
        matches.sort(key=lambda pair: (pair[0]["ts"], pair[0]["rowid"]))
        update = lookalike_update(domain, cfg)
        gap = cfg["update_campaign_gap_seconds"] if update else max(cfg["loader_chain_window_seconds"], cfg["download_repeat_seconds"])
        by_id = {p["rowid"]: h for p, h in matches}
        for group in campaigns([p for p, _ in matches], gap):
            if update and (len(group) < cfg["update_min_requests"] or seconds(group[-1]["ts"]) - seconds(group[0]["ts"]) < cfg["update_min_span_seconds"]):
                findings.hold(7, "weak_lookalike_update", group[0], "Insufficient repeated update-fetch evidence")
                continue
            # Separate different downloads unless loader -> DLL is a short causal chain.
            batches = [group] if update else []
            if not update:
                current = []
                for proxy in group:
                    path = urlsplit(proxy["url"]).path.lower()
                    same = current and proxy["url"] == current[-1]["url"] and seconds(proxy["ts"]) - seconds(current[0]["ts"]) <= cfg["download_repeat_seconds"]
                    chain = current and "loader" in current[0]["url"].lower() and path.endswith(".dll") and seconds(proxy["ts"]) - seconds(current[0]["ts"]) <= cfg["loader_chain_window_seconds"]
                    if current and not (same or chain):
                        batches.append(current)
                        current = []
                    current.append(proxy)
                if current:
                    batches.append(current)
            for batch in batches:
                first = batch[0]
                sensor = by_id[first["rowid"]]
                # Proxy time is the first request; host/process come from sensor evidence.
                # Remove host rowid when timestamp is replaced: sessions resolve as of proxy time.
                anchor = {k: v for k, v in sensor.items() if k != "rowid"}
                anchor["ts"] = first["ts"]
                rule = "lookalike_update_fetches" if update else "loader_then_second_stage" if len({p["url"] for p in batch}) > 1 else "untrusted_executable_download"
                findings.add(7, rule, MALWARE, anchor,
                             [{"table": "host", **sensor}] + [{"table": "proxy", **p} for p in batch])
                findings.suppressed["repeated_download_or_stage_telemetry"] += len(batch) - 1
    return [{"domain": d, "path": p, "count": n} for (d, p), n in inventory.most_common()]


def run_detection(db_path, cfg, progress=lambda message: None):
    start = time.monotonic()
    db_path = Path(db_path).resolve()
    # mode=ro and query_only prevent writes even if this script changes later.
    con = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA temp_store=MEMORY")
    con.execute("PRAGMA cache_size=-8192")
    try:
        progress("Loading LOGIN/LOGOUT history with existing partial indexes")
        session_events = list(rows(con, "SELECT rowid,* FROM host WHERE event='LOGIN'"))
        session_events.extend(rows(con, "SELECT rowid,* FROM host WHERE event='LOGOUT'"))
        sessions = SessionIndex(session_events)
        findings = Findings(sessions)
        progress("Examining commands, process signatures and IP assignments")
        stats, variants, examples, archives, ips = command_hunts(con, cfg, findings)
        usb = archive_hunt(con, cfg, findings, archives) if 4 in cfg["enabled_hunts"] else {}
        net_stats, process_inventory = network_hunt(con, cfg, findings, variants, examples, progress) if 6 in cfg["enabled_hunts"] else ({}, [])
        proxy_inventory = download_hunt(con, cfg, findings, ips, progress) if 7 in cfg["enabled_hunts"] else []
        findings.records.sort(key=lambda r: tuple(r["finding"][f] for f in ("timestamp", "host", "process", "category")))
        # Strict output checks supplement the supplied permissive validator.
        asset_names = {r[0] for r in con.execute("SELECT hostname FROM assets")}
        user_names = {r[0].lower() for r in con.execute("SELECT user FROM users")}
        for record in findings.records:
            f = record["finding"]
            assert tuple(f) == FIELDS and f["host"] in asset_names
            assert f["user"].lower() in user_names | {"none"}
            assert f["process"] not in {"", "-"}
            seconds(f["timestamp"])
        return {
            "findings": [r["finding"] for r in findings.records], "evidence": findings.records,
            "review_queue": findings.review,
            "summary": {"total_findings": len(findings.records),
                "distinct_hosts": len({r["finding"]["host"] for r in findings.records}),
                "by_hunt": {str(h): {"name": name, "count": sum(r["hunt"] == h for r in findings.records)} for h, name in HUNT_NAMES.items()},
                "by_rule": dict(Counter(r["rule"] for r in findings.records)),
                "by_category": dict(Counter(r["finding"]["category"] for r in findings.records)),
                "by_confidence": dict(Counter(r["confidence"] for r in findings.records)),
                "review_by_reason": dict(Counter(r["rule"] for r in findings.review)),
                "suppressed": dict(findings.suppressed),
                "scanned_host_events": {**dict(stats), **net_stats, "LOGIN": sum(r["event"] == "LOGIN" for r in session_events), "LOGOUT": sum(r["event"] == "LOGOUT" for r in session_events)},
                "usb_inventory": usb, "elapsed_seconds": round(time.monotonic() - start, 3)},
            "process_inventory": process_inventory, "proxy_candidate_inventory": proxy_inventory,
            "database": {"path": str(db_path), "size": db_path.stat().st_size, "mtime_ns": db_path.stat().st_mtime_ns},
            "configuration": cfg,
        }
    finally:
        con.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="dataset/bearcorp.db")
    parser.add_argument("--config", default="endpoint_config.json")
    parser.add_argument("--team-id", help="Override shared team_id (preserved as a string)")
    parser.add_argument("--output", default="endpoint_findings.json")
    parser.add_argument("--evidence", default="endpoint_analysis/endpoint_evidence.json")
    parser.add_argument("--force", action="store_true", help="Replace only the explicitly named endpoint outputs")
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    team_id = args.team_id if args.team_id is not None else cfg.get("team_id")
    if isinstance(team_id, bool) or not isinstance(team_id, (str, int)) or str(team_id).strip().lower() in {"", "your-team-id", "your-team-name"}:
        parser.error("Supply the team's real team_id in the config or --team-id")
    outputs = [Path(args.output).resolve(), Path(args.evidence).resolve()]
    source = Path(args.data).resolve()
    if len(set(outputs)) != 2 or source in outputs:
        parser.error("Findings, evidence and source database paths must be distinct")
    for output in outputs:
        if output.exists() and not args.force:
            parser.error(f"Refusing to overwrite {output}; choose new output names or use --force")
        output.parent.mkdir(parents=True, exist_ok=True)
    report = run_detection(args.data, cfg, lambda message: print(message, flush=True))
    document = {"team_id": team_id, "findings": report["findings"]}
    outputs[0].write_text(json.dumps(document, indent=2) + "\n")
    outputs[1].write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
