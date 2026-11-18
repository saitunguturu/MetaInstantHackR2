#!/usr/bin/env python3
"""Validate a hackathon findings.json file.

Checks structure, the required team_id, required fields, timestamp format,
category names and per-category caps (from the dataset's categories.md, when
present), and that hosts and users exist in the dataset's assets and users
tables. Top-level keys other than team_id and findings are ignored.
Participants run this before submitting; organizers run it on receipt.

Jargon used here: a cap is the maximum number of rows allowed per grading
category; a finding is one submitted row in the findings list; team_id is the
value every member of a team puts in their own file, so the scorer can merge
the files; the dataset is bearcorp.db, or a folder holding bearcorp.db or
assets.csv and users.csv.

Usage:
    python3 berkeley_hackathon_validate.py findings.json --data dataset/bearcorp.db
    python3 berkeley_hackathon_validate.py findings.json --data /path/to/dataset
"""

from __future__ import annotations

import argparse
import csv
import difflib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

DB_NAME = "bearcorp.db"
PLACEHOLDER_TEAM_IDS = {"your-team-id", "your-team-name"}
ERRORS: list[str] = []
WARNINGS: list[str] = []

FALLBACK_CATEGORIES = [
    "Known-bad indicators",
    "Command and control",
    "Reconnaissance",
    "Data theft",
    "Deceptive domains",
    "Malware delivery",
    "Host intrusion signs",
    "Lateral movement",
    "Credential abuse",
]


def err(msg: str) -> None:
    ERRORS.append(msg)
    print(f"error: {msg}")


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"warning: {msg}")


def parse_ts(s: str) -> int:
    text = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return int(
                datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
                * 1000
            )
        except ValueError:
            continue
    raise ValueError(f"bad timestamp: {s!r}")


def load_categories(path: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.startswith("| ") or line.startswith("| Category"):
                continue
            parts = [p.strip() for p in line.strip("|").split("|")]
            if len(parts) == 3 and parts[2].isdigit():
                counts[parts[0]] = int(parts[2])
    return counts


def check_team_id(team_id: object) -> None:
    if isinstance(team_id, bool) or not isinstance(team_id, (str, int)):
        err("team_id must be a string or a whole number")
        return
    text = str(team_id).strip()
    if not text:
        err("team_id must not be empty")
    elif text.lower() in PLACEHOLDER_TEAM_IDS:
        err(f"team_id {text!r} is the example value; use your team's ID")


def load_document(path: str) -> dict | None:
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        err(f"cannot read JSON: {exc}")
        return None
    if not isinstance(doc, dict):
        err("top level must be an object")
        return None
    if "team_id" not in doc:
        hint = "; rename team to team_id" if "team" in doc else ""
        err(f"missing required key: team_id{hint}")
    if "findings" not in doc:
        hint = "; rename detections to findings" if "detections" in doc else ""
        err(f"missing required key: findings{hint}")
    if ERRORS:
        return None
    check_team_id(doc["team_id"])
    if not isinstance(doc["findings"], list):
        err("findings must be a list")
    return doc if not ERRORS else None


def find_db(data: str) -> str | None:
    if os.path.isfile(data):
        return data
    path = os.path.join(data, DB_NAME)
    return path if os.path.isfile(path) else None


def load_caps(folder: str, quiet: bool) -> tuple[dict[str, int], bool]:
    try:
        return load_categories(os.path.join(folder, "categories.md")), True
    except OSError as exc:
        if not quiet:
            warn(
                f"cannot read categories.md: {exc}; "
                "using fallback category names, cap checks skipped"
            )
        return {name: 10**9 for name in FALLBACK_CATEGORIES}, False


def load_names_from_db(db: str) -> tuple[set[str], set[str]] | None:
    try:
        con = sqlite3.connect(db)
        try:
            assets = {
                str(r[0]).strip() for r in con.execute("SELECT hostname FROM assets")
            }
            users = {
                str(r[0]).strip().lower() for r in con.execute("SELECT user FROM users")
            }
        finally:
            con.close()
    except sqlite3.Error as exc:
        err(f"cannot read {db}: {exc}")
        return None
    return assets, users


def load_names_from_csv(folder: str) -> tuple[set[str], set[str]] | None:
    assets: set[str] = set()
    try:
        with open(os.path.join(folder, "assets.csv"), newline="") as f:
            for row in csv.reader(f):
                if row and row[0] != "hostname":
                    assets.add(row[0].strip())
    except OSError as exc:
        err(f"cannot read assets.csv: {exc}")
        return None
    users: set[str] = set()
    try:
        with open(os.path.join(folder, "users.csv"), newline="") as f:
            for row in csv.reader(f):
                if row and row[0] != "user":
                    users.add(row[0].strip().lower())
    except OSError as exc:
        err(f"cannot read users.csv: {exc}")
        return None
    return assets, users


def load_reference(
    data: str,
) -> tuple[dict[str, int], set[str], set[str], bool] | None:
    db = find_db(data)
    folder = os.path.dirname(data) if os.path.isfile(data) else data
    caps, caps_enforced = load_caps(folder, quiet=db is not None)
    names = load_names_from_db(db) if db else load_names_from_csv(folder)
    if names is None:
        return None
    return caps, names[0], names[1], caps_enforced


def check_finding(
    finding: dict,
    where: str,
    caps: dict[str, int],
    assets: set[str],
    users: set[str],
) -> tuple[str, str | None]:
    missing = [
        field
        for field in ("category", "timestamp", "host", "user", "process")
        if field not in finding or not str(finding[field]).strip()
    ]
    if missing:
        err(f"{where}: missing or empty {', '.join(missing)}")
        return "", None
    cat = str(finding["category"]).strip()
    if cat not in caps:
        suggestion = difflib.get_close_matches(cat, list(caps), n=1, cutoff=0.6)
        if suggestion:
            err(f"{where}: unknown category {cat!r}; did you mean {suggestion[0]!r}?")
        else:
            err(f"{where}: unknown category {cat!r}")
        cat = ""
    host = str(finding["host"]).strip()
    if host not in assets:
        err(f"{where}: unknown host {host!r} (check the assets table)")
    user = str(finding["user"]).strip().lower()
    if user != "none" and user not in users:
        err(f"{where}: unknown user {finding['user']!r} (check the users table)")
    try:
        parse_ts(str(finding["timestamp"]))
    except ValueError:
        err(
            f"{where}: bad timestamp "
            "(want 2026-10-14T09:21:53.441Z or 2026-10-14T09:21:53Z)"
        )
    if "confidence" in finding and finding["confidence"] not in (
        "high",
        "medium",
        "low",
    ):
        err(f"{where}: confidence must be high, medium, or low")
    if "evidence" in finding and (
        not isinstance(finding["evidence"], list)
        or not all(isinstance(e, str) for e in finding["evidence"])
    ):
        err(f"{where}: evidence must be a list of strings")
    return host, cat or None


def main() -> int:  # noqa: C901
    ap = argparse.ArgumentParser(description="Validate findings.json.")
    ap.add_argument("findings", help="your findings.json file")
    ap.add_argument(
        "--data", required=True, help=f"{DB_NAME}, or the dataset folder holding it"
    )
    args = ap.parse_args()

    doc = load_document(args.findings)
    if doc is None:
        return 1
    ref = load_reference(args.data)
    if ref is None:
        return 1
    caps, assets, users, caps_enforced = ref

    per_cat: dict[str, int] = {}
    hosts: set[str] = set()
    for i, finding in enumerate(doc["findings"]):
        where = f"findings[{i}]"
        if not isinstance(finding, dict):
            err(f"{where}: must be an object")
            continue
        host, cat = check_finding(finding, where, caps, assets, users)
        if not host:
            continue
        if cat is not None:
            per_cat[cat] = per_cat.get(cat, 0) + 1
        hosts.add(host)

    if caps_enforced:
        for cat, n in sorted(per_cat.items()):
            if n > caps[cat]:
                warn(f"category {cat!r}: {n} rows exceeds cap of {caps[cat]}")

    if ERRORS:
        print(f"\n{len(ERRORS)} errors, {len(WARNINGS)} warnings: INVALID")
        return 1
    print(
        f"OK: team_id={doc['team_id']} findings={len(doc['findings'])} "
        f"hosts={len(hosts)} warnings={len(WARNINGS)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
