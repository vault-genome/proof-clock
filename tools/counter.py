#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The counter: latest.json and index.json from every record.json under records/.

    counter.py --records DIR --out DIR [--today YYYY-MM-DD]

latest.json (schema vault-genome/proof-clock/v1) answers the stranger's
questions: when was the release last proven on a real chip, how many days
in a row, how many runs, how many distinct chips and launch measurements;
index.json lists every record, newest first; badge.json is the same badge
in the shape shields.io's endpoint reads. All three are recomputed from the
records each time, never edited.
"""
import argparse
import datetime as dt
import glob
import json
import os
import sys

SCHEMA = "vault-genome/proof-clock/v1"
STATUSES = ["proven", "not-exact", "refused", "no-capacity", "failed"]


def load(path):
    with open(path) as f:
        return json.load(f)


def chip_label(r):
    c = r.get("chip") or {}
    if r.get("platform") == "sev-snp":
        return "AMD %s" % c.get("product") if c.get("product") else "AMD SEV-SNP"
    return "Intel TDX"


def summary(r, path):
    t = r.get("timing") or {}
    g = r.get("gate") or {}
    return {
        "date": r["date"], "stamp": r["stamp"], "platform": r["platform"], "status": r["status"],
        "reason": r.get("reason") or "", "release": (r.get("release") or {}).get("tag"),
        "zone": (r.get("cloud") or {}).get("zone"), "machine": (r.get("cloud") or {}).get("machine"),
        "chip": chip_label(r), "firmware": (r.get("chip") or {}).get("firmware"),
        "measurement": r.get("measurement"), "gate": g.get("level"),
        "fixtures": g.get("fixtures"), "n_exact": g.get("n_exact"),
        "button_to_record_s": t.get("button_to_record_s"), "proven_at": r.get("proven_at"),
        "run_url": (r.get("run") or {}).get("url"), "path": os.path.dirname(path).replace(os.sep, "/"),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--records", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--today", default=None, help="UTC date for the streak (default: now)")
    a = ap.parse_args()

    paths = sorted(glob.glob(os.path.join(a.records, "*", "*", "record.json")))
    recs = []
    for p in paths:
        r = load(p)
        recs.append((r, os.path.relpath(p, os.path.dirname(a.records.rstrip("/")) or ".")))
    recs.sort(key=lambda rp: rp[0]["stamp"])
    index = [summary(r, p) for r, p in reversed(recs)]

    today = dt.date.fromisoformat(a.today) if a.today else dt.datetime.now(dt.timezone.utc).date()
    proven_days = {r["date"] for r, _ in recs if r["status"] == "proven"}
    d = today if today.isoformat() in proven_days else today - dt.timedelta(days=1)
    streak = 0
    while d.isoformat() in proven_days:
        streak += 1
        d -= dt.timedelta(days=1)

    counts = {s: 0 for s in STATUSES}
    by_platform = {}
    releases = set()
    last_proven = None
    last_run = None
    for r, p in recs:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        bp = by_platform.setdefault(r["platform"], {
            "runs": 0, "proven": 0, "last_proven_at": None, "chips": set(), "measurements": set(), "firmware": set(), "releases": set()})
        bp["runs"] += 1
        last_run = summary(r, p)
        if r["status"] == "proven":
            bp["proven"] += 1
            bp["last_proven_at"] = r.get("proven_at")
            if r.get("measurement"):
                bp["measurements"].add(r["measurement"])
            c = r.get("chip") or {}
            if c.get("chip_id_hex"):
                bp["chips"].add(c["chip_id_hex"])
            if c.get("firmware"):
                bp["firmware"].add(c["firmware"])
            if (r.get("release") or {}).get("tag"):
                releases.add(r["release"]["tag"])
                bp["releases"].add(r["release"]["tag"])
            last_proven = summary(r, p)
    for bp in by_platform.values():
        bp["chips_seen"] = len(bp.pop("chips"))
        bp["measurements_seen"] = len(bp.pop("measurements"))
        bp["firmware_seen"] = sorted(bp.pop("firmware"))
        bp["releases_proven"] = sorted(bp.pop("releases"))

    if last_run and last_run["status"] == "proven":
        when = (last_run["proven_at"] or "")[:16].replace("T", " ")
        badge = {"schemaVersion": 1, "label": "proof clock", "color": "brightgreen",
                 "message": "proven %sZ on %s, %s s" % (when, last_run["chip"], int(last_run["button_to_record_s"] or 0))}
    elif last_run:
        badge = {"schemaVersion": 1, "label": "proof clock", "color": "yellow" if last_run["status"] == "no-capacity" else "red",
                 "message": "%s %s on %s" % (last_run["status"], last_run["date"], last_run["chip"])}
    else:
        badge = {"schemaVersion": 1, "label": "proof clock", "color": "lightgrey", "message": "no run yet"}

    latest = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_proven": last_proven,
        "last_run": last_run,
        "streak_days": streak,
        "days_proven": len(proven_days),
        "runs": {"total": len(recs), **counts},
        "by_platform": by_platform,
        "releases_proven": sorted(releases),
        "badge": badge,
    }
    os.makedirs(a.out, exist_ok=True)
    for name, obj in (("latest.json", latest), ("index.json", index), ("badge.json", badge)):
        with open(os.path.join(a.out, name), "w") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
    print("records=%d proven=%d streak_days=%d" % (len(recs), counts["proven"], streak))
    return 0


if __name__ == "__main__":
    sys.exit(main())
