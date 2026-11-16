"""Risk engine entry point.

Reads the existing JSONL event stream (schema untouched) and emits versioned,
evidence-backed alerts. Rules live in ``rules.py`` as data: tuning a threshold
bumps ``RULESET_VERSION`` instead of requiring a code release, and every alert
keeps the exact rule version + parameter snapshot that produced it, so old
alerts remain explainable after later rule changes.

Usage:
    python engine.py data/events.jsonl alerts.json
    python engine.py data/events.jsonl alerts.json --rule shared_device_transfer_ring
"""

from __future__ import annotations

import argparse
import json
import sys

from detectors import run_all
from rules import RULESET_VERSION


def load_events(src: str):
    events = []
    line_of = {}
    with open(src, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            line_of[id(event)] = line_no
            events.append(event)
    return events, line_of


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Versioned fraud detection engine")
    parser.add_argument("src", nargs="?", default="data/events.jsonl")
    parser.add_argument("out", nargs="?", default="alerts.json")
    parser.add_argument(
        "--rule",
        action="append",
        default=None,
        help="restrict to a rule id (repeatable); default runs every rule",
    )
    args = parser.parse_args(argv)

    events, line_of = load_events(args.src)
    alerts = run_all(events, line_of, only=set(args.rule) if args.rule else None)

    # Backward-compatible top-level key, plus version metadata and per-rule
    # summary. The "account" field is kept on every alert so existing
    # integrations and the skeleton tests keep working.
    rule_counts = {}
    for alert in alerts:
        rule_counts[alert["rule"]] = rule_counts.get(alert["rule"], 0) + 1
        alert["account"] = alert["accounts"][0]

    payload = {
        "ruleset_version": RULESET_VERSION,
        "source": args.src,
        "event_count": len(events),
        "alert_count": len(alerts),
        "rule_counts": rule_counts,
        "alerts": alerts,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"{len(alerts)} alerts -> {args.out} (ruleset {RULESET_VERSION})")
    for rule, count in sorted(rule_counts.items()):
        print(f"  {rule}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
