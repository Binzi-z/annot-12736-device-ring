"""Detection functions.

Every detector returns a list of alerts. Each alert is self-describing: it
embeds the rule id/version, the full parameter snapshot used, and the evidence
(window, accounts, devices, transfer edges and the raw supporting events).
Nothing here writes to the event file; events are read-only inputs.
"""

from __future__ import annotations

import itertools
import re
from collections import defaultdict
from datetime import datetime

from rules import FINGERPRINT_PATTERN, RULESET_VERSION, rule_index

_FP_RE = re.compile(FINGERPRINT_PATTERN)


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def fingerprint(device: str) -> str:
    """Stable hardware fingerprint behind a device string.

    ``u1000-d477`` and ``u1024-d477`` are two accounts on the same physical
    device, so they share fingerprint ``d477``. Names that do not match the
    account-prefixed shape are used verbatim.
    """
    match = _FP_RE.match(device)
    return match.group(2) if match else device


def _line_ref(event: dict, line_no: int) -> dict:
    """Compact pointer back to the source line (the event file is not modified)."""
    return {
        "line": line_no,
        "ts": event["ts"],
        "account": event["account"],
        "device": event["device"],
        "action": event["action"],
        "amount": event["amount"],
        "ip_region": event["ip_region"],
    }


def detect_shared_device_transfer_ring(events, lines, cfg):
    """Find clusters of accounts sharing devices and transferring among themselves.

    Discriminator vs. normal household device sharing:
      * household pairs share a device occasionally, across days, with sparse
        and mostly one-directional encounters;
      * a farm/ring shares a *batch* of fingerprints (every pair overlaps on
        several of them) AND produces a dense graph of same-amount transfers
        inside one short window.
    Random background components are long-lived and sparse, so the density +
    span + shared-fingerprint conjunction separates the two cases.
    """
    p = cfg["params"]
    edge_window_s = p["edge_window_s"]
    max_span_s = p["max_span_s"]

    account_fps = defaultdict(set)
    event_by_id = {id(event): event for event in events}
    for event in events:
        account_fps[event["account"]].add(fingerprint(event["device"]))

    pays = sorted(
        (e for e in events if e["action"] == "pay"),
        key=lambda e: e["ts"],
    )

    # Candidate transfer edges: cross-account pay pairs, equal amount, close in
    # time, between accounts that share enough fingerprints. Each stored
    # occurrence carries its own start timestamp for window anchoring.
    raw_edges = defaultdict(list)  # pair -> list of (left_event, right_event)
    for i, left in enumerate(pays):
        left_t = parse_ts(left["ts"])
        for j in range(i + 1, len(pays)):
            right = pays[j]
            delta = (parse_ts(right["ts"]) - left_t).total_seconds()
            if delta > edge_window_s:
                break
            if left["account"] == right["account"]:
                continue
            if p["require_same_amount"] and left["amount"] != right["amount"]:
                continue
            shared = account_fps[left["account"]] & account_fps[right["account"]]
            if len(shared) < p["min_shared_fingerprints"]:
                continue
            pair = tuple(sorted((left["account"], right["account"])))
            raw_edges[pair].append((left, right))

    edge_occurrences = [
        (left, right)
        for occurrences in raw_edges.values()
        for left, right in occurrences
    ]

    # Evaluate every bounded window anchored on an edge occurrence, keep the
    # qualifying connected components, then collapse overlapping windows over
    # the same account set into one alert (widest window wins).
    best_by_members = {}
    for anchor_left, _ in edge_occurrences:
        anchor_ts = parse_ts(anchor_left["ts"]).timestamp()
        window_end = anchor_ts + max_span_s

        active_pairs = set()         # distinct account pairs with an edge here
        active_events = defaultdict(list)
        weighted_edge_count = 0
        for edge_pair, occurrences in raw_edges.items():
            for left, right in occurrences:
                ts0 = parse_ts(left["ts"]).timestamp()
                if anchor_ts <= ts0 <= window_end:
                    active_pairs.add(edge_pair)
                    active_events[edge_pair].append((left, right))
                    weighted_edge_count += 1
        if weighted_edge_count < p["min_edges"]:
            continue

        graph = defaultdict(set)
        for left, right in active_pairs:
            graph[left].add(right)
            graph[right].add(left)

        visited = set()
        for node in graph:
            if node in visited:
                continue
            stack = [node]
            component = set()
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                stack.extend(graph[current] - visited)

            members = sorted(component)
            k = len(members)
            if k < p["min_accounts"]:
                continue
            member_pair_set = {
                tuple(sorted(pair_))
                for pair_ in itertools.combinations(members, 2)
            }
            internal_pairs = member_pair_set & active_pairs
            if len(internal_pairs) < p["min_edges"]:
                continue
            possible = k * (k - 1) // 2
            density = len(internal_pairs) / possible  # over unique pairs, <= 1
            if density < p["min_density"]:
                continue

            timestamps, devices, window_event_ids = [], set(), set()
            for edge_pair in internal_pairs:
                for left, right in active_events[edge_pair]:
                    timestamps.extend([left["ts"], right["ts"]])
                    devices.add(left["device"])
                    devices.add(right["device"])
                    window_event_ids.add(id(left))
                    window_event_ids.add(id(right))

            window_from = min(timestamps)
            window_to = max(timestamps)
            span_s = int(
                (parse_ts(window_to) - parse_ts(window_from)).total_seconds()
            )
            if span_s > max_span_s:
                continue

            key = tuple(members)
            # keep the widest window seen for this exact account set
            if key in best_by_members and best_by_members[key]["window_from"] <= window_from:
                continue
            best_by_members[key] = {
                "members": members,
                "internal_pairs": internal_pairs,
                "active_events": active_events,
                "window_from": window_from,
                "window_to": window_to,
                "span_s": span_s,
                "devices": devices,
                "window_event_ids": window_event_ids,
                "density": density,
            }

    alerts = []
    for members, candidate in best_by_members.items():
        members = candidate["members"]
        k = len(members)
        internal_pairs = candidate["internal_pairs"]
        transfer_edges = []
        for edge_pair in sorted(internal_pairs):
            for left, right in candidate["active_events"][edge_pair]:
                transfer_edges.append(
                    {
                        "from": left["account"],
                        "to": right["account"],
                        "amount": left["amount"],
                        "left_ts": left["ts"],
                        "right_ts": right["ts"],
                        "gap_s": int(
                            (parse_ts(right["ts"]) - parse_ts(left["ts"])).total_seconds()
                        ),
                        "left_device": left["device"],
                        "right_device": right["device"],
                        "shared_fingerprints": sorted(
                            account_fps[left["account"]]
                            & account_fps[right["account"]]
                        ),
                    }
                )
        transfer_edges.sort(key=lambda e: (e["left_ts"], e["from"], e["to"]))

        # Cluster-wide fingerprint evidence: intersection is the batch every
        # member shares; union documents every fingerprint the members touch.
        shared_batch = set.intersection(*(account_fps[m] for m in members))
        cluster_fps = set()
        for member in members:
            cluster_fps.update(account_fps[member])

        supporting = []
        for event_id in sorted(
            candidate["window_event_ids"], key=lambda eid: lines.get(eid, 1 << 30)
        ):
            line_no = lines.get(event_id)
            event = event_by_id.get(event_id)
            if line_no is not None and event is not None:
                supporting.append(_line_ref(event, line_no))

        alerts.append(
            {
                "rule": cfg["rule"],
                "rule_version": cfg["rule_version"],
                "ruleset_version": RULESET_VERSION,
                "params": p,
                "severity": "high",
                "window": {
                    "from": candidate["window_from"],
                    "to": candidate["window_to"],
                    "span_s": candidate["span_s"],
                },
                "accounts": members,
                "devices": {
                    "window_devices": sorted(candidate["devices"]),
                    "shared_fingerprint_batch": sorted(shared_batch),
                    "cluster_fingerprints": sorted(cluster_fps),
                },
                "transfer_edges": transfer_edges,
                "metrics": {
                    "account_count": k,
                    "edge_count": len(internal_pairs),
                    "weighted_edge_count": len(transfer_edges),
                    "density": round(candidate["density"], 4),
                },
                "evidence_events": sorted(supporting, key=lambda e: e["line"]),
            }
        )
    return alerts


def detect_burst_small_pay(events, lines, cfg):
    """Many small payments from an unseen region inside a sub-minute window."""
    p = cfg["params"]
    # Regions the account has historically been seen in.
    known_regions = defaultdict(set)
    for event in events:
        known_regions[event["account"]].add(event["ip_region"])

    by_account = defaultdict(list)
    for event in events:
        if event["action"] != p["action"]:
            continue
        if event["amount"] > p["small_amount_max"]:
            continue
        by_account[event["account"]].append(event)

    alerts = []
    for account, account_events in by_account.items():
        account_events.sort(key=lambda e: e["ts"])
        n = len(account_events)
        for i in range(n):
            start = parse_ts(account_events[i]["ts"])
            window = [
                event
                for event in account_events[i:]
                if (parse_ts(event["ts"]) - start).total_seconds() < p["window_s"]
            ]
            if len(window) < p["min_count"]:
                continue
            region = window[0]["ip_region"]
            if p["unseen_region_only"]:
                # "Unseen" means the region appears only inside this burst, not
                # anywhere else in the account's history.
                window_ids = {id(event) for event in window}
                outside = [
                    event
                    for event in events
                    if event["account"] == account
                    and event["ip_region"] == region
                    and id(event) not in window_ids
                ]
                if outside:
                    continue
            window = window[: p["min_count"]]
            supporting = []
            for event in window:
                line_no = lines.get(id(event))
                if line_no is not None:
                    supporting.append(_line_ref(event, line_no))
            alerts.append(
                {
                    "rule": cfg["rule"],
                    "rule_version": cfg["rule_version"],
                    "ruleset_version": RULESET_VERSION,
                    "params": p,
                    "severity": "high",
                    "window": {
                        "from": window[0]["ts"],
                        "to": window[-1]["ts"],
                        "span_s": int(
                            (
                                parse_ts(window[-1]["ts"])
                                - parse_ts(window[0]["ts"])
                            ).total_seconds()
                        ),
                    },
                    "accounts": [account],
                    "devices": {
                        "window_devices": sorted({e["device"] for e in window}),
                        "shared_fingerprint_batch": sorted(
                            {fingerprint(e["device"]) for e in window}
                        ),
                        "cluster_fingerprints": sorted(
                            {fingerprint(e["device"]) for e in window}
                        ),
                    },
                    "transfer_edges": [],
                    "metrics": {
                        "payment_count": len(window),
                        "ip_region": region,
                        "known_regions": sorted(known_regions[account] - {region}),
                    },
                    "evidence_events": supporting,
                }
            )
            break  # one alert per account for the earliest qualifying burst
    return alerts


def detect_new_device_big_withdraw(events, lines, cfg):
    """Login on a never-before-seen device, then a large withdrawal."""
    p = cfg["params"]
    alerts = []
    by_account = defaultdict(list)
    for event in events:
        by_account[event["account"]].append(event)

    for account, account_events in by_account.items():
        account_events.sort(key=lambda e: e["ts"])
        seen_devices = set()
        for index, event in enumerate(account_events):
            if event["action"] == p["login_action"]:
                is_new_device = event["device"] not in seen_devices
                if not is_new_device:
                    seen_devices.add(event["device"])
                    continue
                seen_devices.add(event["device"])
                login = event
                login_t = parse_ts(login["ts"])
                # find the first big withdrawal within the follow-up window
                withdrawal = None
                for later in account_events[index + 1 :]:
                    delta = (parse_ts(later["ts"]) - login_t).total_seconds()
                    if delta > p["login_withdraw_window_s"]:
                        break
                    if (
                        later["action"] == p["withdraw_action"]
                        and later["amount"] >= p["withdraw_amount_min"]
                    ):
                        withdrawal = later
                        break
                if withdrawal is None:
                    continue
                refs = []
                for event_ref in (login, withdrawal):
                    line_no = lines.get(id(event_ref))
                    if line_no is not None:
                        refs.append(_line_ref(event_ref, line_no))
                alerts.append(
                    {
                        "rule": cfg["rule"],
                        "rule_version": cfg["rule_version"],
                        "ruleset_version": RULESET_VERSION,
                        "params": p,
                        "severity": "critical",
                        "window": {
                            "from": login["ts"],
                            "to": withdrawal["ts"],
                            "span_s": int(
                                (
                                    parse_ts(withdrawal["ts"])
                                    - parse_ts(login["ts"])
                                ).total_seconds()
                            ),
                        },
                        "accounts": [account],
                        "devices": {
                            "window_devices": sorted(
                                {login["device"], withdrawal["device"]}
                            ),
                            "shared_fingerprint_batch": sorted(
                                {
                                    fingerprint(login["device"]),
                                    fingerprint(withdrawal["device"]),
                                }
                            ),
                            "cluster_fingerprints": sorted(
                                {
                                    fingerprint(login["device"]),
                                    fingerprint(withdrawal["device"]),
                                }
                            ),
                        },
                        "transfer_edges": [
                            {
                                "from": account,
                                "to": account,
                                "amount": withdrawal["amount"],
                                "left_ts": login["ts"],
                                "right_ts": withdrawal["ts"],
                                "gap_s": int(
                                    (
                                        parse_ts(withdrawal["ts"])
                                        - parse_ts(login["ts"])
                                    ).total_seconds()
                                ),
                                "left_device": login["device"],
                                "right_device": withdrawal["device"],
                                "shared_fingerprints": [
                                    fingerprint(login["device"])
                                ],
                            }
                        ],
                        "metrics": {
                            "withdraw_amount": withdrawal["amount"],
                            "new_device": login["device"],
                            "ip_region": withdrawal["ip_region"],
                        },
                        "evidence_events": refs,
                    }
                )
    return alerts


DETECTORS = {
    "shared_device_transfer_ring": detect_shared_device_transfer_ring,
    "burst_small_pay": detect_burst_small_pay,
    "new_device_big_withdraw": detect_new_device_big_withdraw,
}


def run_all(events, lines, only=None):
    """Execute every configured rule (or a selected subset) and collect alerts."""
    alerts = []
    for cfg in rule_index().values():
        if only and cfg["rule"] not in only:
            continue
        detector = DETECTORS[cfg["rule"]]
        alerts.extend(detector(events, lines, cfg))
    alerts.sort(key=lambda a: (a["window"]["from"], a["rule"]))
    return alerts
