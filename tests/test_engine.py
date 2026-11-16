import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import detectors  # noqa: E402
from rules import RULESET_VERSION, rule_index  # noqa: E402


def run(tmp_path, *extra):
    out = tmp_path / "alerts.json"
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "engine.py"),
         os.path.join(ROOT, "data", "events.jsonl"), str(out), *extra],
        capture_output=True, text=True,
    )
    return r, out


def load_real():
    events, lines = [], {}
    with open(os.path.join(ROOT, "data", "events.jsonl"), encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if line.strip():
                event = json.loads(line)
                lines[id(event)] = line_no
                events.append(event)
    return events, lines


def ring_events():
    """A synthetic device-farm ring: 5 new accounts, 4 shared fingerprints,
    dense same-amount mutual transfers inside ~7 minutes."""
    accounts = [f"u800{i}" for i in range(5)]
    fps = ["d501", "d502", "d503", "d504"]
    events = []
    # establish the shared fingerprint batch for every account first
    for account in accounts:
        for k, fp in enumerate(fps):
            events.append({
                "ts": f"2026-10-03T00:{k:02d}:00", "account": account,
                "device": f"{account}-{fp}", "amount": 9.9,
                "action": "view", "ip_region": "310000",
            })
    from datetime import datetime, timedelta
    start = datetime(2026, 10, 3, 8, 0, 0)
    step = 0
    for i in range(5):
        for j in range(i + 1, 5):
            ts0 = (start + timedelta(seconds=40 * step)).isoformat()
            ts1 = (start + timedelta(seconds=40 * step + 25)).isoformat()
            fp = fps[step % 4]
            events.append({
                "ts": ts0, "account": accounts[i],
                "device": f"{accounts[i]}-{fp}", "amount": 88.0,
                "action": "pay", "ip_region": "310000",
            })
            events.append({
                "ts": ts1, "account": accounts[j],
                "device": f"{accounts[j]}-{fp}", "amount": 88.0,
                "action": "pay", "ip_region": "310000",
            })
            step += 1
    lines = {id(e): n for n, e in enumerate(events, start=1)}
    return events, lines, accounts


# --------------------------------------------------------------------------
# Skeleton tests (kept, now exercising the new engine)
# --------------------------------------------------------------------------

def test_events_present():
    with open(os.path.join(ROOT, "data", "events.jsonl"), encoding="utf-8") as fh:
        assert sum(1 for _ in fh) > 1000


def test_labels_present():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        assert len(json.load(fh)["fraud"]) >= 2


def test_engine_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "alerts" in json.loads(out.read_text(encoding="utf-8"))


def test_alerts_have_account(tmp_path):
    _, out = run(tmp_path)
    for alert in json.loads(out.read_text(encoding="utf-8"))["alerts"]:
        assert alert.get("account")


# --------------------------------------------------------------------------
# Zero false positives on the benign stream + all labeled frauds hit
# --------------------------------------------------------------------------

def test_real_stream_zero_false_positives_and_labels_hit():
    events, lines = load_real()
    alerts = detectors.run_all(events, lines)
    # only the two labeled fraud accounts may alert; nothing in the benign
    # u10xx household traffic may trip any rule
    alerted_accounts = {acc for a in alerts for acc in a["accounts"]}
    assert alerted_accounts == {"u9001", "u9002"}
    rules = {a["rule"] for a in alerts}
    assert rules == {"burst_small_pay", "new_device_big_withdraw"}
    assert all(a["ruleset_version"] == RULESET_VERSION for a in alerts)


def test_ring_rule_silent_on_benign_background():
    events, lines = load_real()
    cfg = rule_index()["shared_device_transfer_ring"]
    assert detectors.detect_shared_device_transfer_ring(events, lines, cfg) == []


def test_ring_threshold_calibration_margin_on_background():
    # The chosen min_edges=8 sits clearly above the background's random floor:
    # loosening any other single dimension stays silent, while dropping the
    # edge requirement to 4 lets sparse random components through. This pins
    # the calibration so a future tuning change cannot silently erode it.
    import copy
    events, lines = load_real()
    base = rule_index()["shared_device_transfer_ring"]
    for key, value in (
        ("min_density", 0.33),
        ("min_accounts", 3),
        ("min_shared_fingerprints", 1),
        ("max_span_s", 3600),
    ):
        cfg = copy.deepcopy(base)
        cfg["params"][key] = value
        assert detectors.detect_shared_device_transfer_ring(events, lines, cfg) == []
    loose = copy.deepcopy(base)
    loose["params"]["min_edges"] = 4
    assert detectors.detect_shared_device_transfer_ring(events, lines, loose)


# --------------------------------------------------------------------------
# Ring detection: hits, evidence structure, family-sharing discrimination
# --------------------------------------------------------------------------

def test_ring_detected_with_full_evidence():
    events, lines, accounts = ring_events()
    cfg = rule_index()["shared_device_transfer_ring"]
    alerts = detectors.detect_shared_device_transfer_ring(events, lines, cfg)
    assert alerts, "a dense shared-device transfer ring must be detected"
    alert = alerts[0]
    # every ring member is reported
    assert set(accounts).issubset(set(alert["accounts"]))
    # devices / fingerprints / transfer edges / time window all present
    assert alert["devices"]["shared_fingerprint_batch"]
    assert len(alert["transfer_edges"]) >= cfg["params"]["min_edges"]
    assert alert["window"]["span_s"] <= cfg["params"]["max_span_s"]
    assert alert["metrics"]["density"] >= cfg["params"]["min_density"]
    # every edge references two distinct accounts sharing a fingerprint
    for edge in alert["transfer_edges"]:
        assert edge["from"] != edge["to"]
        assert edge["shared_fingerprints"]
        assert edge["gap_s"] <= cfg["params"]["edge_window_s"]
    # evidence events point back at source lines
    assert alert["evidence_events"]
    assert all("line" in ref for ref in alert["evidence_events"])


def test_family_sharing_without_coordinated_transfers_is_not_a_ring():
    # Two household accounts share two devices over two days, with only
    # isolated, non-dense payment activity — must not form a ring.
    events = [
        {"ts": "2026-10-01T09:00:00", "account": "u2001",
         "device": "u2001-d601", "amount": 49.0, "action": "view",
         "ip_region": "110000"},
        {"ts": "2026-10-01T10:00:00", "account": "u2002",
         "device": "u2002-d601", "amount": 49.0, "action": "view",
         "ip_region": "110000"},
        {"ts": "2026-10-02T09:00:00", "account": "u2001",
         "device": "u2001-d602", "amount": 99.0, "action": "pay",
         "ip_region": "110000"},
        {"ts": "2026-10-02T20:00:00", "account": "u2002",
         "device": "u2002-d602", "amount": 19.9, "action": "pay",
         "ip_region": "110000"},
    ]
    lines = {id(e): n for n, e in enumerate(events, start=1)}
    cfg = rule_index()["shared_device_transfer_ring"]
    assert detectors.detect_shared_device_transfer_ring(events, lines, cfg) == []


def test_four_person_household_sharing_two_devices_is_not_a_ring():
    # Four family members share two household devices (d601/d602) across two
    # days with normal, non-coordinated activity. Shared fingerprints alone
    # must never trigger the ring rule without dense in-window transfers.
    members = ["u2101", "u2102", "u2103", "u2104"]
    events = []
    for day in (1, 2):
        for k, member in enumerate(members):
            for fp in ("d601", "d602"):
                events.append({
                    "ts": f"2026-10-0{day}T{9 + k:02d}:0{k}:00",
                    "account": member, "device": f"{member}-{fp}",
                    "amount": 49.0, "action": ("view" if k % 2 else "pay"),
                    "ip_region": "110000",
                })
    # a couple of sporadic, different-amount payments hours apart
    events.append({
        "ts": "2026-10-01T18:00:00", "account": "u2101",
        "device": "u2101-d601", "amount": 199.0, "action": "pay",
        "ip_region": "110000",
    })
    events.append({
        "ts": "2026-10-01T22:00:00", "account": "u2102",
        "device": "u2102-d601", "amount": 9.9, "action": "pay",
        "ip_region": "110000",
    })
    lines = {id(e): n for n, e in enumerate(events, start=1)}
    cfg = rule_index()["shared_device_transfer_ring"]
    assert detectors.detect_shared_device_transfer_ring(events, lines, cfg) == []


def test_dense_transfers_without_shared_devices_are_not_a_ring():
    # coordinated transfers alone, on disjoint devices, lack the device
    # clustering requirement
    accounts = [f"u300{i}" for i in range(4)]
    events = []
    step = 0
    for i in range(4):
        for j in range(i + 1, 4):
            minute, second = divmod(40 * step, 60)
            for account in (accounts[i], accounts[j]):
                events.append({
                    "ts": f"2026-10-03T08:{minute:02d}:{second:02d}",
                    "account": account,
                    "device": f"{account}-d7{step:02d}",  # unique per edge
                    "amount": 88.0, "action": "pay", "ip_region": "310000",
                })
            step += 1
    lines = {id(e): n for n, e in enumerate(events, start=1)}
    cfg = rule_index()["shared_device_transfer_ring"]
    assert detectors.detect_shared_device_transfer_ring(events, lines, cfg) == []


# --------------------------------------------------------------------------
# Versioning: alerts freeze the rule version and parameter snapshot
# --------------------------------------------------------------------------

def test_alerts_freeze_version_and_params():
    events, lines = load_real()
    alerts = detectors.run_all(events, lines)
    for alert in alerts:
        cfg = rule_index()[alert["rule"]]
        assert alert["rule_version"] == cfg["rule_version"]
        assert alert["ruleset_version"] == RULESET_VERSION
        # the exact parameter snapshot is embedded, so an old alert stays
        # explainable even after rules.py later changes thresholds
        assert alert["params"] == cfg["params"]


def test_rule_filter_argument(tmp_path):
    r, out = run(tmp_path, "--rule", "burst_small_pay")
    assert r.returncode == 0, r.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert {a["rule"] for a in payload["alerts"]} == {"burst_small_pay"}
    assert payload["ruleset_version"] == RULESET_VERSION


def test_old_alert_stays_explainable_after_rule_change(tmp_path):
    # Freeze an alert produced under ruleset 1.0.0 (simulating an archived
    # alert). Then "upgrade" a threshold in-memory and re-run: the archived
    # payload must still carry its original version + parameter snapshot, and
    # the new run reports its own version — old and new never get conflated.
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    archived = json.loads(out.read_text(encoding="utf-8"))
    archived_burst = next(
        a for a in archived["alerts"] if a["rule"] == "burst_small_pay"
    )
    frozen_version = archived_burst["rule_version"]
    frozen_params = dict(archived_burst["params"])

    cfg = rule_index()["burst_small_pay"]
    original_count = cfg["params"]["min_count"]
    try:
        cfg["params"]["min_count"] = original_count + 5  # simulated rule change
        events, lines = load_real()
        rerun = detectors.run_all(events, lines)
        rerun_versions = {a["rule"]: a["rule_version"] for a in rerun}
        # archived snapshot is immutable and still self-describing
        assert archived_burst["rule_version"] == frozen_version
        assert archived_burst["params"] == frozen_params
        assert archived_burst["params"]["min_count"] == original_count
        # every freshly produced alert still embeds a complete snapshot
        for alert in rerun:
            assert alert["params"] == rule_index()[alert["rule"]]["params"]
            assert alert["rule_version"] in rerun_versions.values()
    finally:
        cfg["params"]["min_count"] = original_count


def test_event_file_format_untouched():
    # engine only reads the jsonl; verify every source line still parses with
    # the original six-field schema
    with open(os.path.join(ROOT, "data", "events.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            event = json.loads(line)
            assert set(event) == {
                "ts", "account", "device", "amount", "action", "ip_region"
            }
