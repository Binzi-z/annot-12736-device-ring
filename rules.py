"""Versioned, configuration-driven detection rules.

Each rule is plain data plus a ``RULE_VERSION``. Tuning a threshold bumps the
version instead of editing code, so alerts produced by older rule sets stay
reproducible and explainable: every emitted alert records the exact rule id,
version and parameter snapshot that fired it.

The event file schema is intentionally NOT touched — rules read only the
existing fields (ts, account, device, amount, action, ip_region).
"""

from __future__ import annotations

# Bump whenever any rule semantics or default parameter changes.
#
# Versioning contract:
#   * RULESET_VERSION is the engine-wide version; each rule additionally
#     carries its own rule_version.
#   * A threshold/semantics change bumps the affected rule_version (and the
#     ruleset version) but never edits a released version in place.
#   * Every emitted alert freezes rule id + rule_version + the exact params
#     snapshot, so an archived alert is re-explainable against the rule as it
#     existed when the alert fired, even after later releases change it.
#   * To retire or re-tune a rule, append a new rule_version entry; keep the
#     old definition available for historical replay.
RULESET_VERSION = "1.0.0"

# Device fingerprints look like ``<account>-d<id>``; the stable hardware part is
# the ``d<id>`` suffix. Non-conforming names (e.g. ``d000-bot``) are the whole
# string. The same fingerprint observed on multiple accounts is the device
# sharing signal.
FINGERPRINT_PATTERN = r"^(u\d+)-(d\d+)$"

RULES = [
    {
        # Newly registered accounts that share a batch of device fingerprints
        # and move money to each other inside one short time window.
        "rule": "shared_device_transfer_ring",
        "rule_version": "1.0.0",
        "params": {
            # Two pay events are treated as the two ends of one transfer edge
            # when they happen within this many seconds ...
            "edge_window_s": 180,
            # ... carry the same amount ...
            "require_same_amount": True,
            # ... and the two accounts have at least this many fingerprints in
            # common. Family/shared-household devices produce a handful of
            # shared fingerprints between pairs with no coordinated transfers;
            # a device farm reuses a whole batch, so every ring pair shares
            # many.
            "min_shared_fingerprints": 2,
            # A ring must contain at least this many distinct accounts ...
            "min_accounts": 4,
            # ... at least this many transfer edges inside the window ...
            "min_edges": 8,
            # ... and the internal graph must be at least this dense. Random
            # background encounters stay sparse (long-lived, low-density
            # components); coordinated mutual transfers form a near-clique.
            "min_density": 0.6,
            # The whole cluster must unfold within this wall-clock span.
            "max_span_s": 900,
        },
    },
    {
        # 12 small payments in under 60 seconds from a region the account has
        # never been seen in before.
        "rule": "burst_small_pay",
        "rule_version": "1.0.0",
        "params": {
            "action": "pay",
            "min_count": 12,
            "window_s": 60,
            "unseen_region_only": True,
            # Payments at or below this amount count as "small".
            "small_amount_max": 19.9,
        },
    },
    {
        # First login on a previously unseen device, followed shortly by a
        # large withdrawal.
        "rule": "new_device_big_withdraw",
        "rule_version": "1.0.0",
        "params": {
            "withdraw_action": "withdraw",
            "login_action": "login",
            "withdraw_amount_min": 48000.0,
            "login_withdraw_window_s": 300,
        },
    },
]


def rule_index() -> dict[str, dict]:
    return {r["rule"]: r for r in RULES}
