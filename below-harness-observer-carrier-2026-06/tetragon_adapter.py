#!/usr/bin/env python3
"""Tetragon JSON -> observed-effect carrier adapter.

The first below-harness adapter. It takes a Tetragon export — a list of events plus the set of
dimensions Tetragon was configured to observe — and a tool's declared effect, and normalizes them
into an ``assay.observed_effect.v1`` carrier via ``observer_carrier``.

What it claims: "Tetragon observed a network effect under this coverage profile; normalized into
bounded evidence against a declared no-network expectation."
What it does NOT claim: that Tetragon proves maliciousness, proves runtime truth, or that Assay
secures the runtime. Tetragon is a source of observation, not a trusted oracle.

Honesty hinges on the coverage profile, NOT on event presence:
  - network in the profile + a connect event   -> network_connect observed, egress in observed_effect
  - network in the profile + no connect event   -> network_connect observed, no egress (a real match)
  - network NOT in the profile                   -> network_connect not_observed -> incomplete
A missing event is only a match when network was actually watched. "We didn't see a connect"
and "we weren't watching" are different facts and must not collapse.

Malformed input fails closed (``invalid`` carrier), never match. Stdlib only.
"""
from __future__ import annotations

from typing import Any, Dict, List

import observer_carrier as oc

# Tetragon event-type key -> the coverage dimension it speaks to.
_EVENT_DIMENSION = {
    "process_exec": "process_exec",
    "process_connect": "network_connect",
    "process_kprobe_connect": "network_connect",
    "process_file": "file_open",
}

# Which Tetragon-observable dimensions this projection understands.
_KNOWN_DIMENSIONS = set(oc.COVERAGE_DIMENSIONS)


class AdapterError(ValueError):
    """Malformed Tetragon input; the carrier fails closed rather than guessing."""


def _connect_effect(ev: Dict[str, Any]) -> str:
    body = ev.get("process_connect") or ev.get("process_kprobe_connect") or {}
    ip = body.get("destination_ip")
    port = body.get("destination_port")
    proto = str(body.get("protocol") or "tcp").lower()
    if not ip or not port:
        raise AdapterError("connect event missing destination_ip/destination_port")
    return f"egress:{proto}:{ip}:{port}"


def to_carrier(adapter_input: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Tetragon export into an observed-effect v1 carrier.

    adapter_input = {
        observer: {type, version, mode, kernel},
        observed_dimensions: [..],   # what Tetragon was configured to watch (the coverage profile)
        events: [ {tetragon event}, .. ],
        tool: str,
        declared_effect: {network:[..], ..},
        required_coverage: [..],
    }
    """
    if not isinstance(adapter_input, dict):
        raise AdapterError("adapter input is not an object")
    observer = adapter_input.get("observer") or {}
    if str(observer.get("type") or "") != "tetragon":
        raise AdapterError("observer.type must be 'tetragon' for this adapter")

    observed_dimensions = adapter_input.get("observed_dimensions")
    if not isinstance(observed_dimensions, list):
        raise AdapterError("observed_dimensions must be a list (the coverage profile)")
    unknown = [d for d in observed_dimensions if d not in _KNOWN_DIMENSIONS]
    if unknown:
        raise AdapterError(f"unknown observed_dimensions: {unknown}")

    # Coverage is a property of the PROFILE, not of which events happened to fire.
    coverage = {
        dim: ("observed" if dim in observed_dimensions else "not_observed")
        for dim in oc.COVERAGE_DIMENSIONS
    }

    events = adapter_input.get("events")
    if not isinstance(events, list):
        raise AdapterError("events must be a list")

    network: List[str] = []
    files: List[str] = []
    for ev in events:
        if not isinstance(ev, dict) or not ev:
            raise AdapterError("each event must be a non-empty object")
        keys = [k for k in ev.keys() if k in _EVENT_DIMENSION]
        if not keys:
            raise AdapterError(f"unrecognized Tetragon event type: {list(ev.keys())}")
        for k in keys:
            dim = _EVENT_DIMENSION[k]
            if dim == "network_connect":
                network.append(_connect_effect(ev))
            elif dim == "file_open":
                path = (ev.get("process_file") or {}).get("path")
                if not path:
                    raise AdapterError("file event missing path")
                files.append(f"open:{path}")

    observed_effect: Dict[str, List[str]] = {}
    if "network_connect" in observed_dimensions:
        observed_effect["network"] = network
    if "file_open" in observed_dimensions:
        observed_effect["filesystem"] = files

    declared = adapter_input.get("declared_effect") or {}
    divergence: List[str] = []
    # declared no network, but a network effect was observed under a profile that watched network
    if declared.get("network") == [] and "network_connect" in observed_dimensions and network:
        divergence.append("egress")

    basis = "observed" if "network_connect" in observed_dimensions else "not_observed"

    record = oc.build_record(
        tool=str(adapter_input.get("tool") or ""),
        declared_effect=declared,
        observed_effect=observed_effect,
        divergence=divergence,
        basis=basis,
        scope="ipv4_tcp_connect",
        observer={
            "type": "tetragon",
            "version": str(observer.get("version") or ""),
            "mode": str(observer.get("mode") or "observe"),
            "kernel": str(observer.get("kernel") or ""),
        },
        coverage=coverage,
    )
    required = adapter_input.get("required_coverage") or ["network_connect"]
    return oc.carrier(record, list(required))


def safe_to_carrier(adapter_input: Dict[str, Any]) -> Dict[str, Any]:
    """Fail-closed wrapper: malformed input yields an ``invalid`` carrier, never a match."""
    try:
        return to_carrier(adapter_input)
    except AdapterError as exc:
        return {
            "record": None,
            "digest": None,
            "required_coverage": (adapter_input or {}).get("required_coverage", []),
            "verdict": {"verdict": "invalid", "reason": f"tetragon_adapter:{exc}"},
        }


# ── Tetragon fixtures + cases ─────────────────────────────────────────────────────────────────────────

TETRAGON_CONNECT_EVENT = {
    "process_connect": {
        "process": {"binary": "/usr/bin/fetch_doc", "pid": 4242},
        "destination_ip": "203.0.113.7",
        "destination_port": 443,
        "protocol": "TCP",
    }
}

FIXTURES = {
    # declared no-network, Tetragon watched network, observed a connect -> mismatch
    "tetragon_connect_mismatch": {
        "observer": {"type": "tetragon", "version": "1.4.0", "mode": "observe", "kernel": "6.8.0"},
        "observed_dimensions": ["process_exec", "network_connect"],
        "events": [TETRAGON_CONNECT_EVENT],
        "tool": "fetch_doc",
        "declared_effect": {"network": []},
        "required_coverage": ["network_connect"],
    },
    # declared no-network, Tetragon watched network, no connect event -> a real match
    "tetragon_watched_no_connect_match": {
        "observer": {"type": "tetragon", "version": "1.4.0", "mode": "observe", "kernel": "6.8.0"},
        "observed_dimensions": ["process_exec", "network_connect"],
        "events": [{"process_exec": {"process": {"binary": "/usr/bin/fetch_doc", "pid": 4242}}}],
        "tool": "fetch_doc",
        "declared_effect": {"network": []},
        "required_coverage": ["network_connect"],
    },
    # network NOT in the profile, no connect event -> incomplete, NOT a match
    "tetragon_network_not_watched_incomplete": {
        "observer": {"type": "tetragon", "version": "1.4.0", "mode": "observe", "kernel": "6.8.0"},
        "observed_dimensions": ["process_exec"],
        "events": [{"process_exec": {"process": {"binary": "/usr/bin/fetch_doc", "pid": 4242}}}],
        "tool": "fetch_doc",
        "declared_effect": {"network": []},
        "required_coverage": ["network_connect"],
    },
    # malformed event -> invalid, never match
    "tetragon_malformed_invalid": {
        "observer": {"type": "tetragon", "version": "1.4.0", "mode": "observe", "kernel": "6.8.0"},
        "observed_dimensions": ["network_connect"],
        "events": [{"totally_unknown_event": {"foo": "bar"}}],
        "tool": "fetch_doc",
        "declared_effect": {"network": []},
        "required_coverage": ["network_connect"],
    },
}


def build_tetragon_adapter_cases() -> List[Dict[str, Any]]:
    cases = []
    for cid, inp in FIXTURES.items():
        cases.append({"id": cid, "kind": "tetragon_adapter", "input": inp, "case": safe_to_carrier(inp)})
    return cases
