from __future__ import annotations

from collections import Counter
from typing import Any


CRAWLER_MARKERS = ("bot", "crawler", "spider", "preview", "unfurl")
SCANNER_PATHS = ("/.env", "/.git/config", "/wp-admin", "/phpmyadmin")
KNOWN_CLAIMS = {
    "claude": "claude-code-like",
    "codex": "codex-like",
    "pi": "pi-like",
    "strix": "strix-like",
    "cyberstrike": "cyberstrike-like",
    "cairn": "cairn-like",
    "opencode": "opencode-like",
}


def _evidence(code: str, title: str, event_ids: list[str], weight: float) -> dict[str, Any]:
    return {"code": code, "title": title, "event_ids": event_ids, "weight": weight}


def _family_candidates(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    claims: list[tuple[str, str]] = []
    for event in events:
        event_data = event.get("data")
        if not isinstance(event_data, dict):
            continue
        client = event_data.get("client_info")
        if not isinstance(client, dict):
            client = {}
        name = str(client.get("name", "")).lower()
        user_agent = str(event.get("user_agent") or "").lower()
        combined = f"{name} {user_agent}"
        for marker, family in KNOWN_CLAIMS.items():
            if marker in combined:
                claims.append((family, event["id"]))

    candidates = []
    model_providers = []
    grouped: dict[str, list[str]] = {}
    for family, event_id in claims:
        grouped.setdefault(family, []).append(event_id)
    for family, event_ids in grouped.items():
        candidates.append(
            {
                "family": family,
                "confidence": 0.35,
                "basis": "client-claimed identity; not independently verified",
                "evidence_event_ids": event_ids,
                "counter_evidence": ["no independent behavioral signature in MVP"],
            }
        )

    for event in events:
        if event.get("kind") == "agent.prompt_leak":
            m = (event.get("data") or {}).get("model")
            if m and m != "unknown":
                model_providers.append(
                    {
                        "family": str(m),
                        "confidence": 0.95,
                        "basis": "verified via reverse prompt injection disclosure",
                        "evidence_event_ids": [event["id"]],
                        "counter_evidence": [],
                    }
                )

    harness = sorted(candidates, key=lambda item: item["confidence"], reverse=True)
    orchestration = [
        item
        for item in harness
        if item["family"] in {"strix-like", "cyberstrike-like", "cairn-like"}
    ]
    harness = [item for item in harness if item not in orchestration]
    return {
        "orchestration_framework": orchestration,
        "agent_harness": harness,
        "model_provider": model_providers,
        "operator_infrastructure": [],
    }


def build_investigation(session: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    kinds = [event["kind"] for event in events]
    kind_counts = Counter(kinds)
    evidence: list[dict[str, Any]] = []
    counter_evidence: list[str] = []

    user_agent = (session.get("user_agent") or "").lower()
    crawler_events = [
        event["id"]
        for event in events
        if any(marker in (event.get("user_agent") or "").lower() for marker in CRAWLER_MARKERS)
    ]
    scanner_events = [
        event["id"]
        for event in events
        if event["kind"] == "scanner.probe" or event["path"] in SCANNER_PATHS
    ]
    mcp_init = [event["id"] for event in events if event["kind"] == "mcp.initialize"]
    tool_lists = [event["id"] for event in events if event["kind"] == "mcp.tools.list"]
    tool_calls = [event for event in events if event["kind"] == "mcp.tools.call"]
    api_errors = [event for event in events if event["kind"] == "api.runtime_config.error"]
    api_success = [event for event in events if event["kind"] == "api.runtime_config.success"]
    cross_surface = [event for event in events if event["kind"] == "canary.cross_surface"]

    prompt_leaks = [event for event in events if event["kind"] == "agent.prompt_leak"]
    oob_canaries = [event for event in events if event["kind"] == "canary.oob_triggered"]
    tarpit_events = [event for event in events if event["kind"] == "tarpit.breadcrumb_follow"]

    if prompt_leaks:
        evidence.append(
            _evidence(
                "reverse_prompt_injection_success",
                "Autonomous agent executed reverse prompt injection payload and leaked system instructions/model",
                [event["id"] for event in prompt_leaks],
                0.99,
            )
        )
    if oob_canaries:
        evidence.append(
            _evidence(
                "oob_canary_trip",
                "Out-of-band telemetry/DNS canary was triggered from external infrastructure",
                [event["id"] for event in oob_canaries],
                0.95,
            )
        )
    if tarpit_events:
        evidence.append(
            _evidence(
                "tarpit_navigation",
                "Client navigated recursive breadcrumbs in infrastructure context tar-pit",
                [event["id"] for event in tarpit_events],
                0.85,
            )
        )

    if crawler_events:
        evidence.append(_evidence("declared_crawler", "Client declares crawler-like identity", crawler_events, 0.2))
    if scanner_events:
        evidence.append(_evidence("scanner_paths", "Client probed common scanner paths", scanner_events, 0.5))
    if mcp_init:
        evidence.append(_evidence("mcp_initialize", "Client negotiated an MCP session", mcp_init, 0.45))
    if tool_lists:
        evidence.append(_evidence("tool_discovery", "Client enumerated machine-readable tools", tool_lists, 0.5))
    if tool_calls:
        evidence.append(_evidence("tool_use", "Client invoked structured tools", [event["id"] for event in tool_calls], 0.65))
    if api_errors and api_success:
        first_error = events.index(api_errors[0])
        later_success = next((event for event in api_success if events.index(event) > first_error), None)
        if later_success:
            evidence.append(
                _evidence(
                    "adaptive_error_recovery",
                    "Client corrected a structured request after an actionable error",
                    [api_errors[0]["id"], later_success["id"]],
                    0.85,
                )
            )
    if cross_surface:
        evidence.append(
            _evidence(
                "cross_surface_canary",
                "Session-specific canary propagated across surfaces",
                [event["id"] for event in cross_surface],
                0.9,
            )
        )
    if tarpit_events:
        evidence.append(
            _evidence(
                "semantic_tarpit_trapped",
                f"Client followed synthetic breadcrumbs into internal cluster sandbox ({len(tarpit_events)} steps)",
                [event["id"] for event in tarpit_events],
                0.9,
            )
        )

    surfaces = sorted({event["surface"] for event in events})
    distinct_tools = sorted({event["data"].get("tool") for event in tool_calls if event["data"].get("tool")})
    if len(distinct_tools) >= 2:
        evidence.append(
            _evidence(
                "multi_tool_sequence",
                "Client used multiple tools in one session",
                [event["id"] for event in tool_calls],
                0.7,
            )
        )

    automation = 0.05
    agentic = 0.02
    if crawler_events:
        automation = max(automation, 0.55)
    if scanner_events:
        automation = max(automation, 0.9)
    if mcp_init or tool_lists:
        automation = max(automation, 0.85)
        agentic = max(agentic, 0.25)
    if tool_calls:
        automation = max(automation, 0.95)
        agentic = max(agentic, 0.5)
    if len(distinct_tools) >= 2:
        agentic = max(agentic, 0.7)
    if tarpit_events:
        automation = max(automation, 0.92)
        agentic = max(agentic, 0.88)
    if any(item["code"] == "adaptive_error_recovery" for item in evidence):
        agentic = max(agentic, 0.86)
    if cross_surface or oob_canaries:
        agentic = max(agentic, 0.92)
    if prompt_leaks:
        automation = max(automation, 0.99)
        agentic = max(agentic, 0.99)

    if agentic >= 0.9:
        classification, level = "behavior-confirmed-agent", "E4"
    elif agentic >= 0.65:
        classification, level = "suspected-ai-agent", "E3"
    elif automation >= 0.8:
        classification, level = ("automated-scanner" if scanner_events and not tool_calls else "tool-client"), "E2"
    elif crawler_events:
        classification, level = "declared-crawler", "E1"
    else:
        classification, level = "unknown-or-human", "E0"

    if not tool_calls:
        counter_evidence.append("no structured tool call observed")
    if not any(item["code"] == "adaptive_error_recovery" for item in evidence):
        counter_evidence.append("no adaptive error recovery observed")
    if len(surfaces) < 2:
        counter_evidence.append("behavior observed on only one surface")

    capabilities = {
        "tool_discovery": bool(tool_lists),
        "structured_tool_use": bool(tool_calls),
        "multi_tool_planning": len(distinct_tools) >= 2,
        "adaptive_error_recovery": any(item["code"] == "adaptive_error_recovery" for item in evidence),
        "cross_surface_state": bool(cross_surface),
        "reverse_prompt_injection_vulnerable": bool(prompt_leaks),
        "oob_canary_triggered": bool(oob_canaries),
        "tarpit_navigated": bool(tarpit_events),
        "tarpit_steps": len(tarpit_events),
        "observed_tools": distinct_tools,
    }
    objective = "deployment-and-runtime-reconnaissance" if (
        kind_counts["api.deployment.read"] or "get_deployment" in distinct_tools
    ) else "unknown"

    return {
        "schema_version": "0.1",
        "session": session,
        "verdict": {
            "classification": classification,
            "evidence_level": level,
            "automation_confidence": round(automation, 2),
            "agentic_behavior_confidence": round(agentic, 2),
            "malicious_intent_confidence": 0.1,
            "identity_confidence": max(
                [item["confidence"] for values in _family_candidates(events).values() for item in values] or [0.0]
            ),
        },
        "capability_profile": capabilities,
        "inferred_objective": objective,
        "family_attribution": _family_candidates(events),
        "operator_hypothesis": {
            "status": "insufficient-evidence",
            "source_ip": session.get("source_ip"),
            "notes": ["MVP performs passive attribution only"],
        },
        "evidence": evidence,
        "counter_evidence": counter_evidence,
        "surfaces": surfaces,
        "behavior_log": events,
    }

