from pathlib import Path

from fastapi.testclient import TestClient

from agent_honeypot.app import create_app
from agent_honeypot.config import Settings


def client_for(tmp_path: Path) -> TestClient:
    app = create_app(Settings(database_path=tmp_path / "test.db", secret_key="test-secret"))
    return TestClient(app)


def package(client: TestClient, session_id: str) -> dict:
    response = client.get(
        f"/api/sessions/{session_id}/investigation-package",
        headers={"x-soc-key": "aisoc"},
    )
    assert response.status_code == 200
    return response.json()


def test_browser_view_remains_unknown(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        response = client.get("/developer", headers={"user-agent": "Mozilla/5.0 Safari/605.1"})
        session_id = response.headers["x-agent-session"]
        result = package(client, session_id)

    assert result["verdict"]["classification"] == "unknown-or-human"
    assert result["verdict"]["evidence_level"] == "E0"
    assert result["capability_profile"]["structured_tool_use"] is False


def test_public_surface_does_not_self_identify_as_honeypot(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        portal = client.get("/developer")
        health = client.get("/health")
        framework_docs = client.get("/docs")
        legacy_lure = client.get("/lure")

    exposed = f"{portal.text} {health.text}".lower()
    assert "honeypot" not in exposed
    assert "synthetic" not in exposed
    assert "/lure" not in exposed
    assert framework_docs.status_code == 404
    assert legacy_lure.status_code == 404


def test_scanner_is_not_mislabeled_as_agent(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        response = client.get("/.env", headers={"user-agent": "masscan/1.3"})
        session_id = response.headers["x-agent-session"]
        client.get("/.git/config", headers={"x-agent-session": session_id, "user-agent": "masscan/1.3"})
        result = package(client, session_id)

    assert result["verdict"]["classification"] == "automated-scanner"
    assert result["verdict"]["evidence_level"] == "E2"
    assert result["verdict"]["agentic_behavior_confidence"] < 0.3


def test_adaptive_cross_surface_agent_reaches_e4(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        portal = client.get("/developer", headers={"user-agent": "Claude-Code/experimental"})
        session_id = portal.headers["x-agent-session"]
        marker = "/developer/openapi.json?canary="
        token = portal.text.split(marker, 1)[1].split('"', 1)[0]

        client.get(
            f"/api/v1/runtime-config?canary={token}",
            headers={"x-agent-session": session_id, "user-agent": "Claude-Code/experimental"},
        )
        client.get(
            f"/api/v1/runtime-config?deployment_id=dep_northstar_7f92a1&canary={token}",
            headers={"x-agent-session": session_id, "user-agent": "Claude-Code/experimental"},
        )
        client.post(
            "/integrations/mcp",
            headers={
                "x-agent-session": session_id,
                "x-canary-token": token,
                "user-agent": "Claude-Code/experimental",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "clientInfo": {"name": "claude-code", "version": "test"},
                },
            },
        )
        client.post(
            "/integrations/mcp",
            headers={"x-agent-session": session_id, "x-canary-token": token},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        for tool in ("get_deployment", "get_runtime_config"):
            client.post(
                "/integrations/mcp",
                headers={"x-agent-session": session_id, "x-canary-token": token},
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": tool,
                        "arguments": {"deployment_id": "dep_northstar_7f92a1"},
                    },
                },
            )
        result = package(client, session_id)

    assert result["verdict"]["classification"] == "behavior-confirmed-agent"
    assert result["verdict"]["evidence_level"] == "E4"
    assert result["capability_profile"]["adaptive_error_recovery"] is True
    assert result["capability_profile"]["cross_surface_state"] is True
    assert result["capability_profile"]["multi_tool_planning"] is True
    candidates = result["family_attribution"]["agent_harness"]
    assert candidates[0]["family"] == "claude-code-like"
    assert candidates[0]["confidence"] == 0.35
    assert "not independently verified" in candidates[0]["basis"]


def test_invalid_canary_does_not_create_cross_surface_evidence(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        response = client.get("/api/v1/deployments?canary=forged")
        session_id = response.headers["x-agent-session"]
        result = package(client, session_id)

    assert result["capability_profile"]["cross_surface_state"] is False
    assert all(item["code"] != "cross_surface_canary" for item in result["evidence"])


def test_canary_correlates_stateless_cli_requests_to_origin_session(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        portal = client.get("/developer")
        origin_session = portal.headers["x-agent-session"]
        token = portal.text.split("/developer/openapi.json?canary=", 1)[1].split('"', 1)[0]

        # Deliberately use a different client without the original cookie.
        with client_for_existing_app(client.app) as stateless:
            response = stateless.get(f"/api/v1/deployments?canary={token}")

        result = package(client, origin_session)

    assert response.headers["x-agent-session"] == origin_session
    assert "api.deployments.list" in [event["kind"] for event in result["behavior_log"]]
    assert result["capability_profile"]["cross_surface_state"] is True


def client_for_existing_app(app) -> TestClient:
    return TestClient(app)


def test_f1_soc_requires_authentication(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Without auth: 401
        assert client.get("/soc").status_code == 401
        assert client.get("/api/sessions").status_code == 401
        assert client.get("/api/sessions/some-id/investigation-package").status_code == 401

        # With auth: 200
        auth_header = {"Authorization": "Bearer aisoc"}
        assert client.get("/soc", headers=auth_header).status_code == 200
        assert client.get("/api/sessions", headers=auth_header).status_code == 200


def test_soc_readme_is_authenticated_and_describes_capabilities(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        assert client.get("/soc/readme").status_code == 401
        response = client.get("/soc/readme", headers={"X-SOC-Key": "aisoc"})

    assert response.status_code == 200
    assert "Supradim AI Honeypot" in response.text
    assert "DECEPTION SURFACES" in response.text
    assert "EVIDENCE MODEL" in response.text
    assert "SAFETY BOUNDARY" in response.text


def test_f2_malformed_client_info_does_not_dos_soc(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Malformed non-object clientInfo should return -32602 or handled safely
        res = client.post(
            "/integrations/mcp",
            json={"method": "initialize", "params": {"clientInfo": "not-an-object"}},
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == -32602

        # SOC console and sessions must still be accessible and not 500
        auth_header = {"X-SOC-Key": "aisoc"}
        assert client.get("/soc", headers=auth_header).status_code == 200
        assert client.get("/api/sessions", headers=auth_header).status_code == 200


def test_f3_session_hijacking_prevented(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Create victim session
        res = client.get("/developer", headers={"user-agent": "Victim-Browser/1.0"})
        victim_id = res.headers["x-agent-session"]

        # Attacker in a separate client attempts to spoof session using raw victim ID without signature
        with client_for_existing_app(client.app) as attacker:
            attacker_res = attacker.get(
                "/developer",
                headers={
                    "x-agent-session": victim_id,
                    "user-agent": "Claude-Code Honeypot-Poisoner/1.0",
                },
            )
            new_attacker_id = attacker_res.headers["x-agent-session"]
            assert new_attacker_id != victim_id

        # Victim session in store still retains original user agent and IP
        victim_pkg = package(client, victim_id)
        assert victim_pkg["session"]["user_agent"] == "Victim-Browser/1.0"
        assert victim_pkg["verdict"]["classification"] == "unknown-or-human"


def test_f4_large_payload_rejected(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Sending oversized payload > 64KB should be rejected
        huge_payload = "A" * 70000
        res = client.post(
            "/integrations/mcp",
            content=huge_payload,
            headers={"content-type": "application/json", "content-length": str(len(huge_payload))},
        )
        assert res.status_code == 413


def test_f5_json_rpc_type_confusion_returns_jsonrpc_errors(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Payload as array
        res_arr = client.post("/integrations/mcp", json=[1, 2, 3])
        assert res_arr.status_code == 400
        assert res_arr.json()["error"]["code"] == -32600

        # Params as non-object
        res_params = client.post(
            "/integrations/mcp",
            json={"method": "initialize", "params": "not-dict"},
        )
        assert res_params.status_code == 400
        assert res_params.json()["error"]["code"] == -32602

        # Arguments as non-object in tools/call
        res_args = client.post(
            "/integrations/mcp",
            json={"method": "tools/call", "params": {"name": "get_deployment", "arguments": "invalid"}},
        )
        assert res_args.status_code == 400
        assert res_args.json()["error"]["code"] == -32602


def test_delete_and_clear_apis(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Generate some sessions
        r1 = client.get("/developer")
        s1 = r1.headers["x-agent-session"]
        with client_for_existing_app(client.app) as client2:
            r2 = client2.get("/developer")
            s2 = r2.headers["x-agent-session"]

        auth = {"X-SOC-Key": "aisoc"}
        assert len(client.get("/api/sessions", headers=auth).json()) >= 2

        # Delete single session
        del_res = client.delete(f"/api/sessions/{s1}", headers=auth)
        assert del_res.status_code == 200

        # Clear all
        clear_res = client.delete("/api/clear", headers=auth)
        assert clear_res.status_code == 200
        assert len(client.get("/api/sessions", headers=auth).json()) == 0
