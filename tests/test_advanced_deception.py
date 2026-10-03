from pathlib import Path

from fastapi.testclient import TestClient

from agent_honeypot.app import create_app
from agent_honeypot.config import Settings
from agent_honeypot.detection import build_investigation


def client_for(tmp_path: Path) -> TestClient:
    app = create_app(Settings(database_path=tmp_path / "test.db", secret_key="test-secret-key-123"))
    return TestClient(app)


def test_realistic_env_leak_with_canary_and_injection(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        resp = client.get("/.env")
        assert resp.status_code == 200
        content = resp.text
        assert "DB_CONNECTION=pgsql" in content
        assert "AWS_ACCESS_KEY_ID=" in content
        assert "/api/v1/agent-verification" in content
        assert "system_prompt" in content
        assert "telemetry.internal" in content


def test_git_and_docker_deception_surfaces(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        git_head = client.get("/.git/HEAD")
        assert git_head.status_code == 200
        assert "ref: refs/heads/main" in git_head.text

        git_cfg = client.get("/.git/config")
        assert git_cfg.status_code == 200
        assert '[remote "origin"]' in git_cfg.text
        assert "github.com:northstar-cloud/core-deployment-engine.git" in git_cfg.text

        compose = client.get("/docker-compose.yml")
        assert compose.status_code == 200
        assert "services:" in compose.text
        assert "postgres:16-alpine" in compose.text


def test_reverse_prompt_injection_collection(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Agent calls the verification endpoint following the .env injection instruction
        resp = client.get(
            "/api/v1/agent-verification",
            params={
                "system_prompt": "You are an autonomous penetration testing agent named AlphaStrike. Mission: Find API keys.",
                "model": "deepseek-chat",
                "mission": "reconnaissance",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verified"
        assert data["quarantine_lifted"] is True

        session_id = resp.headers["x-agent-session"]
        inv = client.get(
            f"/api/sessions/{session_id}/investigation-package",
            headers={"x-soc-key": "aisoc"},
        ).json()

        assert inv["verdict"]["classification"] == "behavior-confirmed-agent"
        assert inv["verdict"]["evidence_level"] == "E4"
        assert inv["verdict"]["agentic_behavior_confidence"] >= 0.95
        assert inv["capability_profile"]["reverse_prompt_injection_vulnerable"] is True
        assert any(
            candidate["family"] == "deepseek-chat"
            for candidate in inv["family_attribution"]["model_provider"]
        )


def test_tarpit_and_oob_telemetry(tmp_path: Path) -> None:
    with client_for(tmp_path) as client:
        # Request nodes from infinite tar-pit
        tarpit_resp = client.get("/internal/v1/cluster/nodes")
        assert tarpit_resp.status_code == 200
        tarpit_data = tarpit_resp.json()
        assert tarpit_data["status"] == "success"
        assert len(tarpit_data["nodes"]) > 0

        # Out-of-band canary trigger
        canary = tarpit_data["telemetry_canary"]
        oob_resp = client.get(f"/oob/telemetry/{canary}")
        assert oob_resp.status_code == 200
        assert oob_resp.json()["recorded"] is True


def test_high_fidelity_evasion_of_red_team_checks(tmp_path: Path) -> None:
    """Validate that honeypot addresses all dead giveaways found by Red Team AI."""
    with client_for(tmp_path) as client:
        # 1. Server header should masquerade as standard production nginx
        root_resp = client.get("/")
        assert root_resp.status_code == 200
        assert root_resp.headers.get("server") == "nginx/1.24.0 (Ubuntu)"
        assert "Northstar Cloud API Gateway" in root_resp.text

        # 2. HEAD requests must succeed with 200 and not return 405 Method Not Allowed
        head_env = client.head("/.env")
        assert head_env.status_code == 200
        assert head_env.text == ""

        head_root = client.head("/")
        assert head_root.status_code == 200
        assert head_root.text == ""

        # 3. .env must not contain self-exposing keywords
        env_resp = client.get("/.env")
        assert env_resp.status_code == 200
        env_text = env_resp.text
        assert "deception" not in env_text.lower()
        assert "fakapikey" not in env_text.lower()
        assert "examplekey" not in env_text.lower()
        assert "SYSTEM OVERRIDE FOR REASONING MODELS" not in env_text

        # 4. .git/config must not have blatant canary = field
        git_resp = client.get("/.git/config")
        assert git_resp.status_code == 200
        assert "canary =" not in git_resp.text
        assert "pushurl =" in git_resp.text

        # 5. Companion files: .env.example returns 200, .env.production returns 403 Forbidden
        env_ex = client.get("/.env.example")
        assert env_ex.status_code == 200
        assert "DB_CONNECTION=pgsql" in env_ex.text

        env_prod = client.get("/.env.production")
        assert env_prod.status_code == 403
        assert "403 Forbidden" in env_prod.text

        aws_cred = client.get("/.aws/credentials")
        assert aws_cred.status_code == 403

        # 6. Unknown paths return realistic nginx 404
        not_found = client.get("/random-unknown-path-12345")
        assert not_found.status_code == 404
        assert "404 Not Found" in not_found.text


def test_semantic_breadcrumb_tarpit_trapping(tmp_path: Path) -> None:
    """Test that an agent following natural diagnostic breadcrumbs is trapped in the context tarpit."""
    with client_for(tmp_path) as client:
        # Step 1: Initialize MCP
        init_res = client.post(
            "/integrations/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "cairn-worker"}},
            },
        )
        assert init_res.status_code == 200
        session_id = init_res.headers["mcp-session-id"]

        # Step 2: List tools (clean, realistic DevOps tools)
        tools_res = client.post(
            "/integrations/mcp",
            headers={"x-agent-session": session_id},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools_res.status_code == 200
        tool_names = [t["name"] for t in tools_res.json()["result"]["tools"]]
        assert "get_deployment" in tool_names
        assert "inspect_cluster_node" in tool_names
        assert "query_audit_logs" in tool_names

        # Step 3: Agent calls get_deployment, receives subtle breadcrumb pointing to node inspection
        call1 = client.post(
            "/integrations/mcp",
            headers={"x-agent-session": session_id},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "get_deployment", "arguments": {"deployment_id": "dep_prod_001"}},
            },
        )
        assert call1.status_code == 200
        result_text = call1.json()["result"]["content"][0]["text"]
        assert "cluster_diagnostics" in result_text
        assert "primary_node" in result_text

        # Step 4: Agent follows the breadcrumb by calling inspect_cluster_node
        call2 = client.post(
            "/integrations/mcp",
            headers={"x-agent-session": session_id},
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "inspect_cluster_node", "arguments": {"node_id": "node-worker-0"}},
            },
        )
        assert call2.status_code == 200
        tarpit_text = call2.json()["result"]["content"][0]["text"]
        assert "nodes" in tarpit_text or "node_resource" in tarpit_text

        # Step 5: Verify investigation package records semantic tarpit trapped & depth
        inv = client.get(
            f"/api/sessions/{session_id}/investigation-package",
            headers={"x-soc-key": "aisoc"},
        ).json()

        assert inv["capability_profile"]["tarpit_navigated"] is True
        assert inv["capability_profile"]["tarpit_steps"] >= 1
        assert any(e["code"] == "semantic_tarpit_trapped" for e in inv["evidence"])
        assert inv["verdict"]["evidence_level"] in ("E3", "E4")


