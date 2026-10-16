from fastapi.testclient import TestClient
from .main import app
from .verify_falkordb import run_verification_suite

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["isolated_graphs"] >= 4
    assert data["mcp_tools_count"] >= 8


def test_track1_blast_radius():
    res = client.get("/api/track1/blast-radius?pr_id=PR-4821")
    assert res.status_code == 200
    data = res.json()
    assert data["root_service"] == "fx-settlement-ledger"
    assert data["requires_human_approval"] is True


def test_track2_handoff_and_consensus():
    res = client.post(
        "/api/track2/handoffs",
        json={
            "from_agent": "Sherlock-Triage",
            "to_agent": "CapyGuard-Auditor",
            "memory_type": "Episodic -> Procedural",
            "subgraph_lock": "sys_fx_ledger",
            "summary": "Unit test handoff",
        },
    )
    assert res.status_code == 200
    assert res.json()["handoff_id"].startswith("ho-")

    cons = client.get("/api/track2/swarm-consensus?incident_id=INC-9042")
    assert cons.status_code == 200
    assert cons.json()["quorum_reached"] is True


def test_track3_company_brain_and_v4_endpoints():
    res = client.post("/api/track3/ask", json={"question": "Which RFC docs are stale?"})
    assert res.status_code == 200
    assert "RFC-118" in res.json()["answer"]

    bf = client.get("/api/track3/bus-factor")
    assert bf.status_code == 200
    assert len(bf.json()["silo_risks"]) >= 3

    hyb = client.get("/api/v4/hybrid-vector-graph")
    assert hyb.status_code == 200
    assert hyb.json()["hybrid_results"][0]["rfc_id"] == "RFC-118"


def test_full_20_point_verification_suite():
    assert run_verification_suite() is True
