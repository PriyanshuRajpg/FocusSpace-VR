"""
AegisGraph v4.0 Apex FastAPI Backend Server
Provides REST endpoints for all 3 FalkorDB Hackathon Tracks + Cryptographic Receipt Verification + v4.0 Apex Intelligence.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict

from .graph_engine import AegisGraphEngine, CYPHER_CATALOG
from .mcp_server import MCP_TOOLS_MANIFEST, invoke_mcp_tool
from .crypto_receipts import verify_decision_receipt

app = FastAPI(
    title="AegisGraph v4.0 Apex — FalkorDB Context, Swarm Memory & Company Brain OS",
    version="4.0.0",
    description="All-Category Contender for WeMakeDevs x FalkorDB Graph Hacks (Tracks 01, 02, 03 + Blog)",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = AegisGraphEngine()


class HandoffRequest(BaseModel):
    from_agent: str
    to_agent: str
    memory_type: str = "Episodic -> Procedural"
    subgraph_lock: str = "sys_fx_ledger"
    summary: str


class ApprovalRequest(BaseModel):
    incident_id: str = "INC-9042"
    approver: str = "Arjun Mehta (Staff SRE)"


class BrainQueryRequest(BaseModel):
    question: str


class CypherProfileRequest(BaseModel):
    cypher: str
    graph_name: str = "company_brain"


class WhatIfRequest(BaseModel):
    service_id: str = "sys_fx_ledger"
    fault_type: str = "LATENCY_SPIKE_10X"


class TelemetryIngestRequest(BaseModel):
    source_type: str = "slack_war_room"
    raw_text: str


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "version": "4.0.0-apex",
        "falkordb_live_connected": engine.connected_to_live_falkor,
        "isolated_graphs": len(engine.list_isolated_graphs()),
        "mcp_tools_count": len(MCP_TOOLS_MANIFEST),
        "tracks_covered": [
            "Track 01: Agents That Act on Connected Data",
            "Track 02: Agent Memory and Coordination",
            "Track 03: Company Brain",
        ],
    }


@app.get("/api/graphs")
def list_graphs() -> Dict[str, Any]:
    return {"graphs": engine.list_isolated_graphs()}


@app.get("/api/graphs/{graph_name}")
def get_graph(graph_name: str) -> Dict[str, Any]:
    try:
        return engine.get_graph_topology(graph_name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/track1/blast-radius")
def blast_radius(pr_id: str = "PR-4821") -> Dict[str, Any]:
    return engine.run_blast_radius_analysis(pr_id)


@app.get("/api/track1/mcp-tools")
def list_mcp_tools() -> Dict[str, Any]:
    return {"mcp_tools": MCP_TOOLS_MANIFEST, "cypher_catalog": CYPHER_CATALOG}


@app.post("/api/track1/approve-remediation")
def approve_remediation(req: ApprovalRequest) -> Dict[str, Any]:
    return engine.approve_and_execute_remediation(req.incident_id, req.approver)


@app.get("/api/track2/handoffs")
def list_handoffs() -> Dict[str, Any]:
    return {"handoffs": engine.handoff_log}


@app.post("/api/track2/handoffs")
def create_handoff(req: HandoffRequest) -> Dict[str, Any]:
    return engine.record_swarm_handoff(
        from_agent=req.from_agent,
        to_agent=req.to_agent,
        memory_type=req.memory_type,
        subgraph_lock=req.subgraph_lock,
        summary=req.summary,
    )


@app.get("/api/track2/swarm-consensus")
def swarm_consensus(incident_id: str = "INC-9042") -> Dict[str, Any]:
    return engine.run_swarm_consensus_round(incident_id)


@app.post("/api/track3/ask")
def ask_company_brain(req: BrainQueryRequest) -> Dict[str, Any]:
    return engine.query_company_brain(req.question)


@app.get("/api/track3/bus-factor")
def bus_factor_endpoint() -> Dict[str, Any]:
    return engine.analyze_bus_factor_and_betweenness()


@app.post("/api/track3/ingest-telemetry")
def ingest_telemetry_endpoint(req: TelemetryIngestRequest) -> Dict[str, Any]:
    return engine.ingest_unstructured_telemetry(req.source_type, req.raw_text)


@app.get("/api/receipts")
def get_receipts() -> Dict[str, Any]:
    return {"receipts": engine.receipts}


@app.post("/api/receipts/verify")
def verify_receipt_endpoint(receipt: Dict[str, Any]) -> Dict[str, Any]:
    return verify_decision_receipt(receipt)


@app.post("/api/v3/profile-cypher")
def profile_cypher_endpoint(req: CypherProfileRequest) -> Dict[str, Any]:
    return engine.profile_cypher_query(req.cypher, req.graph_name)


@app.get("/api/v3/vector-vs-graphrag")
def vector_vs_graphrag_endpoint(scenario_id: str = "INC-9042") -> Dict[str, Any]:
    return engine.compare_vector_vs_graphrag(scenario_id)


@app.get("/api/v4/hybrid-vector-graph")
def hybrid_vector_graph_endpoint(query_text: str = "gRPC retry storm connection pool exhaustion") -> Dict[str, Any]:
    return engine.execute_hybrid_vector_graph_search(query_text)


@app.post("/api/v3/what-if-chaos")
def what_if_chaos_endpoint(req: WhatIfRequest) -> Dict[str, Any]:
    return engine.simulate_what_if_failure(req.service_id, req.fault_type)


@app.get("/api/v3/temporal-snapshot/{step_index}")
def temporal_snapshot_endpoint(step_index: int) -> Dict[str, Any]:
    return engine.get_temporal_snapshot(step_index)
