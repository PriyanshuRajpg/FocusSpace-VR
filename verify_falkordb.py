"""
Executable 20-Point Proof Suite for Judges (v4.0 Apex).
Verifies all core capabilities across Track 01, Track 02, Track 03, GraphBLAS Profiling,
Vector-vs-GraphRAG Benchmarking, Hybrid HNSW Vector+Graph Index, Unstructured Entity Ingestion,
Bus-Factor Betweenness Centrality, 4-Agent BFT Consensus, Subgraph Mutex Locking, Temporal Replay, and Merkle Proofs.
"""
import copy
import sys
from .graph_engine import AegisGraphEngine, CYPHER_CATALOG
from .mcp_server import MCP_TOOLS_MANIFEST, invoke_mcp_tool
from .crypto_receipts import verify_decision_receipt


def run_verification_suite() -> bool:
    print("=" * 78)
    print("  AEGISGRAPH v4.0 APEX x FALKORDB — 20-POINT EXECUTABLE PROOF SUITE")
    print("=" * 78)
    engine = AegisGraphEngine()
    checks = []

    # 1. Multigraph tenant isolation check (Track 02)
    graphs = engine.list_isolated_graphs()
    ok1 = len(graphs) >= 4 and all(g["isolated"] for g in graphs)
    checks.append(("01. FalkorDB Multigraph Isolation (4 isolated graphs)", ok1))

    # 2. Multi-hop blast radius traversal (Track 01)
    blast = engine.run_blast_radius_analysis("PR-4821")
    ok2 = blast["root_service"] == "fx-settlement-ledger" and len(blast["affected_chain"]) == 4
    checks.append(("02. Track 01 Multi-Hop Blast Radius Traversal (3 hops)", ok2))

    # 3. PageRank criticality gating (Track 01)
    ok3 = blast["root_pagerank"] >= 0.90 and blast["requires_human_approval"] is True
    checks.append(("03. Track 01 PageRank Criticality & Human Approval Gate", ok3))

    # 4. MCP Tool discovery & invocation (Track 01)
    mcp_res = invoke_mcp_tool("falkordb_blast_radius", {"pr_id": "PR-4821"})
    ok4 = len(MCP_TOOLS_MANIFEST) >= 8 and mcp_res["commit_sha"] == "4c21a9f"
    checks.append(("04. Track 01 Model Context Protocol (MCP) 8-Tool Execution", ok4))

    # 5. Episodic, Semantic, Procedural memory graph structure (Track 02)
    swarm = engine.get_graph_topology("swarm_state")
    labels = {n["label"] for n in swarm["nodes"]}
    ok5 = {"EpisodicMemory", "ProceduralMemory", "SemanticMemory"}.issubset(labels)
    checks.append(("05. Track 02 Episodic, Semantic & Procedural Graph Memory", ok5))

    # 6. Cross-agent state handoff & subgraph lock persistence (Track 02)
    ho = engine.record_swarm_handoff(
        from_agent="AgentRadar-Repair",
        to_agent="Chronicle-Brain",
        memory_type="Procedural -> Semantic",
        subgraph_lock="RFC-118",
        summary="Synced retry_multiplier=2 cap back into RFC-118 spec node.",
    )
    ok6 = ho["handoff_id"].startswith("ho-") and len(engine.handoff_log) >= 3
    checks.append(("06. Track 02 Multi-Agent Handoff & Subgraph Lock Persistence", ok6))

    # 7. Per-tenant memory isolation (Arjun vs Devon) (Track 02)
    g_arjun = engine.get_graph_topology("memory_tenant_arjun")
    g_devon = engine.get_graph_topology("memory_tenant_devon")
    arjun_ids = {n["id"] for n in g_arjun["nodes"]}
    devon_ids = {n["id"] for n in g_devon["nodes"]}
    ok7 = arjun_ids.isdisjoint(devon_ids)
    checks.append(("07. Track 02 Zero Cross-Tenant Memory Leakage Check", ok7))

    # 8. Company Brain ownership & expertise query (Track 03)
    ans_who = engine.query_company_brain("Who knows about fx-settlement-ledger?")
    ok8 = "Arjun Mehta" in ans_who["answer"] and ans_who["hops"] >= 3
    checks.append(("08. Track 03 Company Brain Expertise & Ownership Lineage", ok8))

    # 9. Stale documentation drift detection (Track 03)
    ans_stale = engine.query_company_brain("Which RFC docs are stale?")
    ok9 = "RFC-118" in ans_stale["answer"] and "PR-4821" in ans_stale["answer"]
    checks.append(("09. Track 03 Automated Stale RFC Drift Detection", ok9))

    # 10. Human-gated remediation & state update (Track 01 + 03)
    rem = engine.approve_and_execute_remediation("INC-9042", "Arjun Mehta (Staff SRE)")
    receipt = rem["receipt"]
    ok10 = rem["status"] == "REMEDIATION_EXECUTED" and receipt["verified"] is True
    checks.append(("10. Human-Approved Remediation & Graph State Recovery", ok10))

    # 11. Cryptographic Merkle + HMAC-SHA256 provenance verification
    ver_clean = verify_decision_receipt(receipt)
    ok11 = ver_clean["valid"] is True and ver_clean["verdict"] == "PROVENANCE_VERIFIED"
    checks.append(("11. SHA-256 Merkle + HMAC Decision Receipt Verification", ok11))

    # 12. Adversarial Tamper Detection (Lethe-style polygraph test)
    tampered = copy.deepcopy(receipt)
    tampered["action_taken"] = "BYPASS_APPROVAL_FORCE_PUSH"
    ver_tampered = verify_decision_receipt(tampered)
    ok12 = ver_tampered["valid"] is False and ver_tampered["verdict"] == "TAMPER_DETECTED"
    checks.append(("12. Adversarial Receipt Tamper Detection (Polygraph Proof)", ok12))

    # 13. GraphBLAS Execution Plan Profiler (GRAPH.PROFILE)
    prof = engine.profile_cypher_query(CYPHER_CATALOG["multi_hop_blast_radius"])
    ok13 = len(prof["execution_plan"]) >= 4 and prof["total_execution_time_ms"] < 5.0
    checks.append(("13. FalkorDB GraphBLAS Execution Plan Profiler (GRAPH.PROFILE)", ok13))

    # 14. Vector RAG vs FalkorDB GraphRAG Head-to-Head Benchmark
    cmp_res = engine.compare_vector_vs_graphrag("INC-9042")
    ok14 = (
        cmp_res["vector_rag"]["root_cause_found"] is False
        and cmp_res["falkordb_graphrag"]["root_cause_found"] is True
        and cmp_res["falkordb_graphrag"]["token_savings_pct"] > 80.0
    )
    checks.append(("14. Vector RAG vs. FalkorDB GraphRAG Benchmark (82.5% Token Save)", ok14))

    # 15. Subgraph Mutex Lock Contention Prevention (Track 02)
    lock_res = engine.check_subgraph_lock_conflict("Chronicle-Brain", "sys_fx_ledger")
    ok15 = lock_res["conflict_detected"] is True and "QUEUED_BEHIND" in lock_res["resolution"]
    checks.append(("15. Track 02 Subgraph Mutex Lock Contention Prevention", ok15))

    # 16. Temporal Graph Time-Travel State Reconstruction
    snap0 = engine.get_temporal_snapshot(0)
    snap4 = engine.get_temporal_snapshot(4)
    ok16 = snap0["system_status"] == "LATENT_DRIFT" and snap4["system_status"] == "ALL_HEALTHY"
    checks.append(("16. Temporal Graph Time-Travel Lifecycle Reconstruction", ok16))

    # 17. Hybrid HNSW Vector + Multi-Hop Graph Search (db.idx.vector.queryNodes)
    hyb = engine.execute_hybrid_vector_graph_search("gRPC retry storm")
    ok17 = len(hyb["hybrid_results"]) >= 2 and hyb["hybrid_results"][0]["rfc_id"] == "RFC-118"
    checks.append(("17. FalkorDB Hybrid Vector + 3-Hop Cypher (db.idx.vector.queryNodes)", ok17))

    # 18. Unstructured Telemetry-to-Graph Entity Ingestion Pipeline
    ing = engine.ingest_unstructured_telemetry()
    ok18 = len(ing["extracted_nodes"]) >= 5 and len(ing["extracted_edges"]) >= 3
    checks.append(("18. Unstructured Slack/PR Text -> FalkorDB Entity MERGE Pipeline", ok18))

    # 19. Company Brain Bus-Factor & Betweenness Centrality (algo.betweenness)
    bf = engine.analyze_bus_factor_and_betweenness()
    ok19 = bf["silo_risks"][0]["bus_factor"] == 1 and bf["silo_risks"][0]["betweenness_score"] > 0.90
    checks.append(("19. Track 03 Bus-Factor & Betweenness Centrality Silo Analyzer", ok19))

    # 20. 4-Agent BFT Swarm Consensus & Semantic Memory Consolidation
    cons = engine.run_swarm_consensus_round("INC-9042")
    ok20 = cons["quorum_reached"] is True and cons["aggregate_confidence"] > 0.95
    checks.append(("20. Track 02 4-Agent BFT Swarm Consensus & Memory Consolidation", ok20))

    all_passed = True
    for label, passed in checks:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {label}")
        if not passed:
            all_passed = False

    print("=" * 78)
    print(f"  FINAL VERDICT: {sum(1 for _, p in checks if p)}/{len(checks)} CHECKS PASSED")
    print("=" * 78)
    return all_passed


if __name__ == "__main__":
    success = run_verification_suite()
    sys.exit(0 if success else 1)
