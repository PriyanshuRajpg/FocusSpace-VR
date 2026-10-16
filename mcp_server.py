"""
AegisGraph Model Context Protocol (MCP) Server for Track 01, Track 02 & Track 03 (v4.0 Apex).
Exposes FalkorDB Cypher traversals, GraphBLAS execution profiling, PageRank, Hybrid HNSW Vector+Graph search,
Unstructured Entity Extraction, Bus-Factor Betweenness Centrality, and Swarm Consensus as standardized MCP tools.
"""
from typing import Any, Dict, List
from .graph_engine import AegisGraphEngine, CYPHER_CATALOG

engine = AegisGraphEngine()

MCP_TOOLS_MANIFEST: List[Dict[str, Any]] = [
    {
        "name": "falkordb_blast_radius",
        "description": "Run multi-hop dependency traversal and PageRank criticality scoring in FalkorDB to trace the blast radius of a PR or service outage.",
        "inputSchema": {
            "type": "object",
            "properties": {"pr_id": {"type": "string", "default": "PR-4821"}},
            "required": ["pr_id"],
        },
    },
    {
        "name": "falkordb_who_knows_system",
        "description": "Query the Company Brain graph in FalkorDB to find engineers who own, committed to, or authored RFCs for a system.",
        "inputSchema": {
            "type": "object",
            "properties": {"system_name": {"type": "string", "default": "fx-settlement-ledger"}},
            "required": ["system_name"],
        },
    },
    {
        "name": "falkordb_swarm_handoff",
        "description": "Persist a multi-agent state handoff and subgraph lock into FalkorDB's swarm_state coordination graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_agent": {"type": "string"},
                "to_agent": {"type": "string"},
                "memory_type": {"type": "string"},
                "subgraph_lock": {"type": "string"},
                "summary": {"type": "string"},
            },
            "required": ["from_agent", "to_agent", "summary"],
        },
    },
    {
        "name": "falkordb_detect_stale_docs",
        "description": "Detect architecture RFCs and docs in FalkorDB that have drifted from recent merged pull requests.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "falkordb_profile_cypher",
        "description": "Execute and profile an OpenCypher query on FalkorDB with GraphBLAS sparse-matrix operator timing breakdown.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cypher": {"type": "string"},
                "graph_name": {"type": "string", "default": "company_brain"},
            },
            "required": ["cypher"],
        },
    },
    {
        "name": "falkordb_what_if_chaos_sim",
        "description": "Simulate a service failure in FalkorDB and compute multi-hop downstream SLA burn rate and PageRank gate status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_id": {"type": "string", "default": "sys_fx_ledger"},
                "fault_type": {"type": "string", "default": "LATENCY_SPIKE_10X"},
            },
            "required": ["service_id"],
        },
    },
    {
        "name": "falkordb_hybrid_vector_graph_search",
        "description": "Execute FalkorDB HNSW vector index search (db.idx.vector.queryNodes) combined with 3-hop Cypher graph traversal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query_text": {"type": "string", "default": "gRPC retry storm connection pool exhaustion"},
            },
            "required": ["query_text"],
        },
    },
    {
        "name": "falkordb_bus_factor_betweenness",
        "description": "Compute algo.betweenness centrality and commit ownership concentration to identify Bus-Factor=1 SPOF silos.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def invoke_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if tool_name == "falkordb_blast_radius":
        return engine.run_blast_radius_analysis(arguments.get("pr_id", "PR-4821"))
    if tool_name == "falkordb_who_knows_system":
        sys_name = arguments.get("system_name", "fx-settlement-ledger")
        return engine.query_company_brain(f"Who knows about {sys_name}?")
    if tool_name == "falkordb_swarm_handoff":
        return engine.record_swarm_handoff(
            from_agent=arguments["from_agent"],
            to_agent=arguments["to_agent"],
            memory_type=arguments.get("memory_type", "Episodic -> Procedural"),
            subgraph_lock=arguments.get("subgraph_lock", "sys_fx_ledger"),
            summary=arguments["summary"],
        )
    if tool_name == "falkordb_detect_stale_docs":
        return engine.query_company_brain("Which RFCs or docs are stale?")
    if tool_name == "falkordb_profile_cypher":
        return engine.profile_cypher_query(
            cypher=arguments.get("cypher", CYPHER_CATALOG["multi_hop_blast_radius"]),
            graph_name=arguments.get("graph_name", "company_brain"),
        )
    if tool_name == "falkordb_what_if_chaos_sim":
        return engine.simulate_what_if_failure(
            service_id=arguments.get("service_id", "sys_fx_ledger"),
            fault_type=arguments.get("fault_type", "LATENCY_SPIKE_10X"),
        )
    if tool_name == "falkordb_hybrid_vector_graph_search":
        return engine.execute_hybrid_vector_graph_search(
            query_text=arguments.get("query_text", "gRPC retry storm connection pool exhaustion")
        )
    if tool_name == "falkordb_bus_factor_betweenness":
        return engine.analyze_bus_factor_and_betweenness()
    raise ValueError(f"Unknown MCP tool: {tool_name}")
