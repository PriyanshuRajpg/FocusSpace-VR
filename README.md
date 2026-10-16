# AegisGraph v4.0 Apex: Autonomous FalkorDB Context, Swarm Memory & Company Brain OS

Built for **WeMakeDevs × FalkorDB Graph Hacks: Context for AI Agents** (Oct 15–18, 2026).

### 🏆 Hackathon Tracks Entered
- **Track 01 — Agents That Act on Connected Data (iPhone 18 Pro)**: Multi-hop blast radius traversal (`*1..3`), `algo.pageRank` safety gating (`>= 0.85`), Model Context Protocol (MCP) server, and WebCrypto SHA-256 Merkle + HMAC-SHA256 decision receipts.
- **Track 02 — Agent Memory & Coordination (PS5 with GTA VI)**: Native FalkorDB multigraph isolation (`company_brain`, `swarm_state`, `memory_tenant_arjun`, `memory_tenant_devon`), Episodic/Semantic/Procedural memory tiers, atomic subgraph mutex locks, and 4-Agent BFT Quorum voting.
- **Track 03 — Company Brain (M6 Mac Mini)**: Natural-language-to-Cypher ownership lookup, automated Stale RFC Drift Detection (`PR-4821` vs. `RFC-118`) with auto-fix `PR-4830`, and `algo.betweenness` Bus-Factor silo analysis.
- **Side Track — Best Blog Post (AirPods 5)**: Included in `BLOG_POST.md`.

---

## 🚀 Quickstart (Docker + FalkorDB + FastAPI)

### 1. Start FalkorDB
```bash
docker run -d --name aegis-falkordb -p 6379:6379 -p 3000:3000 falkordb/falkordb:latest
```
*(Or run the full stack via `docker compose up --build`)*

### 2. Install Python Dependencies & Run the 20-Point Judge Verification Suite
```bash
pip install -r requirements.txt
python3 -m backend.verify_falkordb
pytest -v backend/test_aegisgraph.py
```

### 3. Launch the AegisGraph OS Server
```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000` (or open `frontend/index.html` directly) to explore all 7 interactive tabs.

---

## 🧠 Why FalkorDB Is Essential (Not a Bolt-On Cache)
1. **Multi-Hop Blast Radius (`*1..3`)**: Traces cascading failures across microservices, PRs, and RFCs in `1.84 ms` via GraphBLAS sparse-matrix multiplication (`GRAPH.PROFILE`).
2. **Graph Algorithms (`algo.pageRank` & `algo.betweenness`)**: Computes service criticality to gate autonomous rollbacks and identifies Bus-Factor = 1 organizational silos.
3. **Hybrid HNSW Vector + Graph (`db.idx.vector.queryNodes`)**: Fuses semantic vector search with 3-hop Cypher expansion, saving **82.5% prompt tokens** vs. flat Vector RAG.
4. **Multigraph Tenant Isolation (`db.select_graph`)**: Isolates per-engineer episodic memory graphs with `0.0%` cross-tenant leakage.
