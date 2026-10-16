#!/usr/bin/env bash
set -e
echo "=========================================================="
echo "  AegisGraph: Autonomous Graph Context & Company Brain OS "
echo "  Powered by FalkorDB (Tracks 01, 02 & 03)                "
echo "=========================================================="

if command -v docker >/dev/null 2>&1; then
  echo "[1/3] Starting FalkorDB container (ports 6379 & 3000)..."
  docker run -d --name aegis-falkordb -p 6379:6379 -p 3000:3000 falkordb/falkordb:latest || true
fi

echo "[2/3] Running executable proof suite (verify_falkordb.py)..."
python3 -m backend.verify_falkordb

echo "[3/3] Starting AegisGraph FastAPI Server on http://127.0.0.1:8000 ..."
uvicorn backend.main:app --reload --port 8000
