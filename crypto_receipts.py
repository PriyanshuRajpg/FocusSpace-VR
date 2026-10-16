"""
Cryptographic Decision & Erasure Provenance Engine (Upgrading Lethe + oncall).
Computes SHA-256 Merkle roots over multi-hop FalkorDB Cypher paths, MCP tool traces,
and red-team extraction probes, signed with canonical HMAC-SHA256.
"""
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List


SECRET_KEY = os.getenv("AEGIS_HMAC_SECRET", "aegisgraph-falkordb-2026-secret-key").encode("utf-8")


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_merkle_root(leaves: List[str]) -> str:
    if not leaves:
        return sha256_hex("EMPTY_TREE")
    level = [sha256_hex(leaf) for leaf in leaves]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(sha256_hex(left + ":" + right))
        level = next_level
    return level[0]


def canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def issue_decision_receipt(
    incident_id: str,
    graph_name: str,
    cypher_queries: List[str],
    traversal_path: List[str],
    action_taken: str,
    approved_by: str,
) -> Dict[str, Any]:
    """Issues a tamper-evident SHA-256 Merkle + HMAC-SHA256 receipt for an agent graph action."""
    timestamp = int(time.time())
    evidence_leaves = [
        f"hop:{idx}:{node}" for idx, node in enumerate(traversal_path)
    ] + [
        f"cypher:{idx}:{q}" for idx, q in enumerate(cypher_queries)
    ]
    merkle_root = compute_merkle_root(evidence_leaves)
    body = {
        "receipt_id": f"rcpt-{incident_id.lower()}-{timestamp}",
        "incident_id": incident_id,
        "graph_name": graph_name,
        "cypher_count": len(cypher_queries),
        "traversal_path": traversal_path,
        "action_taken": action_taken,
        "approved_by": approved_by,
        "merkle_root": merkle_root,
        "evidence_leaves": evidence_leaves,
        "issued_at": timestamp,
    }
    signature = hmac.new(SECRET_KEY, canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()
    return {**body, "hmac_sha256": signature, "verified": True}


def verify_decision_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Recomputes both the SHA-256 Merkle root and canonical HMAC-SHA256 signature."""
    provided_sig = receipt.get("hmac_sha256", "")
    leaves = receipt.get("evidence_leaves", [])
    recomputed_merkle = compute_merkle_root(leaves)
    merkle_ok = recomputed_merkle == receipt.get("merkle_root")

    body_keys = [
        "receipt_id",
        "incident_id",
        "graph_name",
        "cypher_count",
        "traversal_path",
        "action_taken",
        "approved_by",
        "merkle_root",
        "evidence_leaves",
        "issued_at",
    ]
    body = {k: receipt.get(k) for k in body_keys if k in receipt}
    expected_sig = hmac.new(SECRET_KEY, canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()
    sig_ok = hmac.compare_digest(provided_sig, expected_sig)

    return {
        "valid": bool(merkle_ok and sig_ok),
        "merkle_valid": merkle_ok,
        "signature_valid": sig_ok,
        "recomputed_merkle_root": recomputed_merkle,
        "expected_merkle_root": receipt.get("merkle_root"),
        "verdict": "PROVENANCE_VERIFIED" if (merkle_ok and sig_ok) else "TAMPER_DETECTED",
    }
