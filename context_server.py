#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "fastmcp>=2.0",
#     "z3-solver>=4.12.0",
# ]
# ///
"""
Semantic / Epistemic Context Manager MCP Server

Design Boundaries:
1. Codex / AI Agent is the sole reasoning component.
2. The Context Manager is intentionally dumb and deterministic.
3. Does not call LLMs, does not call Ghidra, does not evaluate evidence or change confidence automatically.
4. Stores and retrieves notes, hypotheses, facts, evidence, data-flow, and entity states.
5. Formats and renders deterministic validation templates (e.g., Vulnerabilities vs Semantic Recovery).
"""

import ast
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import z3
from fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("re-context")

# Configurable state file via environment variable, with default matching the reference spec
DEFAULT_STATE_FILE = Path.home() / ".local/share/re-agent/state.json"

VULNERABILITY_TEMPLATE_EXAMPLE = """Confirmed Facts
----------------
process() calls parse()
parse() reads length
length reaches allocation
fixed version adds bounds check

Hypotheses
----------------
H1 [0.90]: integer overflow causes undersized allocation
H2 [0.85]: attacker controls length

Evidence
----------------
E1 [supports H1]: length comes from file header
E2 [supports H1]: multiplication occurs before allocation
E3 [supports H1]: fixed version adds overflow check

Rejected Hypotheses
----------------
R1: vulnerability is in validate() (validate() is called after sanitize())
R2: vulnerability is caused by use-after-free (buffer is never freed prematurely)

Candidate Functions
----------------
parse_header()
allocate_buffer()
process_file()

Data-flow Facts
----------------
input → length → multiplication → allocation

Path Constraints (Symbolic)
----------------
PC1 [parse_header]: length > 0 (header non-empty check)
PC2 [allocate_buffer]: alloc_size == (length * 4) & 0xffffffff (32-bit truncation)
PC3 [allocate_buffer]: alloc_size < length (undersized buffer condition)

Exploit Primitives Ledger
----------------
P1 [HEAP_BUFFER_OVERFLOW] | target=heap_chunk_0x40 | controllable=length - alloc_size | func=allocate_buffer | status=verified"""

SEMANTIC_RECOVERY_TEMPLATE_EXAMPLE = """Confirmed Facts
----------------
decompiled sub_401000 accepts socket descriptor in rcx
buffer size is initialized to 1024 bytes
return value is status code (0 for success, -1 on error)

Hypotheses
----------------
H1 [0.90]: function implements TLS record framing
H2 [0.40]: payload uses custom ChaCha20-Poly1305 stream cipher

Evidence
----------------
E1 [supports H1]: magic byte 0x16 checked at offset 0 (TLS handshake)
E2 [supports H1]: loop calls recv() until header complete
E3 [refutes H2]: unrolled loop constants match AES S-box, not ChaCha quarter-round

Rejected Hypotheses
----------------
R1: function handles HTTP chunked encoding (reason: magic byte is 0x16, not ASCII)
R2: buffer is dynamically resized on heap (reason: buffer resides on stack frame)

Candidate Functions / Signatures
----------------
int tls_read_record(session_t *session, uint8_t *buf, size_t max_len)
bool parse_record_header(const uint8_t *hdr, record_meta_t *out_meta)

Data-flow & Control-flow Facts
----------------
socket → recv() → buffer → parse_header() → decrypt_payload()

Struct / Type Definitions
----------------
struct session_t {
    int socket_fd;          /* +0x00 */
    uint32_t state;         /* +0x04 */
    uint8_t rx_buffer[1024];/* +0x08 */
};"""

CALL_GRAPH_TEMPLATE_EXAMPLE = """Function Priority Queue & Attention Scores
----------------
sub_4012a0 [Attention: 0.95] [Role: Crypto/Sink] [Status: uninspected] (In: 1, Out: 4)
- reason: Magic constant 0x9e3779b9 + high cyclomatic complexity (18 blocks)
sub_4018f0 [Attention: 0.85] [Role: Packet Parser] [Status: in_progress] (In: 2, Out: 8)
- reason: Ingests untrusted buffer from recv(); parses length header
sub_402100 [Attention: 0.40] [Role: Allocator Wrapper] [Status: uninspected] (In: 5, Out: 1)
- reason: Wrapper around malloc; check integer overflow bounds
sub_400f10 [Attention: 0.10] [Role: Utility/Leaf] [Status: analyzed] (In: 12, Out: 0)
- reason: Simple byte swap / endian helper (skip deep audit)

Bottom-Up Callee-to-Caller Semantic Flows
----------------
Flow 1 (Crypto Decryption Pipeline):
  [Leaf] EVP_DecryptUpdate() [OpenSSL]
    ▲ called by: sub_401340 (aes_gcm_decrypt) [Conf: 0.90]
      ▲ called by: sub_401820 (tls_record_unpack) [Conf: 0.75]
        ▲ called by: sub_402000 (client_dispatch_loop) [Conf: 0.85]

Flow 2 (Untrusted Input Allocation Path):
  [Leaf] malloc(size) [System Allocator]
    ▲ called by: sub_402100 (realloc_payload_buf) [Sink candidate]
      ▲ called by: sub_4018f0 (parse_packet_header) [Source: recv() length]

Call Graph Edges
----------------
sub_402000 -> sub_401820
sub_401820 -> sub_401340
sub_401340 -> EVP_DecryptUpdate
sub_4018f0 -> sub_402100
sub_402100 -> malloc"""


def get_state_file_path() -> Path:
    env_path = os.environ.get("RE_STATE_FILE")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return DEFAULT_STATE_FILE.expanduser().resolve()


def load_state() -> Dict[str, Any]:
    """Read the current state from disk. Returns empty dict if file does not exist."""
    state_file = get_state_file_path()
    if not state_file.exists():
        return {}
    try:
        content = state_file.read_text(encoding="utf-8").strip()
        if not content:
            return {}
        return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state: Dict[str, Any]) -> None:
    """Safely save state to disk using atomic rename."""
    state_file = get_state_file_path()
    state_file.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write to temporary file in the same directory, then rename
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=state_file.parent, delete=False, encoding="utf-8"
        ) as tf:
            json.dump(state, tf, indent=2)
            tf.flush()
            os.fsync(tf.fileno())
            temp_file = Path(tf.name)
        temp_file.replace(state_file)
    except Exception:
        if temp_file and temp_file.exists():
            temp_file.unlink(missing_ok=True)
        raise


def normalize_template_type(template_type: str) -> str:
    cleaned = template_type.strip().lower().replace("-", "_").replace(" ", "_")
    if cleaned in ("vuln", "vulnerability", "vulnerabilities", "vulnerability_validation"):
        return "vulnerabilities"
    if cleaned in ("semantic", "semantic_recovery", "recovery"):
        return "semantic_recovery"
    if cleaned in ("call_graph", "callgraph", "call_tree", "topology", "graph"):
        return "call_graph"
    return cleaned


# ==========================================
# Core MCP Tools
# ==========================================

@mcp.tool()
def get_state(entity: str) -> Dict[str, Any]:
    """
    Return semantic/epistemic state for one entity (e.g., 'function:add_numbers' or 'cve-2024-xxxx').
    Returns an empty dict if the entity is not tracked.
    """
    state = load_state()
    return state.get(entity, {})


@mcp.tool()
def set_note(entity: str, note: str) -> Dict[str, Any]:
    """
    Store a generic semantic observation or factual note for an entity.
    No reasoning is performed here.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    entry.setdefault("notes", []).append(note)
    save_state(state)
    return entry


@mcp.tool()
def record_fact(entity: str, fact: str) -> Dict[str, Any]:
    """
    Store a confirmed, ground-truth fact for an entity in the validation state.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    entry.setdefault("confirmed_facts", []).append(fact)
    save_state(state)
    return entry


@mcp.tool()
def record_evidence(
    entity: str,
    evidence: str,
    target_hypothesis: str = "",
    polarity: str = "",
    evidence_id: str = "",
) -> Dict[str, Any]:
    """
    Store an item of concrete evidence linking observations to hypotheses.
    If target_hypothesis or polarity ('supports', 'refutes') is omitted, they are auto-detected from text.
    If evidence_id is empty, auto-generates E1, E2, etc.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    ev_list = entry.setdefault("evidence", [])

    if not evidence_id:
        existing_indices = []
        for item in ev_list:
            if isinstance(item, dict) and "id" in item:
                m = re.match(r"^E(\d+)$", str(item["id"]))
                if m:
                    existing_indices.append(int(m.group(1)))
        next_idx = max(existing_indices, default=0) + 1
        evidence_id = f"E{next_idx}"

    # Auto-detect target_hypothesis and polarity if omitted
    detected_target = target_hypothesis
    detected_polarity = polarity.lower() if polarity else ""

    if not detected_target or not detected_polarity:
        m_tag = re.search(r"\[(supports|refutes)\s+(H\d+)\]", evidence, re.IGNORECASE)
        if m_tag:
            if not detected_polarity:
                detected_polarity = m_tag.group(1).lower()
            if not detected_target:
                detected_target = m_tag.group(2).upper()
        else:
            if not detected_polarity:
                if "refutes" in evidence.lower():
                    detected_polarity = "refutes"
                elif "supports" in evidence.lower():
                    detected_polarity = "supports"
                else:
                    detected_polarity = "neutral"

    ev_record = {
        "id": evidence_id,
        "description": evidence,
        "target_hypothesis": detected_target,
        "polarity": detected_polarity,
    }
    ev_list.append(ev_record)
    save_state(state)
    return entry


@mcp.tool()
def add_hypothesis(
    entity: str,
    claim: str,
    confidence: float,
    depends_on: List[str] = [],
    associated_function: str = "",
    hypothesis_id: str = "",
) -> Dict[str, Any]:
    """
    Store a hypothesis with caller-defined confidence, optional upstream dependencies, and associated function.
    If hypothesis_id is omitted, auto-generates H1, H2, etc.
    """
    if not (0.0 <= confidence <= 1.0):
        raise ValueError("Confidence must be a float between 0.0 and 1.0 inclusive.")

    state = load_state()
    entry = state.setdefault(entity, {})
    hyp_list = entry.setdefault("hypotheses", [])

    if not hypothesis_id:
        existing_indices = []
        for item in hyp_list:
            if isinstance(item, dict) and "id" in item:
                m = re.match(r"^H(\d+)$", str(item["id"]))
                if m:
                    existing_indices.append(int(m.group(1)))
        next_idx = max(existing_indices, default=0) + 1
        hypothesis_id = f"H{next_idx}"

    hyp_record = {
        "id": hypothesis_id,
        "claim": claim,
        "confidence": round(confidence, 4),
        "status": "tentative",
        "depends_on": depends_on or [],
    }
    if associated_function:
        hyp_record["associated_function"] = associated_function

    entry["hypotheses"].append(hyp_record)
    save_state(state)
    return entry


def _cascade_invalidation(hyp_list: List[Dict[str, Any]], target_id: str, reason: str) -> List[str]:
    invalidated_ids: List[str] = []
    for h in hyp_list:
        if isinstance(h, dict) and h.get("status") in ("tentative", "active"):
            deps = h.get("depends_on", [])
            if target_id in deps:
                h["status"] = "invalidated"
                h["invalidation_reason"] = f"Upstream dependency {target_id} was rejected: {reason}"
                hid = h.get("id")
                if hid:
                    invalidated_ids.append(hid)
                    invalidated_ids.extend(_cascade_invalidation(hyp_list, hid, reason))
    return list(dict.fromkeys(invalidated_ids))


@mcp.tool()
def reject_hypothesis(
    entity: str, hypothesis_id_or_claim: str, reason: str = ""
) -> Dict[str, Any]:
    """
    Mark an existing hypothesis as rejected and automatically cascade-invalidate all downstream dependent hypotheses.
    Updates call graph node rationales if tied to invalidated hypotheses.
    Auto-assigns R1, R2, etc. in rejected_hypotheses.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    hyp_list = entry.setdefault("hypotheses", [])
    rej_list = entry.setdefault("rejected_hypotheses", [])

    # Next R index
    existing_indices = []
    for item in rej_list:
        if isinstance(item, dict) and "id" in item:
            m = re.match(r"^R(\d+)$", str(item["id"]))
            if m:
                existing_indices.append(int(m.group(1)))
    next_idx = max(existing_indices, default=0) + 1
    rejected_id = f"R{next_idx}"

    claim_text = hypothesis_id_or_claim
    matched_hyp = None
    target_hid = None
    for h in hyp_list:
        if isinstance(h, dict):
            if h.get("id") == hypothesis_id_or_claim or h.get("claim") == hypothesis_id_or_claim:
                matched_hyp = h
                target_hid = h.get("id")
                break

    invalidated_ids: List[str] = []
    if matched_hyp:
        matched_hyp["status"] = "rejected"
        claim_text = matched_hyp.get("claim", hypothesis_id_or_claim)
        if target_hid:
            invalidated_ids = _cascade_invalidation(hyp_list, target_hid, reason)

    record = {"id": rejected_id, "claim": claim_text}
    if reason:
        record["reason"] = reason
    rej_list.append(record)

    # Flag affected call graph nodes
    all_affected_hids = set([target_hid] + invalidated_ids) if target_hid else set(invalidated_ids)
    for node in entry.get("call_graph_nodes", []):
        if isinstance(node, dict):
            node_reason = node.get("reason", "")
            for hid in all_affected_hids:
                if hid and hid in node_reason:
                    if not node_reason.startswith("[INVALIDATED]"):
                        node["reason"] = f"[INVALIDATED - {hid} rejected] {node_reason}"

    save_state(state)
    return entry


@mcp.tool()
def detect_epistemic_conflicts(entity: str) -> Dict[str, Any]:
    """
    Scan entity state for logical contradictions and epistemic conflicts:
    1. Refuting evidence targeting active hypotheses that maintain confidence >= 0.5.
    2. Active hypotheses depending on invalidated or rejected upstream hypotheses.
    3. Call graph nodes with high attention scores (>= 0.70) whose rationale relies on invalidated claims.
    """
    state = load_state()
    entry = state.get(entity, {})
    hypotheses = entry.get("hypotheses", [])
    evidence = entry.get("evidence", [])
    call_nodes = entry.get("call_graph_nodes", [])

    conflicts: List[Dict[str, Any]] = []

    hyp_map = {}
    for h in hypotheses:
        if isinstance(h, dict) and "id" in h:
            hyp_map[h["id"]] = h

    rejected_or_invalidated = {
        h["id"] for h in hypotheses if isinstance(h, dict) and h.get("status") in ("rejected", "invalidated")
    }

    # 1. Check refuting evidence vs high-confidence hypotheses
    for ev in evidence:
        if isinstance(ev, dict):
            target_hid = ev.get("target_hypothesis", "")
            polarity = ev.get("polarity", "")
            desc = ev.get("description", "")

            if not target_hid or not polarity:
                m_tag = re.search(r"\[(supports|refutes)\s+(H\d+)\]", desc, re.IGNORECASE)
                if m_tag:
                    polarity = m_tag.group(1).lower()
                    target_hid = m_tag.group(2).upper()

            if target_hid in hyp_map:
                h = hyp_map[target_hid]
                if h.get("status") in ("tentative", "active"):
                    if polarity == "refutes" and h.get("confidence", 0.0) >= 0.5:
                        conflicts.append({
                            "type": "refuting_evidence_conflict",
                            "severity": "high",
                            "hypothesis_id": target_hid,
                            "evidence_id": ev.get("id"),
                            "confidence": h.get("confidence"),
                            "issue": f"Evidence {ev.get('id')} refutes hypothesis {target_hid}, but confidence remains high ({h.get('confidence')}).",
                            "recommendation": f"Lower confidence of {target_hid} or reject it using reject_hypothesis().",
                        })

    # 2. Check broken dependencies
    for h in hypotheses:
        if isinstance(h, dict) and h.get("status") in ("tentative", "active"):
            deps = h.get("depends_on", [])
            for dep in deps:
                if dep in rejected_or_invalidated:
                    conflicts.append({
                        "type": "broken_dependency",
                        "severity": "critical",
                        "hypothesis_id": h.get("id"),
                        "broken_upstream_id": dep,
                        "issue": f"Hypothesis {h.get('id')} relies on {dep}, which has been rejected or invalidated.",
                        "recommendation": f"Mark {h.get('id')} as invalidated or revise its dependencies.",
                    })

    # 3. Check stale attention rationales
    for node in call_nodes:
        if isinstance(node, dict):
            fn = node.get("function")
            reason = node.get("reason", "")
            att = node.get("attention_score", 0.0)
            if att >= 0.70:
                for bad_hid in rejected_or_invalidated:
                    if bad_hid in reason or f"[INVALIDATED - {bad_hid}" in reason:
                        conflicts.append({
                            "type": "stale_attention_priority",
                            "severity": "medium",
                            "function": fn,
                            "invalidated_hypothesis": bad_hid,
                            "attention_score": att,
                            "issue": f"Function '{fn}' has high attention score ({att:.2f}), but its rationale is tied to invalidated {bad_hid}.",
                            "recommendation": f"Re-evaluate '{fn}' and lower its attention score using add_call_graph_node().",
                        })

    return {
        "conflict_count": len(conflicts),
        "status": "conflicts_found" if conflicts else "consistent",
        "conflicts": conflicts,
    }


@mcp.tool()
def add_candidate_function(entity: str, function_name: str) -> Dict[str, Any]:
    """
    Record a candidate function or signature of interest for validation.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    entry.setdefault("candidate_functions", []).append(function_name)
    save_state(state)
    return entry


@mcp.tool()
def add_data_flow_fact(entity: str, flow: str) -> Dict[str, Any]:
    """
    Record a data-flow or control-flow progression fact (e.g. 'input → length → allocation').
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    entry.setdefault("data_flow_facts", []).append(flow)
    save_state(state)
    return entry


@mcp.tool()
def add_type_definition(entity: str, type_definition: str) -> Dict[str, Any]:
    """
    Record a reconstructed C struct or type definition (for semantic recovery).
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    entry.setdefault("type_definitions", []).append(type_definition)
    save_state(state)
    return entry


@mcp.tool()
def add_call_graph_node(
    entity: str,
    function_name: str,
    attention_score: float,
    role: str = "unknown",
    reason: str = "",
    in_degree: int = 0,
    out_degree: int = 0,
    status: str = "uninspected",
) -> Dict[str, Any]:
    """
    Record or update a function node in the call graph with an attention score (0.0 to 1.0),
    role (e.g. 'Crypto/Sink', 'Parser', 'Dispatcher', 'Utility/Leaf'), status ('uninspected', 'in_progress', 'analyzed'),
    and architectural reason. Nodes are sorted in descending order of attention score.
    """
    if not (0.0 <= attention_score <= 1.0):
        raise ValueError("attention_score must be a float between 0.0 and 1.0")
    state = load_state()
    entry = state.setdefault(entity, {})
    nodes = entry.setdefault("call_graph_nodes", [])

    existing = None
    for n in nodes:
        if isinstance(n, dict) and n.get("function") == function_name:
            existing = n
            break

    node_data = {
        "function": function_name,
        "attention_score": round(attention_score, 2),
        "role": role,
        "reason": reason,
        "in_degree": in_degree,
        "out_degree": out_degree,
        "status": status,
    }

    if existing:
        existing.update(node_data)
    else:
        nodes.append(node_data)

    nodes.sort(key=lambda x: x.get("attention_score", 0.0), reverse=True)
    save_state(state)
    return entry


@mcp.tool()
def get_attention_queue(
    entity: str,
    min_score: float = 0.0,
    status_filter: str = "",
) -> List[Dict[str, Any]]:
    """
    Retrieve functions from the call graph ordered by attention score descending.
    Allows filtering by min_score and status_filter (e.g., 'uninspected', 'in_progress', 'analyzed').
    """
    state = load_state()
    entry = state.get(entity, {})
    nodes = entry.get("call_graph_nodes", [])

    filtered = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        if n.get("attention_score", 0.0) < min_score:
            continue
        if status_filter and n.get("status") != status_filter:
            continue
        filtered.append(n)

    filtered.sort(key=lambda x: x.get("attention_score", 0.0), reverse=True)
    return filtered


@mcp.tool()
def update_call_graph_node_status(
    entity: str,
    function_name: str,
    status: str,
    updated_role: str = "",
) -> Dict[str, Any]:
    """
    Update the inspection status ('uninspected', 'in_progress', 'analyzed') or role of a function node.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    nodes = entry.setdefault("call_graph_nodes", [])

    for n in nodes:
        if isinstance(n, dict) and n.get("function") == function_name:
            n["status"] = status
            if updated_role:
                n["role"] = updated_role
            break
    save_state(state)
    return entry


@mcp.tool()
def add_call_edge(
    entity: str,
    caller: str,
    callee: str,
    callsite: str = "",
) -> Dict[str, Any]:
    """
    Record a directional call graph edge (caller -> callee) and update degree metrics on nodes if present.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    edges = entry.setdefault("call_graph_edges", [])

    exists = any(
        isinstance(e, dict) and e.get("caller") == caller and e.get("callee") == callee
        for e in edges
    )
    if not exists:
        edges.append({"caller": caller, "callee": callee, "callsite": callsite})

        # Update in/out degrees in call_graph_nodes if present
        nodes = entry.get("call_graph_nodes", [])
        for n in nodes:
            if isinstance(n, dict):
                if n.get("function") == caller:
                    n["out_degree"] = n.get("out_degree", 0) + 1
                elif n.get("function") == callee:
                    n["in_degree"] = n.get("in_degree", 0) + 1

    save_state(state)
    return entry


@mcp.tool()
def record_callee_caller_flow(
    entity: str,
    flow_name: str,
    chain: List[Any],
    description: str = "",
) -> Dict[str, Any]:
    """
    Record a bottom-up callee-to-caller semantic flow showing how leaf primitives bubble up to callers.
    chain: list of function steps from leaf to root caller, e.g.:
    ['EVP_DecryptUpdate() [OpenSSL]', 'sub_401340 (aes_decrypt) [Conf: 0.90]', 'sub_402000 (dispatch)'].
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    flows = entry.setdefault("callee_caller_flows", [])

    flow_record = {
        "flow_name": flow_name,
        "chain": chain,
        "description": description,
    }

    replaced = False
    for i, f in enumerate(flows):
        if isinstance(f, dict) and f.get("flow_name") == flow_name:
            flows[i] = flow_record
            replaced = True
            break
    if not replaced:
        flows.append(flow_record)

    save_state(state)
    return entry


@mcp.tool()
def find_call_paths(
    entity: str,
    source_func: str,
    sink_func: str,
    max_depth: int = 6,
    max_paths: int = 5,
) -> Dict[str, Any]:
    """
    Find directional call paths from source_func to sink_func in the call graph using BFS traversal.
    Enables instant vulnerability taint reachability checks from untrusted sources to sensitive sinks.
    """
    state = load_state()
    entry = state.get(entity, {})
    edges = entry.get("call_graph_edges", [])

    adj: Dict[str, List[str]] = {}
    for e in edges:
        if isinstance(e, dict):
            caller = e.get("caller")
            callee = e.get("callee")
            if caller and callee:
                adj.setdefault(caller, []).append(callee)

    if source_func not in adj and source_func != sink_func:
        return {
            "reachable": False,
            "source": source_func,
            "sink": sink_func,
            "path_count": 0,
            "paths": [],
            "message": f"Source function '{source_func}' has no outgoing edges in call graph",
        }

    paths: List[List[str]] = []
    queue = [[source_func]]

    while queue and len(paths) < max_paths:
        curr_path = queue.pop(0)
        curr_node = curr_path[-1]

        if curr_node == sink_func and len(curr_path) > 1:
            paths.append(curr_path)
            continue

        if len(curr_path) - 1 >= max_depth:
            continue

        for neighbor in adj.get(curr_node, []):
            if neighbor not in curr_path:  # Prevent cyclic loops
                queue.append(curr_path + [neighbor])

    reachable = len(paths) > 0
    intermediate = list(dict.fromkeys(
        fn for p in paths for fn in p[1:-1]
    )) if reachable else []

    return {
        "reachable": reachable,
        "source": source_func,
        "sink": sink_func,
        "path_count": len(paths),
        "paths": paths,
        "intermediate_functions": intermediate,
        "shortest_distance": (len(paths[0]) - 1) if reachable else -1,
    }


@mcp.tool()
def render_mermaid_graph(
    entity: str,
    include_attention_colors: bool = True,
    orientation: str = "TD",
) -> str:
    """
    Generate a markdown Mermaid diagram representing the call graph with attention score heatmaps.
    Nodes are styled: High attention (Red), Medium (Yellow), Low (Gray), In-Progress (Blue), Analyzed (Green).
    """
    state = load_state()
    entry = state.get(entity, {})
    nodes = entry.get("call_graph_nodes", [])
    edges = entry.get("call_graph_edges", [])

    if not nodes and not edges:
        return f"```mermaid\ngraph {orientation}\n    empty[\"No call graph nodes or edges recorded for {entity}\"]\n```"

    lines = [f"```mermaid\ngraph {orientation}"]

    def sanitize_id(name: str) -> str:
        return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", name)

    known_nodes = {n.get("function"): n for n in nodes if isinstance(n, dict)}
    for e in edges:
        if isinstance(e, dict):
            for endpoint in (e.get("caller"), e.get("callee")):
                if endpoint and endpoint not in known_nodes:
                    known_nodes[endpoint] = {
                        "function": endpoint,
                        "attention_score": 0.0,
                        "role": "untracked",
                        "status": "uninspected",
                    }

    class_assignments: Dict[str, List[str]] = {}

    for fn_name, n in known_nodes.items():
        node_id = sanitize_id(fn_name)
        role = n.get("role", "")
        att = n.get("attention_score")
        status = n.get("status", "uninspected")

        label_parts = [fn_name]
        if role and role not in ("unknown", "untracked"):
            label_parts.append(f"({role})")
        if att is not None and att > 0.0:
            label_parts.append(f"Att: {att:.2f}")

        label = "<br/>".join(label_parts)
        lines.append(f'    {node_id}["{label}"]')

        if include_attention_colors:
            if status == "analyzed":
                class_assignments.setdefault("analyzed", []).append(node_id)
            elif status == "in_progress":
                class_assignments.setdefault("in_progress", []).append(node_id)
            elif att is not None and att >= 0.80:
                class_assignments.setdefault("high_attention", []).append(node_id)
            elif att is not None and att >= 0.40:
                class_assignments.setdefault("mid_attention", []).append(node_id)
            else:
                class_assignments.setdefault("low_attention", []).append(node_id)

    if edges:
        lines.append("")
        for e in edges:
            if isinstance(e, dict):
                src = sanitize_id(e.get("caller", ""))
                dst = sanitize_id(e.get("callee", ""))
                callsite = e.get("callsite", "")
                if callsite:
                    lines.append(f'    {src} -->|"{callsite}"| {dst}')
                else:
                    lines.append(f"    {src} --> {dst}")

    if include_attention_colors:
        lines.append("")
        lines.append("    classDef high_attention fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#721c24;")
        lines.append("    classDef mid_attention fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#856404;")
        lines.append("    classDef low_attention fill:#e2e3e5,stroke:#6c757d,stroke-width:1px,color:#383d41;")
        lines.append("    classDef analyzed fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724;")
        lines.append("    classDef in_progress fill:#cce5ff,stroke:#007bff,stroke-width:2px,color:#004085;")

        for cls_name, ids in class_assignments.items():
            if ids:
                lines.append(f"    class {','.join(ids)} {cls_name};")

    lines.append("```")
    return "\n".join(lines)


# ==========================================
# Security-First SMT & Exploit Primitive Ledger (z3-solver)
# ==========================================

def _normalize_constraint_expr(expr: str) -> str:
    """Normalize C/pseudocode expression operators to Python/AST-compatible syntax."""
    expr = expr.strip().rstrip(";")
    expr = expr.replace("&&", " and ").replace("||", " or ")
    # Replace ! that is not != with not
    expr = re.sub(r"!(?!=)\s*", " not ", expr)
    # Replace single = with == (equality) if not part of <=, >=, !=, ==
    expr = re.sub(r"(?<![!=<>])=(?![=])", "==", expr)
    return expr.strip()


def _ast_to_z3(
    node: ast.AST,
    env: Dict[str, Any],
    bit_width: int = 32,
    var_types: Optional[Dict[str, str]] = None,
) -> Any:
    """
    Recursively converts a Python AST node into an equivalent Z3 expression.
    Supports BitVector and integer arithmetic, comparisons, bitwise ops, and logical operators.
    """
    var_types = var_types or {}
    if isinstance(node, ast.Expression):
        return _ast_to_z3(node.body, env, bit_width, var_types)

    elif isinstance(node, ast.Constant):
        val = node.value
        if isinstance(val, int):
            if bit_width > 0:
                masked = val & ((1 << bit_width) - 1)
                return z3.BitVecVal(masked if val >= 0 else -((-val) & ((1 << bit_width) - 1)), bit_width)
            return z3.IntVal(val)
        elif isinstance(val, bool):
            return z3.BoolVal(val)
        raise ValueError(f"Unsupported constant type: {type(val).__name__} ({val})")

    elif isinstance(node, ast.Name):
        vname = node.id
        if vname not in env:
            vtype = var_types.get(vname, f"bitvec{bit_width}" if bit_width > 0 else "int").lower()
            if any(t in vtype for t in ("bitvec", "bv", "uint", "int", "u32", "u64", "i32", "i64", "size_t")):
                bw = bit_width
                m = re.search(r"\d+", vtype)
                if m:
                    bw = int(m.group(0))
                env[vname] = z3.BitVec(vname, bw)
            elif vtype in ("bool", "boolean"):
                env[vname] = z3.Bool(vname)
            elif vtype in ("int", "integer"):
                env[vname] = z3.Int(vname)
            else:
                env[vname] = z3.BitVec(vname, bit_width) if bit_width > 0 else z3.Int(vname)
        return env[vname]

    elif isinstance(node, ast.UnaryOp):
        operand = _ast_to_z3(node.operand, env, bit_width, var_types)
        if isinstance(node.op, ast.Not):
            return z3.Not(operand)
        elif isinstance(node.op, ast.USub):
            return -operand
        elif isinstance(node.op, ast.Invert):
            return ~operand
        raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")

    elif isinstance(node, ast.BinOp):
        left = _ast_to_z3(node.left, env, bit_width, var_types)
        right = _ast_to_z3(node.right, env, bit_width, var_types)
        op = node.op
        if isinstance(op, ast.Add):
            return left + right
        if isinstance(op, ast.Sub):
            return left - right
        if isinstance(op, ast.Mult):
            return left * right
        if isinstance(op, (ast.FloorDiv, ast.Div)):
            return left / right
        if isinstance(op, ast.Mod):
            return left % right
        if isinstance(op, ast.BitAnd):
            return left & right
        if isinstance(op, ast.BitOr):
            return left | right
        if isinstance(op, ast.BitXor):
            return left ^ right
        if isinstance(op, ast.LShift):
            return left << right
        if isinstance(op, ast.RShift):
            return left >> right
        raise ValueError(f"Unsupported binary operator: {type(op).__name__}")

    elif isinstance(node, ast.Compare):
        left = _ast_to_z3(node.left, env, bit_width, var_types)
        comps = []
        curr = left
        for op, comp in zip(node.ops, node.comparators):
            right = _ast_to_z3(comp, env, bit_width, var_types)
            is_unsigned = any(
                var_types.get(v, "").lower().startswith(("u", "uint", "size_t"))
                for v in env
            )
            if isinstance(op, ast.Eq):
                c = (curr == right)
            elif isinstance(op, ast.NotEq):
                c = (curr != right)
            elif isinstance(op, ast.Lt):
                c = z3.ULT(curr, right) if is_unsigned and z3.is_bv(curr) and z3.is_bv(right) else (curr < right)
            elif isinstance(op, ast.LtE):
                c = z3.ULE(curr, right) if is_unsigned and z3.is_bv(curr) and z3.is_bv(right) else (curr <= right)
            elif isinstance(op, ast.Gt):
                c = z3.UGT(curr, right) if is_unsigned and z3.is_bv(curr) and z3.is_bv(right) else (curr > right)
            elif isinstance(op, ast.GtE):
                c = z3.UGE(curr, right) if is_unsigned and z3.is_bv(curr) and z3.is_bv(right) else (curr >= right)
            else:
                raise ValueError(f"Unsupported comparison: {type(op).__name__}")
            comps.append(c)
            curr = right
        return z3.And(*comps) if len(comps) > 1 else comps[0]

    elif isinstance(node, ast.BoolOp):
        values = [_ast_to_z3(v, env, bit_width, var_types) for v in node.values]
        if isinstance(node.op, ast.And):
            return z3.And(*values)
        if isinstance(node.op, ast.Or):
            return z3.Or(*values)
        raise ValueError(f"Unsupported boolean operator: {type(node.op).__name__}")

    raise ValueError(f"Unsupported expression node: {type(node).__name__}")


@mcp.tool()
def record_path_constraint(
    entity: str,
    constraint_expr: str,
    source_function: str = "",
    is_negated: bool = False,
    description: str = "",
) -> Dict[str, Any]:
    """
    Record a symbolic path condition or branch constraint (e.g. 'length > 0', 'alloc_size == length * 4')
    encountered along the execution trace. Automatically assigns sequential IDs (PC1, PC2, etc.).
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    constraints = entry.setdefault("path_constraints", [])

    existing_ids = {c.get("id") for c in constraints if isinstance(c, dict)}
    next_idx = len(constraints) + 1
    while f"PC{next_idx}" in existing_ids:
        next_idx += 1
    cid = f"PC{next_idx}"

    pc_data = {
        "id": cid,
        "expr": constraint_expr.strip(),
        "source_function": source_function.strip(),
        "is_negated": bool(is_negated),
        "description": description.strip(),
    }
    constraints.append(pc_data)
    save_state(state)
    return entry


@mcp.tool()
def list_path_constraints(
    entity: str,
    source_function: str = "",
) -> List[Dict[str, Any]]:
    """
    Retrieve all recorded symbolic path constraints for an entity, optionally filtered by source_function.
    """
    state = load_state()
    entry = state.get(entity, {})
    constraints = entry.get("path_constraints", [])
    if not source_function:
        return [c for c in constraints if isinstance(c, dict)]
    return [
        c for c in constraints
        if isinstance(c, dict) and c.get("source_function") == source_function
    ]


@mcp.tool()
def delete_path_constraint(
    entity: str,
    constraint_id: str,
) -> Dict[str, Any]:
    """
    Remove a specific symbolic path constraint by ID (e.g. 'PC2') to support branch backtracking or forking.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    constraints = entry.setdefault("path_constraints", [])
    entry["path_constraints"] = [
        c for c in constraints if isinstance(c, dict) and c.get("id") != constraint_id
    ]
    save_state(state)
    return entry


@mcp.tool()
def clear_path_constraints(
    entity: str,
) -> Dict[str, Any]:
    """
    Clear all recorded symbolic path constraints for an entity without deleting hypotheses, facts, or graph topology.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    entry["path_constraints"] = []
    save_state(state)
    return entry


@mcp.tool()
def record_exploit_primitive(
    entity: str,
    primitive_type: str,
    target_buffer: str = "",
    controllable_bytes: str = "",
    trigger_status: str = "tentative",
    associated_function: str = "",
    details: str = "",
    applied_constraints: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Record an exploit primitive or vulnerability condition (e.g. 'HEAP_BUFFER_OVERFLOW',
    'INTEGER_OVERFLOW', 'OUT_OF_BOUNDS_WRITE', 'USE_AFTER_FREE').
    Assigns sequential IDs (P1, P2, etc.).
    Trigger status can be 'tentative', 'verified', 'unreachable', or 'mitigated'.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    primitives = entry.setdefault("exploit_primitives", [])

    existing_ids = {p.get("primitive_id") for p in primitives if isinstance(p, dict)}
    next_idx = len(primitives) + 1
    while f"P{next_idx}" in existing_ids:
        next_idx += 1
    pid = f"P{next_idx}"

    prim_data = {
        "primitive_id": pid,
        "type": primitive_type.strip(),
        "target_buffer": target_buffer.strip(),
        "controllable_bytes": controllable_bytes.strip(),
        "trigger_status": trigger_status.strip().lower(),
        "associated_function": associated_function.strip(),
        "details": details.strip(),
        "applied_constraints": applied_constraints or [],
    }
    primitives.append(prim_data)
    save_state(state)
    return entry


@mcp.tool()
def list_exploit_primitives(
    entity: str,
    status_filter: str = "",
) -> List[Dict[str, Any]]:
    """
    List all recorded exploit primitives for an entity, optionally filtered by trigger_status ('tentative', 'verified', 'unreachable', 'mitigated').
    """
    state = load_state()
    entry = state.get(entity, {})
    primitives = entry.get("exploit_primitives", [])
    if not status_filter:
        return [p for p in primitives if isinstance(p, dict)]
    return [
        p for p in primitives
        if isinstance(p, dict) and p.get("trigger_status") == status_filter.strip().lower()
    ]


@mcp.tool()
def update_exploit_primitive_status(
    entity: str,
    primitive_id: str,
    status: str,
    verification_notes: str = "",
) -> Dict[str, Any]:
    """
    Update the trigger status of an exploit primitive ('tentative', 'verified', 'unreachable', 'mitigated')
    and record verification notes.
    """
    state = load_state()
    entry = state.setdefault(entity, {})
    primitives = entry.setdefault("exploit_primitives", [])

    for p in primitives:
        if isinstance(p, dict) and p.get("primitive_id") == primitive_id:
            p["trigger_status"] = status.strip().lower()
            if verification_notes:
                p["verification_notes"] = verification_notes.strip()
            break

    save_state(state)
    return entry


@mcp.tool()
def solve_reachability(
    entity: str,
    target_condition: str,
    variable_types: Optional[Dict[str, str]] = None,
    active_constraint_ids: Optional[List[str]] = None,
    additional_constraints: Optional[List[str]] = None,
    bit_width: int = 32,
) -> Dict[str, Any]:
    """
    Run an embedded Z3 SMT solver check to determine if the target condition is mathematically reachable.
    Validates satisfiability over path constraints recorded for the entity (or filtered by active_constraint_ids).
    Supports 32-bit/64-bit BitVector and integer arithmetic, returning satisfying models or proving unreachability (UNSAT).
    """
    state = load_state()
    entry = state.get(entity, {})
    all_pcs = entry.get("path_constraints", [])
    var_types = variable_types or {}

    pcs_to_use = []
    if active_constraint_ids is not None:
        id_set = set(active_constraint_ids)
        for pc in all_pcs:
            if isinstance(pc, dict) and pc.get("id") in id_set:
                pcs_to_use.append(pc)
    else:
        for pc in all_pcs:
            if isinstance(pc, dict):
                pcs_to_use.append(pc)

    solver = z3.Solver()
    env: Dict[str, Any] = {}
    evaluated_constraints: List[str] = []

    try:
        # Add recorded path constraints
        for pc in pcs_to_use:
            expr_raw = pc.get("expr", "")
            is_neg = pc.get("is_negated", False)
            clean = _normalize_constraint_expr(expr_raw)
            tree = ast.parse(clean, mode="eval")
            z_expr = _ast_to_z3(tree, env, bit_width=bit_width, var_types=var_types)
            if is_neg:
                solver.add(z3.Not(z_expr))
                evaluated_constraints.append(f"{pc.get('id')}: NOT ({clean})")
            else:
                solver.add(z_expr)
                evaluated_constraints.append(f"{pc.get('id')}: {clean}")

        # Add additional ad-hoc constraints if supplied
        if additional_constraints:
            for idx, raw_add in enumerate(additional_constraints, start=1):
                clean_add = _normalize_constraint_expr(raw_add)
                tree_add = ast.parse(clean_add, mode="eval")
                z_add = _ast_to_z3(tree_add, env, bit_width=bit_width, var_types=var_types)
                solver.add(z_add)
                evaluated_constraints.append(f"EXTRA_{idx}: {clean_add}")

        # Add target condition
        clean_target = _normalize_constraint_expr(target_condition)
        tree_target = ast.parse(clean_target, mode="eval")
        z_target = _ast_to_z3(tree_target, env, bit_width=bit_width, var_types=var_types)
        solver.add(z_target)
        evaluated_constraints.append(f"TARGET: {clean_target}")

    except Exception as e:
        return {
            "status": "ERROR",
            "is_reachable": False,
            "error": f"Failed to parse or convert constraint to Z3 SMT expression: {str(e)}",
            "evaluated_constraints": evaluated_constraints,
        }

    check_res = solver.check()
    if check_res == z3.sat:
        model = solver.model()
        satisfying_model: Dict[str, Any] = {}
        for decl in model.decls():
            vname = decl.name()
            val_ref = model[decl]
            if z3.is_bv(val_ref):
                val_int = val_ref.as_long()
                satisfying_model[vname] = {
                    "decimal": val_int,
                    "hex": hex(val_int),
                }
            elif z3.is_int(val_ref):
                val_int = val_ref.as_long()
                satisfying_model[vname] = {
                    "decimal": val_int,
                    "hex": hex(val_int) if val_int >= 0 else f"-{hex(abs(val_int))}",
                }
            else:
                satisfying_model[vname] = {"value": str(val_ref)}

        return {
            "status": "SATISFIABLE",
            "is_reachable": True,
            "satisfying_model": satisfying_model,
            "evaluated_constraints": evaluated_constraints,
            "summary": "Target condition is mathematically reachable. Concrete satisfying assignments discovered by Z3.",
        }
    elif check_res == z3.unsat:
        return {
            "status": "UNSATISFIABLE",
            "is_reachable": False,
            "evaluated_constraints": evaluated_constraints,
            "summary": "Target condition is mathematically unreachable (UNSAT). The constraint set proves the condition cannot be triggered under these branch conditions.",
        }
    else:
        return {
            "status": "UNKNOWN",
            "is_reachable": False,
            "reason": solver.reason_unknown(),
            "evaluated_constraints": evaluated_constraints,
            "summary": "Z3 solver returned unknown for the constraint set.",
        }


@mcp.tool()
def explain_unreachability(
    entity: str,
    target_condition: str,
    variable_types: Optional[Dict[str, str]] = None,
    active_constraint_ids: Optional[List[str]] = None,
    additional_constraints: Optional[List[str]] = None,
    bit_width: int = 32,
) -> Dict[str, Any]:
    """
    Diagnose why a target condition is mathematically unreachable (UNSAT) using Z3's Unsat Core engine.
    Pinpoints the minimal contradictory subset of path constraints and sanitization checks that prevent reaching the condition.
    """
    state = load_state()
    entry = state.get(entity, {})
    all_pcs = entry.get("path_constraints", [])
    var_types = variable_types or {}

    pcs_to_use = []
    if active_constraint_ids is not None:
        id_set = set(active_constraint_ids)
        for pc in all_pcs:
            if isinstance(pc, dict) and pc.get("id") in id_set:
                pcs_to_use.append(pc)
    else:
        for pc in all_pcs:
            if isinstance(pc, dict):
                pcs_to_use.append(pc)

    solver = z3.Solver()
    env: Dict[str, Any] = {}
    pc_map: Dict[str, Dict[str, Any]] = {}

    try:
        # Track recorded constraints
        for pc in pcs_to_use:
            cid = pc.get("id", "")
            expr_raw = pc.get("expr", "")
            is_neg = pc.get("is_negated", False)
            clean = _normalize_constraint_expr(expr_raw)
            tree = ast.parse(clean, mode="eval")
            z_expr = _ast_to_z3(tree, env, bit_width=bit_width, var_types=var_types)
            if is_neg:
                solver.assert_and_track(z3.Not(z_expr), cid)
            else:
                solver.assert_and_track(z_expr, cid)
            pc_map[cid] = pc

        # Track additional constraints if any
        if additional_constraints:
            for idx, raw_add in enumerate(additional_constraints, start=1):
                track_id = f"EXTRA_{idx}"
                clean_add = _normalize_constraint_expr(raw_add)
                tree_add = ast.parse(clean_add, mode="eval")
                z_add = _ast_to_z3(tree_add, env, bit_width=bit_width, var_types=var_types)
                solver.assert_and_track(z_add, track_id)
                pc_map[track_id] = {"id": track_id, "expr": clean_add, "source_function": "extra"}

        # Track target condition
        clean_target = _normalize_constraint_expr(target_condition)
        tree_target = ast.parse(clean_target, mode="eval")
        z_target = _ast_to_z3(tree_target, env, bit_width=bit_width, var_types=var_types)
        solver.assert_and_track(z_target, "TARGET")
        pc_map["TARGET"] = {"id": "TARGET", "expr": clean_target, "source_function": "target_condition"}

    except Exception as e:
        return {
            "status": "ERROR",
            "error": f"Failed to parse or convert constraints for unsat core analysis: {str(e)}",
        }

    check_res = solver.check()
    if check_res == z3.sat:
        return {
            "status": "SATISFIABLE",
            "is_reachable": True,
            "message": "Target condition is actually reachable (SAT). Use solve_reachability() to view satisfying variable assignments.",
        }
    elif check_res == z3.unsat:
        core_ids = [str(x) for x in solver.unsat_core()]
        conflicting_constraints = []
        for cid in core_ids:
            if cid in pc_map:
                conflicting_constraints.append(pc_map[cid])
            else:
                conflicting_constraints.append({"id": cid})

        return {
            "status": "UNSATISFIABLE",
            "is_reachable": False,
            "unsat_core_ids": core_ids,
            "conflicting_constraints": conflicting_constraints,
            "diagnosis": f"The condition is prevented by a contradiction between: {', '.join(core_ids)}.",
        }
    else:
        return {
            "status": "UNKNOWN",
            "is_reachable": False,
            "reason": solver.reason_unknown(),
        }


@mcp.tool()
def solve_variable_bounds(
    entity: str,
    variable_name: str,
    variable_types: Optional[Dict[str, str]] = None,
    active_constraint_ids: Optional[List[str]] = None,
    additional_constraints: Optional[List[str]] = None,
    bit_width: int = 32,
) -> Dict[str, Any]:
    """
    Calculate the mathematical minimum and maximum allowable bounds for a variable
    under the recorded path constraints using Z3 optimization.
    Returns interval bounds in decimal and hex.
    """
    state = load_state()
    entry = state.get(entity, {})
    all_pcs = entry.get("path_constraints", [])
    var_types = variable_types or {}

    pcs_to_use = []
    if active_constraint_ids is not None:
        id_set = set(active_constraint_ids)
        for pc in all_pcs:
            if isinstance(pc, dict) and pc.get("id") in id_set:
                pcs_to_use.append(pc)
    else:
        for pc in all_pcs:
            if isinstance(pc, dict):
                pcs_to_use.append(pc)

    env: Dict[str, Any] = {}
    parsed_constraints = []

    try:
        # Pre-instantiate target variable so its type matches var_types
        vtype = var_types.get(variable_name, f"bitvec{bit_width}" if bit_width > 0 else "int").lower()
        if any(t in vtype for t in ("bitvec", "bv", "uint", "int", "u32", "u64", "i32", "i64", "size_t")):
            bw = bit_width
            m = re.search(r"\d+", vtype)
            if m:
                bw = int(m.group(0))
            target_var = z3.BitVec(variable_name, bw)
        elif vtype in ("int", "integer"):
            target_var = z3.Int(variable_name)
        else:
            target_var = z3.BitVec(variable_name, bit_width) if bit_width > 0 else z3.Int(variable_name)
        env[variable_name] = target_var

        for pc in pcs_to_use:
            expr_raw = pc.get("expr", "")
            is_neg = pc.get("is_negated", False)
            clean = _normalize_constraint_expr(expr_raw)
            tree = ast.parse(clean, mode="eval")
            z_expr = _ast_to_z3(tree, env, bit_width=bit_width, var_types=var_types)
            parsed_constraints.append(z3.Not(z_expr) if is_neg else z_expr)

        if additional_constraints:
            for raw_add in additional_constraints:
                clean_add = _normalize_constraint_expr(raw_add)
                tree_add = ast.parse(clean_add, mode="eval")
                z_add = _ast_to_z3(tree_add, env, bit_width=bit_width, var_types=var_types)
                parsed_constraints.append(z_add)

    except Exception as e:
        return {
            "status": "ERROR",
            "error": f"Failed to parse constraints for variable bounds calculation: {str(e)}",
        }

    # Pass 1: Minimize
    opt_min = z3.Optimize()
    for c in parsed_constraints:
        opt_min.add(c)
    h_min = opt_min.minimize(target_var)
    res_min = opt_min.check()

    if res_min == z3.unsat:
        return {
            "status": "UNSATISFIABLE",
            "message": "Constraint set is mathematically unsatisfiable; variable cannot assume any value.",
        }

    # Pass 2: Maximize
    opt_max = z3.Optimize()
    for c in parsed_constraints:
        opt_max.add(c)
    h_max = opt_max.maximize(target_var)
    res_max = opt_max.check()

    def format_val(val_ref):
        s = str(val_ref)
        if s == "oo":
            return "unbounded_positive"
        if s == "-oo":
            return "unbounded_negative"
        try:
            val_int = val_ref.as_long()
            return {
                "decimal": val_int,
                "hex": hex(val_int) if val_int >= 0 else f"-{hex(abs(val_int))}",
            }
        except Exception:
            return {"value": s}

    return {
        "status": "BOUNDED",
        "variable": variable_name,
        "min": format_val(h_min.value()),
        "max": format_val(h_max.value()),
    }


@mcp.tool()
def clear_state(entity: str) -> Dict[str, str]:
    """
    Delete semantic state for one specific entity.
    """
    state = load_state()
    if entity in state:
        state.pop(entity, None)
        save_state(state)
        return {"cleared": entity, "status": "deleted"}
    return {"cleared": entity, "status": "not_found"}


@mcp.tool()
def list_entities() -> List[str]:
    """
    List all entity identifiers currently tracked in semantic state.
    """
    state = load_state()
    return list(state.keys())


@mcp.tool()
def get_all_state() -> Dict[str, Any]:
    """
    Return the entire semantic/epistemic state dictionary across all entities.
    """
    return load_state()


# ==========================================
# Template Management Tools & Rendering
# ==========================================

@mcp.tool()
def get_validation_template(template_type: str = "vulnerabilities") -> str:
    """
    Get the standard blank/example template structure for a given validation domain.
    Supported types: 'vulnerabilities', 'semantic_recovery', and 'call_graph'.
    """
    normalized = normalize_template_type(template_type)
    if normalized == "semantic_recovery":
        return SEMANTIC_RECOVERY_TEMPLATE_EXAMPLE
    if normalized == "call_graph":
        return CALL_GRAPH_TEMPLATE_EXAMPLE
    return VULNERABILITY_TEMPLATE_EXAMPLE


@mcp.tool()
def render_template(
    entity: str,
    template_type: str = "vulnerabilities",
    omit_empty: bool = False,
    include_confidence: bool = True,
) -> str:
    """
    Render the recorded state for an entity formatted according to the validation template.
    Supported types: 'vulnerabilities' and 'semantic_recovery'.
    If omit_empty is True, sections with no recorded items are excluded to save tokens.
    If include_confidence is True, hypotheses include their confidence score, e.g. H1 [0.90].
    """
    normalized = normalize_template_type(template_type)
    state = load_state()
    entry = state.get(entity, {})

    confirmed_facts = entry.get("confirmed_facts", [])
    hypotheses = entry.get("hypotheses", [])
    evidence = entry.get("evidence", [])
    rejected = entry.get("rejected_hypotheses", [])
    candidates = entry.get("candidate_functions", [])
    data_flow = entry.get("data_flow_facts", [])
    type_defs = entry.get("type_definitions", [])

    lines: List[str] = []

    def add_section(title: str, items: List[str]):
        if not items and omit_empty:
            return
        if lines:
            lines.append("")
            lines.append("")
        lines.append(title)
        lines.append("----------------")
        if items:
            for item in items:
                lines.append(item)
        else:
            lines.append("(none)")

    if normalized == "call_graph":
        nodes = entry.get("call_graph_nodes", [])
        edges = entry.get("call_graph_edges", [])
        flows = entry.get("callee_caller_flows", [])

        node_lines: List[str] = []
        for n in nodes:
            if isinstance(n, dict):
                fn = n.get("function", "")
                att = n.get("attention_score", 0.0)
                role = n.get("role", "unknown")
                status = n.get("status", "uninspected")
                ind = n.get("in_degree", 0)
                outd = n.get("out_degree", 0)
                reason = n.get("reason", "")
                line = f"{fn} [Attention: {att:.2f}] [Role: {role}] [Status: {status}] (In: {ind}, Out: {outd})"
                if reason:
                    line += f"\n- reason: {reason}"
                node_lines.append(line)
            else:
                node_lines.append(str(n))
        add_section("Function Priority Queue & Attention Scores", node_lines)

        flow_lines: List[str] = []
        for idx, fl in enumerate(flows, start=1):
            if isinstance(fl, dict):
                fname = fl.get("flow_name", f"Flow {idx}")
                desc = fl.get("description", "")
                chain = fl.get("chain", [])
                header_line = f"Flow {idx} ({fname}):"
                chain_strs = []
                for step_idx, step in enumerate(chain):
                    indent = "  " * (step_idx + 1)
                    arrow = "[Leaf] " if step_idx == 0 else "▲ called by: "
                    chain_strs.append(f"{indent}{arrow}{step}")
                flow_block = header_line
                if desc:
                    flow_block += f" /* {desc} */"
                if chain_strs:
                    flow_block += "\n" + "\n".join(chain_strs)
                flow_lines.append(flow_block)
            else:
                flow_lines.append(str(fl))
        add_section("Bottom-Up Callee-to-Caller Semantic Flows", flow_lines)

        edge_lines: List[str] = []
        for e in edges:
            if isinstance(e, dict):
                cs = f" ({e.get('callsite')})" if e.get("callsite") else ""
                edge_lines.append(f"{e.get('caller')} -> {e.get('callee')}{cs}")
            else:
                edge_lines.append(str(e))
        add_section("Call Graph Edges", edge_lines)

        return "\n".join(lines)

    # 1. Confirmed Facts
    add_section("Confirmed Facts", confirmed_facts)

    # 2. Hypotheses (filter out rejected if desired, or format active hypotheses)
    hyp_lines: List[str] = []
    for idx, h in enumerate(hypotheses, start=1):
        if isinstance(h, dict):
            hid = h.get("id", f"H{idx}")
            claim = h.get("claim", "")
            if h.get("status") == "rejected":
                continue
            conf = h.get("confidence")
            inv_tag = " [INVALIDATED]" if h.get("status") == "invalidated" else ""
            if include_confidence and conf is not None:
                hyp_lines.append(f"{hid} [{conf:.2f}]{inv_tag}: {claim}")
            else:
                hyp_lines.append(f"{hid}{inv_tag}: {claim}")
        else:
            hyp_lines.append(str(h))
    add_section("Hypotheses", hyp_lines)

    # 3. Evidence
    ev_lines: List[str] = []
    for idx, ev in enumerate(evidence, start=1):
        if isinstance(ev, dict):
            eid = ev.get("id", f"E{idx}")
            desc = ev.get("description", "")
            ev_lines.append(f"{eid}: {desc}")
        else:
            ev_lines.append(str(ev))
    add_section("Evidence", ev_lines)

    # 4. Rejected Hypotheses
    rej_lines: List[str] = []
    for idx, r in enumerate(rejected, start=1):
        if isinstance(r, dict):
            rid = r.get("id", f"R{idx}")
            claim = r.get("claim", "")
            reason = r.get("reason")
            if reason:
                rej_lines.append(f"{rid}: {claim} ({reason})")
            else:
                rej_lines.append(f"{rid}: {claim}")
        else:
            rej_lines.append(str(r))
    add_section("Rejected Hypotheses", rej_lines)

    # 5. Functions section (name varies by domain)
    if normalized == "semantic_recovery":
        add_section("Candidate Functions / Signatures", candidates)
        add_section("Data-flow & Control-flow Facts", data_flow)
        add_section("Struct / Type Definitions", type_defs)
    elif normalized == "vulnerabilities":
        add_section("Candidate Functions", candidates)
        add_section("Data-flow Facts", data_flow)

        # Path Constraints (Symbolic)
        pc_lines: List[str] = []
        for pc in entry.get("path_constraints", []):
            if isinstance(pc, dict):
                pid = pc.get("id", "")
                expr = pc.get("expr", "")
                src = pc.get("source_function", "")
                desc = pc.get("description", "")
                neg = " [NEGATED]" if pc.get("is_negated") else ""
                src_str = f" [{src}]" if src else ""
                desc_str = f" ({desc})" if desc else ""
                pc_lines.append(f"{pid}{src_str}: {expr}{neg}{desc_str}")
            else:
                pc_lines.append(str(pc))
        add_section("Path Constraints (Symbolic)", pc_lines)

        # Exploit Primitives Ledger
        prim_lines: List[str] = []
        for p in entry.get("exploit_primitives", []):
            if isinstance(p, dict):
                pid = p.get("primitive_id", "")
                ptype = p.get("type", "")
                target = p.get("target_buffer", "")
                ctrl = p.get("controllable_bytes", "")
                status = p.get("trigger_status", "tentative")
                fn = p.get("associated_function", "")
                parts = [f"{pid} [{ptype}]"]
                if target:
                    parts.append(f"target={target}")
                if ctrl:
                    parts.append(f"controllable={ctrl}")
                if fn:
                    parts.append(f"func={fn}")
                parts.append(f"status={status}")
                prim_lines.append(" | ".join(parts))
            else:
                prim_lines.append(str(p))
        add_section("Exploit Primitives Ledger", prim_lines)
    else:
        add_section("Candidate Functions", candidates)
        add_section("Data-flow Facts", data_flow)

    return "\n".join(lines)


@mcp.tool()
def populate_from_template(
    entity: str, template_type: str, content: str, merge: bool = True
) -> Dict[str, Any]:
    """
    Parse a filled text template and populate the entity state in the Context Manager.
    Sections should be formatted with 'Section Title' followed by '---'.
    If merge is True (default), new facts/items are appended without overwriting existing data.
    """
    normalized = normalize_template_type(template_type)
    state = load_state()
    entry = state.setdefault(entity, {})

    # Split by headers: section title followed by dashes
    sections = re.split(r"\n(?=[A-Za-z0-9 /&()_-]+\n[-=]{3,})", content.strip())

    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue
        parts = re.split(r"\n[-=]{3,}\n", sec, maxsplit=1)
        if len(parts) != 2:
            continue
        header, body = parts[0].strip(), parts[1].strip()
        body_lines = [line.strip() for line in body.splitlines() if line.strip() and line.strip() != "(none)"]

        header_norm = header.lower()
        if "attention" in header_norm or "priority" in header_norm:
            # Parse function priority nodes
            parsed_nodes = []
            curr_node = None
            for line in body.splitlines():
                line_str = line.strip()
                if not line_str or line_str == "(none)":
                    continue
                if line_str.startswith("- reason:"):
                    if curr_node:
                        curr_node["reason"] = line_str.replace("- reason:", "").strip()
                    continue

                m = re.match(
                    r"^([A-Za-z0-9_.$]+)(?:\s*\[Attention:\s*([0-9.]+)\])?(?:\s*\[Role:\s*(.*?)\])?(?:\s*\[Status:\s*(.*?)\])?(?:\s*\(In:\s*(\d+),\s*Out:\s*(\d+)\))?",
                    line_str,
                )
                if m:
                    att = float(m.group(2)) if m.group(2) else 0.5
                    curr_node = {
                        "function": m.group(1),
                        "attention_score": att,
                        "role": m.group(3).strip() if m.group(3) else "unknown",
                        "status": m.group(4).strip() if m.group(4) else "uninspected",
                        "in_degree": int(m.group(5)) if m.group(5) else 0,
                        "out_degree": int(m.group(6)) if m.group(6) else 0,
                        "reason": "",
                    }
                    parsed_nodes.append(curr_node)

            if merge:
                existing = entry.setdefault("call_graph_nodes", [])
                existing_map = {n.get("function"): n for n in existing if isinstance(n, dict)}
                for pn in parsed_nodes:
                    fn = pn.get("function")
                    if fn in existing_map:
                        existing_map[fn].update(pn)
                    else:
                        existing.append(pn)
                existing.sort(key=lambda x: x.get("attention_score", 0.0), reverse=True)
            else:
                parsed_nodes.sort(key=lambda x: x.get("attention_score", 0.0), reverse=True)
                entry["call_graph_nodes"] = parsed_nodes

        elif "callee" in header_norm or "bottom-up" in header_norm or (normalized == "call_graph" and "flow" in header_norm):
            # Parse callee-to-caller flows
            parsed_flows = []
            flow_chunks = re.split(r"(?=Flow\s+\d+)", body)
            for chunk in flow_chunks:
                chunk = chunk.strip()
                if not chunk:
                    continue
                lines_in_chunk = chunk.splitlines()
                first_line = lines_in_chunk[0].strip()
                m_flow = re.match(r"^Flow\s+\d+(?:\s*\((.*?)\))?:\s*(?:/\*\s*(.*?)\s*\*/)?", first_line)
                flow_name = m_flow.group(1).strip() if (m_flow and m_flow.group(1)) else "Flow"
                desc = m_flow.group(2).strip() if (m_flow and m_flow.group(2)) else ""
                chain = []
                for cl in lines_in_chunk[1:]:
                    cleaned = re.sub(r"^[▲\[\]Leafcalledby:\s]+", "", cl.strip())
                    if cleaned:
                        chain.append(cleaned)
                if chain:
                    parsed_flows.append({
                        "flow_name": flow_name,
                        "chain": chain,
                        "description": desc,
                    })

            if merge:
                existing = entry.setdefault("callee_caller_flows", [])
                existing_names = {f.get("flow_name") for f in existing if isinstance(f, dict)}
                for pf in parsed_flows:
                    if pf.get("flow_name") not in existing_names:
                        existing.append(pf)
            else:
                entry["callee_caller_flows"] = parsed_flows

        elif re.search(r"\bedges?\b", header_norm):
            parsed_edges = []
            for line in body_lines:
                m = re.match(r"^([A-Za-z0-9_.$]+)\s*->\s*([A-Za-z0-9_.$()]+)(?:\s*\((.*?)\))?$", line)
                if m:
                    parsed_edges.append({
                        "caller": m.group(1),
                        "callee": m.group(2),
                        "callsite": m.group(3).strip() if m.group(3) else "",
                    })
            if merge:
                existing = entry.setdefault("call_graph_edges", [])
                existing_set = {(e.get("caller"), e.get("callee")) for e in existing if isinstance(e, dict)}
                for pe in parsed_edges:
                    if (pe.get("caller"), pe.get("callee")) not in existing_set:
                        existing.append(pe)
            else:
                entry["call_graph_edges"] = parsed_edges

        elif "confirmed" in header_norm:
            if merge:
                existing = entry.setdefault("confirmed_facts", [])
                for b in body_lines:
                    if b not in existing:
                        existing.append(b)
            else:
                entry["confirmed_facts"] = body_lines

        elif "rejected" in header_norm:
            rej_list = []
            for line in body_lines:
                m = re.match(r"^(R\d+):\s*(.*?)(?:\s*\((.*?)\))?$", line)
                if m:
                    rec = {"id": m.group(1), "claim": m.group(2).strip()}
                    if m.group(3):
                        rec["reason"] = m.group(3).strip()
                    rej_list.append(rec)
                else:
                    rej_list.append({"id": f"R{len(rej_list)+1}", "claim": line})
            if merge:
                existing = entry.setdefault("rejected_hypotheses", [])
                existing_claims = {r.get("claim") for r in existing if isinstance(r, dict)}
                for r in rej_list:
                    if r.get("claim") not in existing_claims:
                        existing.append(r)
            else:
                entry["rejected_hypotheses"] = rej_list

        elif "hypotheses" in header_norm:
            hyp_list = []
            for line in body_lines:
                # Match H1: claim OR H1 [0.90]: claim
                m = re.match(r"^(H\d+)(?:\s*\[([0-9.]+)\])?:\s*(.*)$", line)
                if m:
                    conf = float(m.group(2)) if m.group(2) else 0.8
                    hyp_list.append({
                        "id": m.group(1),
                        "claim": m.group(3).strip(),
                        "confidence": conf,
                        "status": "tentative",
                    })
                else:
                    hyp_list.append({
                        "id": f"H{len(hyp_list)+1}",
                        "claim": line,
                        "confidence": 0.8,
                        "status": "tentative",
                    })
            if merge:
                existing = entry.setdefault("hypotheses", [])
                existing_ids = {h.get("id"): h for h in existing if isinstance(h, dict)}
                for h in hyp_list:
                    hid = h.get("id")
                    if hid in existing_ids:
                        existing_ids[hid]["claim"] = h["claim"]
                        existing_ids[hid]["confidence"] = h["confidence"]
                    else:
                        existing.append(h)
            else:
                entry["hypotheses"] = hyp_list

        elif "evidence" in header_norm:
            ev_list = []
            for line in body_lines:
                m = re.match(r"^(E\d+):\s*(.*)$", line)
                if m:
                    ev_list.append({"id": m.group(1), "description": m.group(2).strip()})
                else:
                    ev_list.append({"id": f"E{len(ev_list)+1}", "description": line})
            if merge:
                existing = entry.setdefault("evidence", [])
                existing_ids = {e.get("id"): e for e in existing if isinstance(e, dict)}
                for e in ev_list:
                    eid = e.get("id")
                    if eid in existing_ids:
                        existing_ids[eid]["description"] = e["description"]
                    else:
                        existing.append(e)
            else:
                entry["evidence"] = ev_list

        elif "candidate" in header_norm or "function" in header_norm:
            if merge:
                existing = entry.setdefault("candidate_functions", [])
                for b in body_lines:
                    if b not in existing:
                        existing.append(b)
            else:
                entry["candidate_functions"] = body_lines

        elif "flow" in header_norm:
            if merge:
                existing = entry.setdefault("data_flow_facts", [])
                for b in body_lines:
                    if b not in existing:
                        existing.append(b)
            else:
                entry["data_flow_facts"] = body_lines

        elif "struct" in header_norm or "type" in header_norm:
            if merge:
                existing = entry.setdefault("type_definitions", [])
                if body not in existing:
                    existing.append(body)
            else:
                entry["type_definitions"] = [body]

        elif "constraint" in header_norm:
            pc_list = []
            for line in body_lines:
                m = re.match(r"^(PC\d+)?(?:\s*\[(.*?)\])?:\s*(.*?)(?:\s*\((.*?)\))?$", line)
                if m:
                    cid = m.group(1) or f"PC{len(pc_list)+1}"
                    fn = m.group(2) or ""
                    expr = m.group(3).strip()
                    desc = m.group(4) or ""
                    is_neg = "[NEGATED]" in expr
                    expr = expr.replace("[NEGATED]", "").strip()
                    pc_list.append({
                        "id": cid,
                        "expr": expr,
                        "source_function": fn,
                        "is_negated": is_neg,
                        "description": desc,
                    })
                else:
                    pc_list.append({
                        "id": f"PC{len(pc_list)+1}",
                        "expr": line,
                        "source_function": "",
                        "is_negated": False,
                        "description": "",
                    })
            if merge:
                existing = entry.setdefault("path_constraints", [])
                existing_ids = {p.get("id"): p for p in existing if isinstance(p, dict)}
                for p in pc_list:
                    pid = p.get("id")
                    if pid in existing_ids:
                        existing_ids[pid].update(p)
                    else:
                        existing.append(p)
            else:
                entry["path_constraints"] = pc_list

        elif "primitive" in header_norm:
            prim_list = []
            for line in body_lines:
                parts = [p.strip() for p in line.split("|")]
                first = parts[0]
                m = re.match(r"^(P\d+)?(?:\s*\[(.*?)\])?", first)
                pid = (m.group(1) if m else None) or f"P{len(prim_list)+1}"
                ptype = (m.group(2) if m else None) or "VULNERABILITY"
                target = ""
                ctrl = ""
                status = "tentative"
                fn = ""
                for part in parts[1:]:
                    if part.startswith("target="):
                        target = part.replace("target=", "").strip()
                    elif part.startswith("controllable="):
                        ctrl = part.replace("controllable=", "").strip()
                    elif part.startswith("func="):
                        fn = part.replace("func=", "").strip()
                    elif part.startswith("status="):
                        status = part.replace("status=", "").strip()
                prim_list.append({
                    "primitive_id": pid,
                    "type": ptype,
                    "target_buffer": target,
                    "controllable_bytes": ctrl,
                    "trigger_status": status,
                    "associated_function": fn,
                    "details": line,
                })
            if merge:
                existing = entry.setdefault("exploit_primitives", [])
                existing_ids = {p.get("primitive_id"): p for p in existing if isinstance(p, dict)}
                for p in prim_list:
                    pid = p.get("primitive_id")
                    if pid in existing_ids:
                        existing_ids[pid].update(p)
                    else:
                        existing.append(p)
            else:
                entry["exploit_primitives"] = prim_list

    save_state(state)
    return entry


# ==========================================
# FastMCP Resources & Prompts
# ==========================================

@mcp.resource("template://vulnerabilities")
def get_vulnerabilities_template_resource() -> str:
    """Resource returning the Vulnerability Validation template specification."""
    return VULNERABILITY_TEMPLATE_EXAMPLE


@mcp.resource("template://semantic_recovery")
def get_semantic_recovery_template_resource() -> str:
    """Resource returning the Semantic Recovery template specification."""
    return SEMANTIC_RECOVERY_TEMPLATE_EXAMPLE


@mcp.resource("template://call_graph")
def get_call_graph_template_resource() -> str:
    """Resource returning the Call Graph & Attention Topology template specification."""
    return CALL_GRAPH_TEMPLATE_EXAMPLE


@mcp.prompt("vulnerability_validation")
def vulnerability_validation_prompt(target_entity: str = "") -> str:
    """
    Prompt guide instructing the agent on performing vulnerability validation
    using the structured Context Manager template.
    """
    entity_str = f" for entity '{target_entity}'" if target_entity else ""
    return f"""You are performing a vulnerability validation analysis{entity_str}.
Follow this exact structured format and update the Context Manager accordingly:

{VULNERABILITY_TEMPLATE_EXAMPLE}

Rules:
1. Only record Confirmed Facts when verified in source, binary disassembly, or execution traces.
2. Label Hypotheses with H1, H2, etc., and record your confidence in the Context Manager.
3. Tie every piece of Evidence (E1, E2, ...) directly to a hypothesis.
4. Record Rejected Hypotheses (R1, R2, ...) to prevent dead-end cycling.
5. Trace explicit data-flow chains from source to sink in Data-flow Facts.
"""


@mcp.prompt("semantic_recovery")
def semantic_recovery_prompt(target_entity: str = "") -> str:
    """
    Prompt guide instructing the agent on performing reverse-engineering semantic recovery
    using the structured Context Manager template.
    """
    entity_str = f" for entity '{target_entity}'" if target_entity else ""
    return f"""You are performing semantic recovery and reverse-engineering{entity_str}.
Follow this exact structured format and update the Context Manager accordingly:

{SEMANTIC_RECOVERY_TEMPLATE_EXAMPLE}

Rules:
1. Confirmed Facts must be verified through decompiled code, exports, or verified cross-references.
2. Formulate behavioral Hypotheses (H1, H2, ...) regarding function purpose and roles.
3. Link concrete Evidence (E1, E2, ...) such as constant values, API calls, or control patterns.
4. Document Rejected Hypotheses (R1, R2, ...) when assumptions are invalidated.
5. Record recovered Candidate Functions / Signatures.
6. Map Data-flow & Control-flow progressions.
7. Reconstruct C Struct / Type Definitions with explicit field offsets and types.
"""


@mcp.prompt("call_graph_triage")
def call_graph_triage_prompt(target_entity: str = "") -> str:
    """
    Prompt guide instructing the agent on mapping the subsystem call graph, assigning attention scores,
    and recording bottom-up callee-to-caller semantic propagation.
    """
    entity_str = f" for entity '{target_entity}'" if target_entity else ""
    return f"""You are analyzing the call graph topology and function triage priority{entity_str}.
Follow this exact structured format and update the Context Manager accordingly:

{CALL_GRAPH_TEMPLATE_EXAMPLE}

Rules:
1. Assign Attention Scores (0.0 to 1.0) to prioritize high-value targets (sinks, parsers, crypto, hub dispatchers).
2. Use get_attention_queue() to prioritize the next functions to decompile and inspect.
3. Trace Bottom-Up Callee-to-Caller Semantic Flows starting from known library/syscall leaves.
4. Record directional Call Graph Edges (caller -> callee).
5. Mark function node statuses as 'uninspected', 'in_progress', or 'analyzed'.
"""


if __name__ == "__main__":
    mcp.run()
