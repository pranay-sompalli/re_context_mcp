import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import context_server


@pytest.fixture(autouse=True)
def isolated_state_file(tmp_path, monkeypatch):
    """Ensure each test runs against a clean temporary state file."""
    test_state_file = tmp_path / "test_state.json"
    monkeypatch.setenv("RE_STATE_FILE", str(test_state_file))
    yield test_state_file
    if test_state_file.exists():
        test_state_file.unlink()


def test_get_state_empty():
    state = context_server.get_state("function:dummy")
    assert state == {}


def test_set_note():
    entity = "function:add_numbers"
    res1 = context_server.set_note(entity, "Observation 1: takes 2 arguments")
    assert "notes" in res1
    assert len(res1["notes"]) == 1
    assert res1["notes"][0] == "Observation 1: takes 2 arguments"

    res2 = context_server.set_note(entity, "Observation 2: returns sum")
    assert len(res2["notes"]) == 2
    assert res2["notes"][1] == "Observation 2: returns sum"

    # Verify persistence by reading from disk
    stored = context_server.get_state(entity)
    assert stored == res2


def test_add_hypothesis_valid():
    entity = "function:add_numbers"
    res = context_server.add_hypothesis(
        entity=entity,
        claim="Function implements 32-bit signed addition",
        confidence=0.95,
    )
    assert "hypotheses" in res
    assert len(res["hypotheses"]) == 1
    hyp = res["hypotheses"][0]
    assert hyp["id"] == "H1"
    assert hyp["claim"] == "Function implements 32-bit signed addition"
    assert hyp["confidence"] == 0.95
    assert hyp["status"] == "tentative"

    # Adding a second auto-generates H2
    res2 = context_server.add_hypothesis(
        entity=entity,
        claim="Overflow produces wrapped value",
        confidence=0.8,
    )
    assert len(res2["hypotheses"]) == 2
    assert res2["hypotheses"][1]["id"] == "H2"


def test_add_hypothesis_invalid_confidence():
    entity = "function:add_numbers"
    with pytest.raises(ValueError, match="Confidence must be a float between 0.0 and 1.0"):
        context_server.add_hypothesis(entity, "Invalid confidence > 1", 1.2)

    with pytest.raises(ValueError, match="Confidence must be a float between 0.0 and 1.0"):
        context_server.add_hypothesis(entity, "Invalid confidence < 0", -0.1)


def test_clear_state():
    entity = "function:add_numbers"
    context_server.set_note(entity, "Note to clear")
    assert context_server.get_state(entity) != {}

    clear_res = context_server.clear_state(entity)
    assert clear_res["cleared"] == entity
    assert clear_res["status"] == "deleted"
    assert context_server.get_state(entity) == {}

    # Clearing again returns not_found
    clear_again = context_server.clear_state(entity)
    assert clear_again["status"] == "not_found"


def test_list_entities_and_get_all_state():
    context_server.set_note("function:a", "Note A")
    context_server.set_note("function:b", "Note B")

    entities = context_server.list_entities()
    assert set(entities) == {"function:a", "function:b"}

    all_state = context_server.get_all_state()
    assert "function:a" in all_state
    assert "function:b" in all_state


def test_validation_template_get():
    vuln_tpl = context_server.get_validation_template("vulnerabilities")
    assert "Confirmed Facts" in vuln_tpl
    assert "Hypotheses" in vuln_tpl
    assert "Candidate Functions" in vuln_tpl
    assert "Data-flow Facts" in vuln_tpl

    sem_tpl = context_server.get_validation_template("semantic_recovery")
    assert "Candidate Functions / Signatures" in sem_tpl
    assert "Data-flow & Control-flow Facts" in sem_tpl
    assert "Struct / Type Definitions" in sem_tpl


def test_facts_evidence_and_hypotheses():
    entity = "vuln:cve-2024-test"
    context_server.record_fact(entity, "process() calls parse()")
    context_server.record_fact(entity, "parse() reads length")

    context_server.record_evidence(entity, "length comes from file header")
    context_server.record_evidence(entity, "multiplication occurs before allocation")

    context_server.add_hypothesis(entity, "integer overflow causes undersized allocation", 0.9)
    context_server.add_hypothesis(entity, "attacker controls length", 0.85)

    st = context_server.get_state(entity)
    assert len(st["confirmed_facts"]) == 2
    assert len(st["evidence"]) == 2
    assert st["evidence"][0]["id"] == "E1"
    assert st["evidence"][1]["id"] == "E2"
    assert st["hypotheses"][0]["id"] == "H1"
    assert st["hypotheses"][1]["id"] == "H2"


def test_reject_hypothesis():
    entity = "vuln:cve-2024-test"
    context_server.add_hypothesis(entity, "vulnerability is in validate()", 0.5)
    context_server.add_hypothesis(entity, "integer overflow occurs in allocator", 0.9)

    context_server.reject_hypothesis(entity, "H1", reason="validate() is called after sanitize()")

    st = context_server.get_state(entity)
    # Check that H1 status is marked rejected
    assert st["hypotheses"][0]["status"] == "rejected"
    assert len(st["rejected_hypotheses"]) == 1
    assert st["rejected_hypotheses"][0]["id"] == "R1"
    assert "validate()" in st["rejected_hypotheses"][0]["claim"]
    assert "validate() is called after sanitize()" in st["rejected_hypotheses"][0]["reason"]


def test_render_vulnerabilities_template():
    entity = "target:binary_parse"
    context_server.record_fact(entity, "process() calls parse()")
    context_server.record_fact(entity, "parse() reads length")
    context_server.add_hypothesis(entity, "integer overflow causes undersized allocation", 0.9)
    context_server.record_evidence(entity, "length comes from file header")
    context_server.reject_hypothesis(entity, "vulnerability is in validate()", reason="code reviewed")
    context_server.add_candidate_function(entity, "parse_header()")
    context_server.add_data_flow_fact(entity, "input → length → multiplication → allocation")

    rendered = context_server.render_template(entity, "vulnerabilities")
    assert "Confirmed Facts" in rendered
    assert "process() calls parse()" in rendered
    assert "H1 [0.90]: integer overflow causes undersized allocation" in rendered
    assert "E1: length comes from file header" in rendered
    assert "R1: vulnerability is in validate() (code reviewed)" in rendered
    assert "parse_header()" in rendered
    assert "input → length → multiplication → allocation" in rendered


def test_render_semantic_recovery_template():
    entity = "func:sub_401000"
    context_server.record_fact(entity, "decompiled sub_401000 accepts socket descriptor")
    context_server.add_hypothesis(entity, "function implements TLS record framing", 0.9)
    context_server.record_evidence(entity, "magic byte 0x16 checked at offset 0")
    context_server.add_candidate_function(entity, "tls_read_record(session_t *session) -> int")
    context_server.add_data_flow_fact(entity, "socket → recv() → buffer → decrypt_payload()")
    context_server.add_type_definition(entity, "struct session_t { int socket_fd; };")

    rendered = context_server.render_template(entity, "semantic_recovery")
    assert "Confirmed Facts" in rendered
    assert "decompiled sub_401000 accepts socket descriptor" in rendered
    assert "Candidate Functions / Signatures" in rendered
    assert "tls_read_record(session_t *session) -> int" in rendered
    assert "Data-flow & Control-flow Facts" in rendered
    assert "Struct / Type Definitions" in rendered
    assert "struct session_t { int socket_fd; };" in rendered


def test_render_template_omit_empty():
    entity = "func:sparse"
    context_server.record_fact(entity, "single fact recorded")

    # With omit_empty=True, sections without items are excluded
    rendered_compact = context_server.render_template(entity, "semantic_recovery", omit_empty=True)
    assert "Confirmed Facts" in rendered_compact
    assert "single fact recorded" in rendered_compact
    assert "Hypotheses" not in rendered_compact
    assert "(none)" not in rendered_compact

    # With omit_empty=False, (none) is rendered
    rendered_full = context_server.render_template(entity, "semantic_recovery", omit_empty=False)
    assert "(none)" in rendered_full


def test_populate_from_template():
    sample = """Confirmed Facts
----------------
process() calls parse()
parse() reads length

Hypotheses
----------------
H1 [0.95]: integer overflow causes undersized allocation
H2: attacker controls length

Evidence
----------------
E1: length comes from file header

Rejected Hypotheses
----------------
R1: vulnerability is in validate()

Candidate Functions
----------------
parse_header()
process_file()

Data-flow Facts
----------------
input → length → multiplication → allocation"""

    res = context_server.populate_from_template("entity:imported", "vulnerabilities", sample)
    assert len(res["confirmed_facts"]) == 2
    assert len(res["hypotheses"]) == 2
    assert res["hypotheses"][0]["id"] == "H1"
    assert res["hypotheses"][0]["confidence"] == 0.95
    assert res["hypotheses"][1]["confidence"] == 0.8  # default when unspecified
    assert len(res["evidence"]) == 1
    assert len(res["rejected_hypotheses"]) == 1
    assert len(res["candidate_functions"]) == 2
    assert res["data_flow_facts"] == ["input → length → multiplication → allocation"]


def test_populate_from_template_merge():
    entity = "entity:merge_test"
    context_server.record_fact(entity, "existing initial fact")

    update_sample = """Confirmed Facts
----------------
newly discovered fact

Hypotheses
----------------
H1 [0.88]: potential race condition"""

    res = context_server.populate_from_template(entity, "vulnerabilities", update_sample, merge=True)
    # Existing fact should be preserved alongside the new one
    assert len(res["confirmed_facts"]) == 2
    assert "existing initial fact" in res["confirmed_facts"]
    assert "newly discovered fact" in res["confirmed_facts"]
    assert res["hypotheses"][0]["confidence"] == 0.88


def test_call_graph_nodes_and_attention_queue():
    entity = "module:crypto_dispatch"
    # Invalid score validation
    with pytest.raises(ValueError, match="attention_score must be a float between 0.0 and 1.0"):
        context_server.add_call_graph_node(entity, "sub_1", 1.5)

    # Add multiple nodes
    context_server.add_call_graph_node(
        entity, "sub_low", 0.15, role="Utility", reason="Trivial wrapper", status="uninspected"
    )
    context_server.add_call_graph_node(
        entity, "sub_high", 0.95, role="Crypto/Sink", reason="AES S-box constant", status="uninspected"
    )
    context_server.add_call_graph_node(
        entity, "sub_mid", 0.70, role="Parser", reason="Header unpack", status="in_progress"
    )

    # Verify descending ordering
    state = context_server.get_state(entity)
    assert len(state["call_graph_nodes"]) == 3
    assert state["call_graph_nodes"][0]["function"] == "sub_high"
    assert state["call_graph_nodes"][1]["function"] == "sub_mid"
    assert state["call_graph_nodes"][2]["function"] == "sub_low"

    # Queue filtering
    queue_all = context_server.get_attention_queue(entity)
    assert len(queue_all) == 3
    assert queue_all[0]["function"] == "sub_high"

    queue_high = context_server.get_attention_queue(entity, min_score=0.5)
    assert len(queue_high) == 2
    assert [n["function"] for n in queue_high] == ["sub_high", "sub_mid"]

    queue_uninspected = context_server.get_attention_queue(entity, min_score=0.5, status_filter="uninspected")
    assert len(queue_uninspected) == 1
    assert queue_uninspected[0]["function"] == "sub_high"

    # Update node status
    context_server.update_call_graph_node_status(entity, "sub_high", "analyzed", updated_role="AES-GCM-Decrypt")
    updated_queue = context_server.get_attention_queue(entity, status_filter="analyzed")
    assert len(updated_queue) == 1
    assert updated_queue[0]["function"] == "sub_high"
    assert updated_queue[0]["role"] == "AES-GCM-Decrypt"


def test_call_edges_and_degree_tracking():
    entity = "module:network"
    context_server.add_call_graph_node(entity, "caller_fn", 0.8)
    context_server.add_call_graph_node(entity, "callee_fn", 0.5)

    context_server.add_call_edge(entity, "caller_fn", "callee_fn", callsite="0x401020")

    state = context_server.get_state(entity)
    assert len(state["call_graph_edges"]) == 1
    assert state["call_graph_edges"][0] == {
        "caller": "caller_fn",
        "callee": "callee_fn",
        "callsite": "0x401020",
    }

    # Verify in/out degrees updated
    nodes_by_fn = {n["function"]: n for n in state["call_graph_nodes"]}
    assert nodes_by_fn["caller_fn"]["out_degree"] == 1
    assert nodes_by_fn["caller_fn"]["in_degree"] == 0
    assert nodes_by_fn["callee_fn"]["in_degree"] == 1
    assert nodes_by_fn["callee_fn"]["out_degree"] == 0


def test_callee_caller_flows():
    entity = "module:pipeline"
    chain = ["EVP_DecryptUpdate() [OpenSSL]", "sub_401340 (aes_decrypt)", "sub_402000 (dispatch)"]
    context_server.record_callee_caller_flow(
        entity, "Crypto Pipeline", chain, description="Primary decryption flow"
    )

    state = context_server.get_state(entity)
    assert "callee_caller_flows" in state
    assert len(state["callee_caller_flows"]) == 1
    flow = state["callee_caller_flows"][0]
    assert flow["flow_name"] == "Crypto Pipeline"
    assert len(flow["chain"]) == 3
    assert flow["description"] == "Primary decryption flow"


def test_render_and_populate_call_graph_template():
    entity = "module:test_template"
    # Seed state
    context_server.add_call_graph_node(
        entity, "sub_sink", 0.95, role="Sink", reason="malloc without bound", in_degree=0, out_degree=0
    )
    context_server.add_call_graph_node(
        entity, "sub_root", 0.80, role="Dispatcher", reason="recv() handler", in_degree=0, out_degree=0
    )
    context_server.add_call_edge(entity, "sub_root", "sub_sink")
    context_server.record_callee_caller_flow(
        entity, "Alloc Flow", ["malloc() [System]", "sub_sink", "sub_root"]
    )

    rendered = context_server.render_template(entity, template_type="call_graph")
    assert "Function Priority Queue & Attention Scores" in rendered
    assert "sub_sink [Attention: 0.95] [Role: Sink] [Status: uninspected] (In: 1, Out: 0)" in rendered
    assert "- reason: malloc without bound" in rendered
    assert "Bottom-Up Callee-to-Caller Semantic Flows" in rendered
    assert "[Leaf] malloc() [System]" in rendered
    assert "Call Graph Edges" in rendered
    assert "sub_root -> sub_sink" in rendered

    # Populate from template into a fresh entity
    target_entity = "module:populated_graph"
    context_server.populate_from_template(target_entity, "call_graph", rendered)

    target_state = context_server.get_state(target_entity)
    assert len(target_state["call_graph_nodes"]) == 2
    assert target_state["call_graph_nodes"][0]["function"] == "sub_sink"
    assert target_state["call_graph_nodes"][0]["attention_score"] == 0.95
    assert len(target_state["call_graph_edges"]) == 1
    assert target_state["call_graph_edges"][0]["caller"] == "sub_root"
    assert len(target_state["callee_caller_flows"]) == 1


def test_find_call_paths():
    entity = "module:traversal_test"
    # Construct graph:
    # ingress -> parser -> alloc -> malloc
    # ingress -> validator -> alloc -> malloc
    # cycle: parser -> parser_helper -> parser
    # disconnected: unused_fn -> logging
    context_server.add_call_edge(entity, "ingress", "parser")
    context_server.add_call_edge(entity, "ingress", "validator")
    context_server.add_call_edge(entity, "parser", "alloc")
    context_server.add_call_edge(entity, "validator", "alloc")
    context_server.add_call_edge(entity, "alloc", "malloc")
    context_server.add_call_edge(entity, "parser", "parser_helper")
    context_server.add_call_edge(entity, "parser_helper", "parser") # cycle
    context_server.add_call_edge(entity, "unused_fn", "logging")

    # Find paths from ingress to malloc
    res = context_server.find_call_paths(entity, "ingress", "malloc")
    assert res["reachable"] is True
    assert res["path_count"] == 2
    assert res["shortest_distance"] == 3
    assert ["ingress", "parser", "alloc", "malloc"] in res["paths"]
    assert ["ingress", "validator", "alloc", "malloc"] in res["paths"]
    assert "alloc" in res["intermediate_functions"]

    # Test unreachable sink
    unreachable_res = context_server.find_call_paths(entity, "ingress", "logging")
    assert unreachable_res["reachable"] is False
    assert unreachable_res["path_count"] == 0
    assert unreachable_res["shortest_distance"] == -1

    # Test unknown source
    unknown_src = context_server.find_call_paths(entity, "non_existent", "malloc")
    assert unknown_src["reachable"] is False


def test_render_mermaid_graph():
    entity = "module:mermaid_test"
    # Empty entity
    empty_mermaid = context_server.render_mermaid_graph("module:non_existent")
    assert "graph TD" in empty_mermaid
    assert "No call graph nodes or edges recorded" in empty_mermaid

    # Add nodes and edges
    context_server.add_call_graph_node(
        entity, "func_crypto", 0.95, role="Crypto", status="uninspected"
    )
    context_server.add_call_graph_node(
        entity, "func_done", 0.30, role="Helper", status="analyzed"
    )
    context_server.add_call_graph_node(
        entity, "func_wip", 0.75, role="Parser", status="in_progress"
    )
    context_server.add_call_edge(entity, "func_wip", "func_crypto", callsite="0x401050")
    context_server.add_call_edge(entity, "func_crypto", "func_done")

    mermaid_out = context_server.render_mermaid_graph(entity, orientation="LR")
    assert "graph LR" in mermaid_out
    assert "n_func_crypto" in mermaid_out
    assert "(Crypto)" in mermaid_out
    assert "Att: 0.95" in mermaid_out
    assert '-->|"0x401050"| n_func_crypto' in mermaid_out
    assert "classDef high_attention" in mermaid_out
    assert "classDef analyzed" in mermaid_out
    assert "classDef in_progress" in mermaid_out


def test_invalidation_cascades():
    entity = "module:cascade_test"
    # H1: root assumption
    context_server.add_hypothesis(entity, "Algorithm uses AES-GCM", 0.9)
    # H2 depends on H1
    context_server.add_hypothesis(entity, "Key length is 256 bits", 0.85, depends_on=["H1"])
    # H3 depends on H2 (multi-tier)
    context_server.add_hypothesis(entity, "IV is passed in *(arg1 + 0x10)", 0.8, depends_on=["H2"])
    # Independent H4
    context_server.add_hypothesis(entity, "Buffer resides on heap", 0.7, depends_on=[])

    # Call graph node tied to H1
    context_server.add_call_graph_node(
        entity, "sub_crypto", 0.95, role="Crypto", reason="Implements H1 AES-GCM engine"
    )

    # Reject H1
    context_server.reject_hypothesis(entity, "H1", reason="Constants match ChaCha20, not AES")

    state = context_server.get_state(entity)
    hyp_by_id = {h["id"]: h for h in state["hypotheses"]}

    # H1 is rejected
    assert hyp_by_id["H1"]["status"] == "rejected"
    # H2 and H3 are cascade-invalidated
    assert hyp_by_id["H2"]["status"] == "invalidated"
    assert "Upstream dependency H1 was rejected" in hyp_by_id["H2"]["invalidation_reason"]
    assert hyp_by_id["H3"]["status"] == "invalidated"
    assert "Upstream dependency H2 was rejected" in hyp_by_id["H3"]["invalidation_reason"]
    # H4 remains tentative
    assert hyp_by_id["H4"]["status"] == "tentative"

    # Call graph node reason is updated
    nodes_by_fn = {n["function"]: n for n in state["call_graph_nodes"]}
    assert "[INVALIDATED - H1 rejected]" in nodes_by_fn["sub_crypto"]["reason"]

    # Verify template rendering displays [INVALIDATED]
    rendered = context_server.render_template(entity, template_type="semantic_recovery")
    assert "H2 [0.85] [INVALIDATED]: Key length is 256 bits" in rendered


def test_detect_epistemic_conflicts():
    entity = "module:conflict_test"
    # Add high-confidence hypothesis H1
    context_server.add_hypothesis(entity, "Function parses TLS header", 0.85)

    # 1. Add refuting evidence against H1 without lowering confidence
    context_server.record_evidence(entity, "Magic bytes are 0x50 0x4B (ZIP header), [refutes H1]")

    conflicts_res = context_server.detect_epistemic_conflicts(entity)
    assert conflicts_res["status"] == "conflicts_found"
    assert conflicts_res["conflict_count"] >= 1
    refute_conflict = next(c for c in conflicts_res["conflicts"] if c["type"] == "refuting_evidence_conflict")
    assert refute_conflict["hypothesis_id"] == "H1"
    assert refute_conflict["severity"] == "high"

    # 2. Add H2 depending on H1, then reject H1
    context_server.add_hypothesis(entity, "Payload is TLS record data", 0.75, depends_on=["H1"])
    context_server.reject_hypothesis(entity, "H1", reason="Verified to be ZIP parser")

    # Add active H3 illegally depending on rejected H1
    context_server.add_hypothesis(entity, "Handshake state machine", 0.60, depends_on=["H1"])

    conflicts_res2 = context_server.detect_epistemic_conflicts(entity)
    broken_dep = next(c for c in conflicts_res2["conflicts"] if c["type"] == "broken_dependency")
    assert broken_dep["hypothesis_id"] == "H3"
    assert broken_dep["broken_upstream_id"] == "H1"
    assert broken_dep["severity"] == "critical"

    # 3. Add high attention call node with invalidated reason
    context_server.add_call_graph_node(
        entity, "sub_stale", 0.90, reason="H1 TLS parser"
    )
    conflicts_res3 = context_server.detect_epistemic_conflicts(entity)
    stale_prio = next(c for c in conflicts_res3["conflicts"] if c["type"] == "stale_attention_priority")
    assert stale_prio["function"] == "sub_stale"


def test_record_and_list_path_constraints(isolated_state_file):
    entity = "vuln:cve-test"
    res1 = context_server.record_path_constraint(
        entity, "length > 0", source_function="parse_header", description="non-empty check"
    )
    assert len(res1["path_constraints"]) == 1
    assert res1["path_constraints"][0]["id"] == "PC1"
    assert res1["path_constraints"][0]["expr"] == "length > 0"
    assert res1["path_constraints"][0]["source_function"] == "parse_header"

    res2 = context_server.record_path_constraint(
        entity, "length < 100", source_function="alloc_buf", is_negated=True
    )
    assert len(res2["path_constraints"]) == 2
    assert res2["path_constraints"][1]["id"] == "PC2"
    assert res2["path_constraints"][1]["is_negated"] is True

    # Test listing
    all_pcs = context_server.list_path_constraints(entity)
    assert len(all_pcs) == 2
    header_pcs = context_server.list_path_constraints(entity, source_function="parse_header")
    assert len(header_pcs) == 1
    assert header_pcs[0]["id"] == "PC1"


def test_record_and_update_exploit_primitives(isolated_state_file):
    entity = "vuln:cve-test"
    res = context_server.record_exploit_primitive(
        entity,
        primitive_type="HEAP_BUFFER_OVERFLOW",
        target_buffer="heap_chunk_0x40",
        controllable_bytes="length - alloc_size",
        trigger_status="tentative",
        associated_function="sub_402100",
        applied_constraints=["PC1", "PC2"],
    )
    assert len(res["exploit_primitives"]) == 1
    p = res["exploit_primitives"][0]
    assert p["primitive_id"] == "P1"
    assert p["type"] == "HEAP_BUFFER_OVERFLOW"
    assert p["trigger_status"] == "tentative"

    # List primitives
    prims = context_server.list_exploit_primitives(entity, status_filter="tentative")
    assert len(prims) == 1

    # Update status
    res_up = context_server.update_exploit_primitive_status(
        entity, "P1", status="verified", verification_notes="Z3 reachability proved"
    )
    p_up = res_up["exploit_primitives"][0]
    assert p_up["trigger_status"] == "verified"
    assert p_up["verification_notes"] == "Z3 reachability proved"


def test_solve_reachability_sat_integer_overflow(isolated_state_file):
    entity = "vuln:cve-overflow"
    context_server.record_path_constraint(entity, "length > 0", source_function="parse")
    context_server.record_path_constraint(entity, "alloc_size = (length * 4) & 0xffffffff", source_function="alloc")
    context_server.record_path_constraint(entity, "length > 0x40000000", source_function="alloc")

    res = context_server.solve_reachability(
        entity,
        target_condition="alloc_size < length",
        variable_types={"length": "uint32", "alloc_size": "uint32"},
        bit_width=32,
    )
    assert res["status"] == "SATISFIABLE"
    assert res["is_reachable"] is True
    assert "length" in res["satisfying_model"]
    assert "alloc_size" in res["satisfying_model"]
    # Check that model satisfies condition
    len_val = res["satisfying_model"]["length"]["decimal"]
    alloc_val = res["satisfying_model"]["alloc_size"]["decimal"]
    assert len_val > 0x40000000
    assert alloc_val < len_val


def test_solve_reachability_unsat_bounded(isolated_state_file):
    entity = "vuln:cve-bounded"
    context_server.record_path_constraint(entity, "length > 0")
    context_server.record_path_constraint(entity, "length < 100")
    context_server.record_path_constraint(entity, "alloc_size == length * 4")

    res = context_server.solve_reachability(
        entity,
        target_condition="alloc_size < length",
        variable_types={"length": "uint32", "alloc_size": "uint32"},
        bit_width=32,
    )
    assert res["status"] == "UNSATISFIABLE"
    assert res["is_reachable"] is False


def test_render_and_populate_vulnerabilities_with_constraints(isolated_state_file):
    entity = "vuln:render-test"
    context_server.record_path_constraint(
        entity, "length > 0", source_function="parse_header", description="non-empty check"
    )
    context_server.record_exploit_primitive(
        entity,
        primitive_type="HEAP_BUFFER_OVERFLOW",
        target_buffer="heap_chunk_0x40",
        controllable_bytes="length - alloc_size",
        trigger_status="verified",
        associated_function="allocate_buffer",
    )

    rendered = context_server.render_template(entity, "vulnerabilities")
    assert "Path Constraints (Symbolic)" in rendered
    assert "PC1 [parse_header]: length > 0 (non-empty check)" in rendered
    assert "Exploit Primitives Ledger" in rendered
    assert "P1 [HEAP_BUFFER_OVERFLOW]" in rendered
    assert "target=heap_chunk_0x40" in rendered
    assert "status=verified" in rendered

    # Test round-trip populate
    entity2 = "vuln:populated-test"
    context_server.populate_from_template(entity2, "vulnerabilities", rendered)
    state2 = context_server.get_state(entity2)
    assert len(state2.get("path_constraints", [])) == 1
    assert state2["path_constraints"][0]["expr"] == "length > 0"
    assert len(state2.get("exploit_primitives", [])) == 1
    assert state2["exploit_primitives"][0]["type"] == "HEAP_BUFFER_OVERFLOW"


def test_delete_and_clear_path_constraints(isolated_state_file):
    entity = "vuln:branch-test"
    context_server.record_path_constraint(entity, "x > 0")
    context_server.record_path_constraint(entity, "x < 100")
    context_server.record_path_constraint(entity, "y == x * 2")

    pcs = context_server.list_path_constraints(entity)
    assert len(pcs) == 3

    # Delete specific constraint
    res_del = context_server.delete_path_constraint(entity, "PC2")
    assert len(res_del["path_constraints"]) == 2
    assert [c["id"] for c in res_del["path_constraints"]] == ["PC1", "PC3"]

    # Clear all constraints
    res_clear = context_server.clear_path_constraints(entity)
    assert len(res_clear["path_constraints"]) == 0


def test_explain_unreachability_unsat_core(isolated_state_file):
    entity = "vuln:core-test"
    context_server.record_path_constraint(entity, "length > 100", source_function="parse_header")
    context_server.record_path_constraint(entity, "length <= 50", source_function="sanitize_len")
    context_server.record_path_constraint(entity, "flags != 0", source_function="check_flags")

    # Diagnose target condition
    res = context_server.explain_unreachability(
        entity,
        target_condition="length == 75",
        variable_types={"length": "uint32"},
        bit_width=32,
    )
    assert res["status"] == "UNSATISFIABLE"
    assert res["is_reachable"] is False
    assert "PC1" in res["unsat_core_ids"] or "PC2" in res["unsat_core_ids"]
    assert "flags != 0" not in [c.get("expr") for c in res["conflicting_constraints"]]


def test_solve_variable_bounds(isolated_state_file):
    entity = "vuln:bounds-test"
    context_server.record_path_constraint(entity, "length > 10")
    context_server.record_path_constraint(entity, "length <= 1024")

    res = context_server.solve_variable_bounds(
        entity,
        variable_name="length",
        variable_types={"length": "uint32"},
        bit_width=32,
    )
    assert res["status"] == "BOUNDED"
    assert res["min"]["decimal"] == 11
    assert res["max"]["decimal"] == 1024
