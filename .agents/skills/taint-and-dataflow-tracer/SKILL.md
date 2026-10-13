---
name: taint-and-dataflow-tracer
description: >-
  Use this skill to track untrusted input progression (taint analysis) from external sources
  to sensitive sinks across multiple functions using Claude, Ghidra MCP, and re_context MCP.
---

# Taint and Data-Flow Tracer Skill

This workflow provides a systematic approach for tracing tainted user/network input through a binary to determine if it reaches a sensitive memory sink without proper sanitization, bounds-checking, or size validation.

---

## 🏛️ Tri-Part Coordination

- **Claude**: Determines source-to-sink reachability, identifies missing validation checks, and performs type/sign extension reasoning.
- **Ghidra MCP**: Inspects parameter passing across calls, variable reassignments in decompiler SSA/AST representations, and xref call trees.
- **re_context MCP**: Maintains the ordered chain of hops, recorded constraints, and rejected sanitization claims.

---

## 📋 Step-by-Step Procedure

### Step 1: Identify Source and Sink
1. Untrusted Source: Network (`recv`, `recvfrom`), file IO (`read`, `fread`), IPC, or CLI/environment.
2. Target Sink: Memory allocation (`malloc`, `alloca`), memory copy (`memcpy`, `memmove`, `strcpy`), indirect call/jump, or filesystem API.

### Step 2: Initialize Taint Session & Trace Call Paths
```python
entity = "taint:network_to_malloc"
record_fact(entity=entity, fact="Source: recv() in handle_client_connection()")
record_fact(entity=entity, fact="Target Sink: malloc() in allocate_message_buffer()")

# Instantly discover all call chains from source to sink across call graph topology
paths = find_call_paths(entity=entity, source_func="handle_client_connection", sink_func="allocate_message_buffer")
```

### Step 3: Backward & Forward Slicing with Ghidra MCP
1. Backward slice from sink:
   - What variable determines the allocation size argument?
   - Trace backwards through arithmetic operations (`*`, `+`, `<<`).
2. Forward slice from source:
   - What buffer holds the read bytes?
   - At what offsets are size/length fields parsed?

### Step 4: Record Intermediate Hops & Branch Constraints
For every function and branch condition on the path:
```python
add_candidate_function(entity=entity, function_name="handle_client_connection()")
add_candidate_function(entity=entity, function_name="deserialize_payload()")
add_candidate_function(entity=entity, function_name="allocate_message_buffer()")

# Record symbolic branch constraints along the trace
record_path_constraint(entity=entity, constraint_expr="count > 0", source_function="deserialize_payload", description="Non-empty check")
record_path_constraint(entity=entity, constraint_expr="alloc_size == (count * 16) & 0xffffffff", source_function="allocate_message_buffer", description="32-bit truncation")
```

### Step 5: SMT Reachability Verification (Z3 Solver)
Instead of guessing whether complex branch constraints allow the sink to be reached, invoke the embedded Z3 solver:
```python
reachability = solve_reachability(
    entity=entity,
    target_condition="alloc_size < count",
    variable_types={"count": "uint32", "alloc_size": "uint32"},
    bit_width=32
)
# If SATISFIABLE, examine concrete inputs in reachability["satisfying_model"]
# If UNSATISFIABLE, the branch constraints mathematically prevent triggering the condition
```

### Step 6: Log Exploit Primitive Ledger & Hypotheses
If reachability proves the condition is satisfiable:
```python
record_exploit_primitive(
    entity=entity,
    primitive_type="HEAP_BUFFER_OVERFLOW",
    target_buffer="heap_chunk_0x40",
    controllable_bytes="count * 16 - alloc_size",
    trigger_status="verified",
    associated_function="allocate_message_buffer",
    applied_constraints=["PC1", "PC2"]
)
```

If a path is guarded by an ironclad check:
```python
reject_hypothesis(
    entity=entity,
    hypothesis_id_or_claim="Attacker can trigger OOB write via large count",
    reason="Checked by if (__builtin_mul_overflow(count, 16, &res)) return -1; at sub_402100:0x18"
)
```

### Step 7: Log Full Taint Chain
```python
add_data_flow_fact(
    entity=entity,
    flow="recv(sock, hdr, 8) → ntohs(hdr.count) → count * sizeof(Item) → malloc(total_size) → memcpy(buf, payload, count * 16)"
)
```

### Step 8: Export Formatted Findings
Render the complete report:
```python
report = render_template(entity=entity, template_type="vulnerabilities")
```
