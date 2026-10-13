---
name: reverse-engineering-semantic-recovery
description: >-
  Use this skill when analyzing stripped or unknown functions in Ghidra to recover
  their algorithmic purpose, reconstruct C structs/types, and document validated signatures
  using Claude and re_context MCP.
---

# Reverse Engineering Semantic Recovery Skill

This workflow guides the agent through recovering the high-level semantics, architecture, signatures, and struct definitions of stripped binary code using **Claude (Reasoning)**, **Ghidra MCP (Binary Queries & Annotation)**, and **re_context MCP (Context Memory)**.

---

## 🏛️ Tri-Part Architecture & Division of Responsibility

1. **Claude**: Analyzes decompilation, infers types and algorithmic roles, generates clean C representations, and drives iterative analysis.
2. **Ghidra MCP**: Provides raw decompilation, xrefs, string tables, call hierarchy, and receives updated symbol names/types once validated.
3. **re_context MCP**: Keeps epistemic memory of hypotheses, disproven dead ends, recovered candidate signatures, and struct definitions across tool calls.

---

## 📋 Step-by-Step Procedure

### Step 1: Initialize Entity in `re_context`
Use an entity identifier matching the target function or subsystem (e.g., `func:sub_4010a0` or `module:crypto_engine`).
Fetch the template guide:
```python
get_validation_template(template_type="semantic_recovery")
```

### Step 2: Establish Confirmed Facts from Ghidra
Query Ghidra MCP for:
- Function entry point and signature decompilation.
- Caller / Callee cross-references.
- String literals and immediate constants.

Record confirmed ground truths in `re_context`:
```python
record_fact(entity="func:sub_4010a0", fact="Accepts 3 arguments: (rdi=context_ptr, rsi=buffer, rdx=length)")
record_fact(entity="func:sub_4010a0", fact="Calls openssl EVP_CipherUpdate and returns status int (0=failure, 1=success)")
```

### Step 3: Formulate Semantic Hypotheses
Infer high-level purpose and cryptographic or protocol semantics, linking dependent deductions:
```python
# Root hypothesis H1
add_hypothesis(
    entity="func:sub_4010a0",
    claim="Function performs custom XTEA payload decryption",
    confidence=0.85
)
# Dependent hypothesis H2 (depends on H1)
add_hypothesis(
    entity="func:sub_4010a0",
    claim="Context pointer rdi points to a custom SessionContext struct with IV at offset 0x28",
    confidence=0.90,
    depends_on=["H1"]
)
```

### Step 4: Gather Structural Evidence
Correlate constants, loop structures, and API sequences:
```python
record_evidence(entity="func:sub_4010a0", evidence="Magic constant 0x9e3779b9 (Golden Ratio) [supports H1]")
record_evidence(entity="func:sub_4010a0", evidence="Offset *(arg1 + 0x28) is passed as IV/nonce buffer [supports H2]")
```

### Step 5: Document Rejected Hypotheses & Invalidation Cascades
When initial assumptions are invalidated by further decompilation, rule them out immediately.
`reject_hypothesis` automatically cascades invalidation to all dependent hypotheses and updates affected call graph node rationales:
```python
reject_hypothesis(
    entity="func:sub_4010a0",
    hypothesis_id_or_claim="TEA/Golden Ratio loop is ChaCha20 round function",
    reason="Inspection of bitwise rotation shows standard XTEA delta addition, not ChaCha quarter-round"
)
```

### Step 5b: Audit for Epistemic Conflicts
Before locking in signatures, audit state for contradictions between refuting evidence and active hypotheses:
```python
detect_epistemic_conflicts(entity="func:sub_4010a0")
```

### Step 6: Map Data & Control Flow
Record key transformations and state transitions:
```python
add_data_flow_fact(
    entity="func:sub_4010a0",
    flow="network_packet → header_validation → extract_tag → xtea_decrypt → verify_checksum"
)
```

### Step 7: Reconstruct Types & C Structs
Synthesize member offsets, types, and padding into clean C definitions:
```python
add_type_definition(
    entity="func:sub_4010a0",
    type_definition="""struct SessionContext {
    int socket_fd;          /* +0x00 */
    uint32_t flags;         /* +0x04 */
    uint8_t iv[16];         /* +0x08 */
    void *cipher_ctx;       /* +0x18 */
    size_t rx_remaining;    /* +0x20 */
};"""
)
```

### Step 8: Propose Clean Signatures & Push Back to Ghidra
1. Propose candidate descriptive signature:
   ```python
   add_candidate_function(
       entity="func:sub_4010a0",
       function_name="session_decrypt_packet(SessionContext *ctx, const uint8_t *in, size_t len) -> int"
   )
   ```
2. Call Ghidra MCP to rename `sub_4010a0` to `session_decrypt_packet` and apply the new parameter types.
3. Render the full semantic recovery report:
   ```python
   report = render_template(entity="func:sub_4010a0", template_type="semantic_recovery")
   ```
