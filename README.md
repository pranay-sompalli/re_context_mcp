# Universal Context Manager MCP Server

A deterministic, lightweight **Semantic and Epistemic Context Manager** MCP server designed for agentic reverse-engineering and complex analysis workflows.

Based on the [Minimal Desktop Codex Reverse-Engineering Plugin specification](#), this server manages hypotheses, observations, and confidence scores across entities (e.g., functions, structs, addresses) while keeping **all reasoning exclusively inside the AI agent**.

---

## 🏛️ Architecture & Design Boundaries

```text
                     AI Agent (Codex / Antigravity / Claude)
                             reasoning / orchestration
                                     |
                                     v
                           RE Skill / Workflow
                              /           \
                             /             \
                            v               v
                  Semantic Context       Ghidra MCP / Tools
                    Manager MCP                  |
                        |                        v
                        v                   Target System
                    state.json
```

### Core Design Rules
1. **The AI Agent is the sole reasoning component.**
2. **The Context Manager is intentionally dumb and deterministic.**
   - Does **not** call an LLM.
   - Does **not** call Ghidra or external analysis tools.
   - Does **not** perform reasoning or adjust confidence values automatically.
   - Only stores, retrieves, and clears state.

---

## 🛠️ Available MCP Tools

| Tool | Parameters | Description |
| :--- | :--- | :--- |
| `get_state` | `entity: str` | Retrieve all notes, facts, hypotheses, and evidence for an entity. |
| `set_note` | `entity: str`, `note: str` | Store a factual observation or semantic note. |
| `record_fact` | `entity: str`, `fact: str` | Store a verified, ground-truth fact. |
| `record_evidence` | `entity: str`, `evidence: str`, `evidence_id: str = ""` | Store concrete evidence (auto-indexes `E1`, `E2`, ...). |
| `add_hypothesis` | `entity: str`, `claim: str`, `confidence: float`, `depends_on: list = []`, `associated_function: str = ""`, `hypothesis_id: str = ""` | Store a tentative hypothesis (`H1`, `H2`, ...) with confidence (`0.0` - `1.0`), optional upstream dependencies, and associated function. |
| `reject_hypothesis` | `entity: str`, `hypothesis_id_or_claim: str`, `reason: str = ""` | Rule out a hypothesis, marking it rejected (`R1`, `R2`, ...) and automatically cascade-invalidating all dependent hypotheses. |
| `detect_epistemic_conflicts` | `entity: str` | Scan entity state for contradictions between refuting evidence and active hypotheses, broken dependencies, or stale attention priorities. |
| `add_candidate_function` | `entity: str`, `function_name: str` | Record candidate function or signature of interest. |
| `add_data_flow_fact` | `entity: str`, `flow: str` | Record data-flow or control-flow progression (e.g. `src → step → sink`). |
| `add_type_definition` | `entity: str`, `type_definition: str` | Record reconstructed struct or type definition (for semantic recovery). |
| `add_call_graph_node` | `entity: str`, `function_name: str`, `attention_score: float`, `role: str = "unknown"`, `reason: str = ""`, `in_degree: int = 0`, `out_degree: int = 0`, `status: str = "uninspected"` | Record or update a function node with an attention score (`0.0` - `1.0`), architectural role, status, and rationale. Auto-sorted descending by attention. |
| `get_attention_queue` | `entity: str`, `min_score: float = 0.0`, `status_filter: str = ""` | Retrieve functions ordered by attention score descending, prioritizing the next high-yield functions for the LLM to inspect. |
| `update_call_graph_node_status` | `entity: str`, `function_name: str`, `status: str`, `updated_role: str = ""` | Update inspection status (`uninspected`, `in_progress`, `analyzed`) or role of a function node. |
| `add_call_edge` | `entity: str`, `caller: str`, `callee: str`, `callsite: str = ""` | Record a directional call graph edge (`caller -> callee`) and update node degrees. |
| `record_callee_caller_flow` | `entity: str`, `flow_name: str`, `chain: list`, `description: str = ""` | Record a bottom-up callee-to-caller semantic flow showing how leaf primitives bubble up to parents. |
| `find_call_paths` | `entity: str`, `source_func: str`, `sink_func: str`, `max_depth: int = 6`, `max_paths: int = 5` | Find all directional call paths from source to sink in the call graph for taint and reachability validation. |
| `render_mermaid_graph` | `entity: str`, `include_attention_colors: bool = True`, `orientation: str = "TD"` | Render an interactive Mermaid diagram of the call graph with attention heatmaps and progress colors. |
| `get_validation_template` | `template_type: str = "vulnerabilities"` | Retrieve the blank/example template for `vulnerabilities`, `semantic_recovery`, or `call_graph`. |
| `render_template` | `entity: str`, `template_type: str = "vulnerabilities"`, `omit_empty: bool = False`, `include_confidence: bool = True` | Deterministically format entity state into the sectioned validation template (`vulnerabilities`, `semantic_recovery`, `call_graph`). Use `omit_empty=True` to save tokens. |
| `populate_from_template` | `entity: str`, `template_type: str`, `content: str`, `merge: bool = True` | Ingest and parse a filled text template directly into entity state (supports confidence `[0.90]` and non-destructive merge). |
| `clear_state` | `entity: str` | Delete semantic/epistemic state for an entity. |
| `list_entities` | _none_ | List all entity identifiers currently tracked in state. |
| `get_all_state` | _none_ | Return the full dictionary of all tracked entities. |
| `record_path_constraint` | `entity: str`, `constraint_expr: str`, `source_function: str = ""`, `is_negated: bool = False`, `description: str = ""` | Record a symbolic branch constraint (`PC1`, `PC2`, ...) along the execution trace for SMT reachability. |
| `list_path_constraints` | `entity: str`, `source_function: str = ""` | List recorded symbolic path constraints for an entity. |
| `record_exploit_primitive` | `entity: str`, `primitive_type: str`, `target_buffer: str = ""`, `controllable_bytes: str = ""`, `trigger_status: str = "tentative"`, `associated_function: str = ""`, `details: str = ""`, `applied_constraints: list = []` | Record an exploit primitive (`P1`, `P2`, ...) in the vulnerability ledger (`tentative`, `verified`, `unreachable`, `mitigated`). |
| `list_exploit_primitives` | `entity: str`, `status_filter: str = ""` | List exploit primitives filtered by trigger status. |
| `update_exploit_primitive_status` | `entity: str`, `primitive_id: str`, `status: str`, `verification_notes: str = ""` | Update the trigger status of an exploit primitive with analytical verification notes. |
| `solve_reachability` | `entity: str`, `target_condition: str`, `variable_types: dict = {}`, `active_constraint_ids: list = None`, `additional_constraints: list = None`, `bit_width: int = 32` | Run embedded Z3 SMT solver check to mathematically prove condition reachability and return satisfying models or prove `UNSAT`. |
| `explain_unreachability` | `entity: str`, `target_condition: str`, `variable_types: dict = {}`, `active_constraint_ids: list = None`, `additional_constraints: list = None`, `bit_width: int = 32` | Diagnose why a condition is mathematically unreachable using Z3 Unsat Core, pinpointing the exact minimal contradictory checks. |
| `solve_variable_bounds` | `entity: str`, `variable_name: str`, `variable_types: dict = {}`, `active_constraint_ids: list = None`, `additional_constraints: list = None`, `bit_width: int = 32` | Calculate the mathematical min/max allowable bounds for a variable (e.g. `alloc_size`, `length`) using Z3 optimization. |
| `delete_path_constraint` | `entity: str`, `constraint_id: str` | Remove a specific symbolic path constraint by ID (`PC2`) for backtracking or exploring alternative branches. |
| `clear_path_constraints` | `entity: str` | Clear all recorded symbolic path constraints for an entity without deleting other state. |

---

## 📋 Validation Templates

The server supports domain-specific validation templates:

### 1. Vulnerability Validation (`vulnerabilities`)
Specialized for vulnerability research, exploitability assessments, and patch validation:
- **Confirmed Facts**: Verified source/binary properties and patch additions.
- **Hypotheses** (`H1`, `H2`...): Exploit mechanisms, root causes, attacker controls.
- **Evidence** (`E1`, `E2`...): File headers, arithmetic operations, allocator constraints.
- **Rejected Hypotheses** (`R1`, `R2`...): Ruled-out locations or bug classes.
- **Candidate Functions**: Functions on the vulnerability path.
- **Data-flow Facts**: End-to-end taint traces from untrusted source to vulnerable sink.

Reference file: [templates/vulnerabilities.md](file://~/context-manager-mcp/templates/vulnerabilities.md)

### 2. Semantic Recovery (`semantic_recovery`)
Specialized for decompilation, binary analysis, and reverse engineering:
- **Confirmed Facts**: Decompiled arguments, buffer sizes, return conventions.
- **Hypotheses** (`H1`, `H2`...): Algorithmic purpose, protocol framing, module identity.
- **Evidence** (`E1`, `E2`...): Magic bytes, constant strings, syscall/API sequences.
- **Rejected Hypotheses** (`R1`, `R2`...): Invalidated format assumptions or dead ends.
- **Candidate Functions / Signatures**: Recovered names and typed signatures.
- **Data-flow & Control-flow Facts**: Sequential processing and state-machine transitions.
- **Struct / Type Definitions**: Reconstructed C structs, offsets, and typedefs.

Reference file: [templates/semantic_recovery.md](file://~/context-manager-mcp/templates/semantic_recovery.md)

### 3. Call Graph & Attention Topology (`call_graph`)
Specialized for subsystem mapping, priority triaging, and bottom-up semantic propagation:
- **Function Priority Queue & Attention Scores**: Prioritized list of functions with attention scores (`0.00` - `1.00`), roles, statuses, and rationale.
- **Bottom-Up Callee-to-Caller Semantic Flows**: Reconstructed control and data paths starting at ground-truth leaves (APIs, syscalls, crypto routines) and bubbling up to parent callers.
- **Call Graph Edges**: Directional caller-to-callee dependencies (`caller -> callee`).

Reference file: [templates/call_graph.md](file://~/context-manager-mcp/templates/call_graph.md)

---

## 💡 FastMCP Prompts & Resources
- **Prompts**:
  - `vulnerability_validation(target_entity)`
  - `semantic_recovery(target_entity)`
  - `call_graph_triage(target_entity)`
- **Resources**:
  - `template://vulnerabilities`
  - `template://semantic_recovery`
  - `template://call_graph`


## 🚀 Quick Start

### 1. Setup Environment
Make scripts executable and run `./setup.sh`:
```bash
chmod +x setup.sh run.sh
./setup.sh
```
This automatically initializes a Python virtual environment in `.venv` and installs `fastmcp` and `pytest`.

### 2. Run Tests
Verify everything is working:
```bash
.venv/bin/pytest tests/ -v
```

### 3. Launching
The launcher `./run.sh` starts the server over stdio:
```bash
./run.sh
```

---

## 🔌 Client Configurations

Configuration files are pre-generated in the `configs/` folder.

### Antigravity IDE
Add to your project's `.agents/mcp_config.json` or global `~/.gemini/config/mcp_config.json`:
```json
{
  "mcpServers": {
    "re_context": {
      "command": "~/Documents/context-manager-mcp/run.sh",
      "args": []
    }
  }
}
```

### Claude Desktop
Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "re_context": {
      "command": "~/context-manager-mcp/run.sh",
      "args": []
    }
  }
}
```

### Codex CLI
In your plugin's `.mcp.json`:
```json
{
  "mcpServers": {
    "re_context": {
      "command": "~/context-manager-mcp/run.sh",
      "args": []
    }
  }
}
```

### Cursor
In Cursor Settings > Features > MCP, add a new server with:
- **Name**: `re_context`
- **Type**: `command`
- **Command**: `~/context-manager-mcp/run.sh`

---

## 📂 Storage & Customization

- **Default State File**: `~/.local/share/re-agent/state.json`
- **Custom State Location**: Set the `RE_STATE_FILE` environment variable in your client configuration:
  ```json
  "env": {
    "RE_STATE_FILE": "/path/to/custom_state.json"
  }
  ```
