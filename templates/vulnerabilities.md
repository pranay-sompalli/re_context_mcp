# Vulnerability Validation Template

```text
Entity: vuln:sub_4021a0 | Class: CWE-190 (Integer Overflow) | Sink: malloc()

Confirmed Facts
----------------
process() extracts packet_length from untrusted header
parse() reads length and multiplies by element size
length reaches allocation without upper-bounds check
fixed version adds integer overflow check

Hypotheses
----------------
H1 [0.95]: integer overflow in multiplication causes undersized buffer allocation
H2 [0.85]: attacker controls packet_length to trigger out-of-bounds heap write

Evidence
----------------
E1 [supports H1]: packet_length comes directly from untrusted network header
E2 [supports H1]: multiplication `imul eax, edx` occurs without checking overflow flag (OF/CF)
E3 [supports H1]: patch commit adds explicit `if (len > MAX / sizeof(item))` check

Rejected Hypotheses
----------------
R1: vulnerability is in validate() (reason: validate() executes after allocation)
R2: vulnerability is caused by use-after-free (reason: buffer pointer is never freed prematurely)

Candidate Functions
----------------
parse_header()
allocate_buffer()
process_file()

Data-flow Facts
----------------
input → packet_length → unchecked_imul → malloc(undersized) → memcpy(overflow)

Path Constraints (Symbolic)
----------------
PC1 [parse_header]: packet_length > 0 (header non-empty check)
PC2 [allocate_buffer]: alloc_size == (packet_length * 4) & 0xffffffff (32-bit truncation)
PC3 [allocate_buffer]: alloc_size < packet_length (undersized buffer condition)

Exploit Primitives Ledger
----------------
P1 [HEAP_BUFFER_OVERFLOW] | target=heap_chunk_0x40 | controllable=packet_length - alloc_size | func=allocate_buffer | status=verified
```

## Field Guide
- **Entity Anchor**: Vulnerability target identifier, CWE/bug class, and vulnerable sink.
- **Confirmed Facts**: Ground-truth observations verified in binary decompilation, assembly, or patch diffs.
- **Hypotheses**: Root-cause theories with explicit confidence scores `[0.00 - 1.00]`.
- **Evidence**: Concrete code indicators linked to hypotheses via `[supports Hx]` or `[refutes Hy]`.
- **Rejected Hypotheses**: Ruled-out locations or bug classes with explicit reasons to prevent circular analysis.
- **Candidate Functions**: Functions on the vulnerability or data-flow path.
- **Data-flow Facts**: End-to-end taint traces from untrusted source to vulnerable sink.
- **Path Constraints (Symbolic)**: Branch conditions along execution trace evaluated symbolically with Z3 SMT solver for reachability.
- **Exploit Primitives Ledger**: Target buffers, controllable byte spans, and vulnerability trigger status (`tentative`, `verified`, `unreachable`, `mitigated`).
