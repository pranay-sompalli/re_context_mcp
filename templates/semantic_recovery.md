# Semantic Recovery Template

```text
Entity: func:sub_401000 | Addr: 0x00401000 | Arch: x86_64 | CC: __fastcall

Confirmed Facts
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
E2 [supports H1]: loop calls recv() until 5-byte record header is complete
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
socket → recv(hdr, 5) → parse_record_header() → decrypt_payload()

Struct / Type Definitions
----------------
struct session_t {
    int socket_fd;          /* +0x00 */
    uint32_t state;         /* +0x04 */
    uint8_t rx_buffer[1024];/* +0x08 */
};
```

## Field Guide
- **Entity Anchor**: Target entity, memory address, architecture, and calling convention. Prevents repeating architecture/address in every line.
- **Confirmed Facts**: Ground-truth behaviors verified from decompilation, exports, or symbols.
- **Hypotheses**: High-level interpretations with confidence scores `[0.00 - 1.00]`.
- **Evidence**: Specific code indicators linked to hypotheses via `[supports Hx]` or `[refutes Hy]`.
- **Rejected Hypotheses**: Disproven architectural or algorithmic assumptions to avoid circular dead ends.
- **Candidate Functions / Signatures**: Recovered function prototypes with calling conventions and typed arguments.
- **Data-flow & Control-flow Facts**: Sequential transformations from input to destination.
- **Struct / Type Definitions**: Reconstructed C structs with explicit byte offsets (`/* +0x08 */`).
