# Call Graph & Attention Topology Template

```text
Entity: module:network_ingress | Subsystem: packet_dispatch | Functions: 12

Function Priority Queue & Attention Scores
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
sub_402100 -> malloc
```

## Field Guide
- **Entity Anchor**: Target subsystem, module, or binary component representing the call graph boundary.
- **Function Priority Queue & Attention Scores**: Prioritized list of functions with attention scores (`0.00 - 1.00`), roles (e.g., `Crypto/Sink`, `Parser`, `Dispatcher`, `Utility/Leaf`), inspection status (`uninspected`, `in_progress`, `analyzed`), and architectural reasons. The agent uses this queue to focus token and reasoning budget greedily on high-yield targets.
- **Bottom-Up Callee-to-Caller Semantic Flows**: Reconstructed control and data paths starting at ground-truth leaf nodes (known APIs, syscalls, crypto functions) and bubbling semantics upward into parent callers and dispatchers.
- **Call Graph Edges**: Directional caller-to-callee dependencies (`caller -> callee`).
