# Streaming Inspection: In-Process Scanner Microbenchmark & Hold-Back Constraints

## 1. Overview & Architectural Trade-Offs

When an LLM agent consumes large web responses or long-context documents, full-body buffering in memory introduces processing latency proportional to document size before any data can be inspected or evaluated. `StreamScanner` provides a sliding-window streaming scanner with a `MAX_MATCH_LEN` (256-byte) overlap tail, rolling size cap enforcement, and safe multi-byte UTF-8 boundary management.

### The Streaming Security Invariant & Decision Point
- **Forwarded Chunks Cannot Be Un-Sent:** In an HTTP proxy, once a network chunk is flushed to the downstream client (the LLM agent), it cannot be recalled or redacted.
- **Decision:**
  - **Log-Only Forwarding (`inbound_action = "log"`):** The proxy can stream chunks immediately to the agent as they arrive, scanning them incrementally with minimal initial processing latency (9–36 µs for the first chunk in scanner microbenchmarks). Any detected injection is logged for audit.
  - **Blocking & Sanitizing (`inbound_action = "block"` or `"sanitize"`):** The proxy **must hold back chunks** in an internal buffer until stream completion or size-cap limit, because an injection detected in chunk $K$ cannot recall chunks $1..K-1$ that the agent may have already processed.

---

## 2. In-Process Scanner Microbenchmark (Log-Only Mode)

Measured via `cargo run --release --example stream_bench` comparing the time required to process the first chunk (`StreamScanner::process_chunk`) versus buffering and scanning the entire payload (`inject::scan`) before emitting any output:

| Payload Size | Chunk Size | Chunks | Full-Body Scan Latency | First-Chunk Stream Latency | Initial Latency Ratio | Scanning Throughput |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **16 KB** | 4 KB | 4 | **206.0 µs** | **9.3 µs** | **22.2x lower initial latency** | 404.2 MB/s |
| **100 KB** | 8 KB | 13 | **227.6 µs** | **17.9 µs** | **12.7x lower initial latency** | 432.6 MB/s |
| **1 MB** | 16 KB | 64 | **2,177.0 µs** (2.18 ms) | **36.1 µs** | **60.4x lower initial latency** | 436.7 MB/s |

*Note: This microbenchmark measures in-process scanner execution time in log-only mode, not end-to-end network proxy TTFB. In block/sanitize modes, the proxy must buffer the full body before forwarding.*

---

## 3. Boundary Correctness & Safety Verification

The sliding-window streaming scanner guarantees that no pattern is missed when split across network chunk boundaries:
- **`MAX_MATCH_LEN = 256`:** All 13 detection rules (4 DLP rules + 9 injection rules) have regex patterns whose match spans are bounded within 256 bytes.
- **Exhaustive Byte-by-Byte Boundary Test (`tests/stream.rs`):** Property test splits every rule fixture across every byte boundary `1..len` across two consecutive chunks; verifies 100% detection rate regardless of split offset.
- **Multi-Byte UTF-8 Boundary Safety:** Incomplete UTF-8 code points at chunk boundaries (e.g., 4-byte emoji `🚨` split across 3 chunks) are preserved in the tail buffer and decoded only when the trailing bytes arrive. Invalid UTF-8 immediately fails closed (`StreamError::InvalidUtf8`).
- **Rolling Size Cap:** Streams exceeding configured `max_bytes` immediately abort with `StreamError::SizeCapExceeded`.

---

## 4. Reproduction
```bash
cargo run --release --example stream_bench
cargo test --test stream
```
