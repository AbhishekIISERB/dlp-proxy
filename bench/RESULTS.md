# DLP Proxy Benchmark & Evaluation Results

Generated: Oct 13, 2026  
Environment: Apple M1 (8-core arm64), macOS, rustc 1.94.1  
Commit: Updated with adversarial corpus, Moka cache measurements, and scanner optimizations  

---

## 1. Adversarial Detection Quality & Evaluation

Evaluation on a **500-sample adversarial & realistic corpus** consisting of:
- **250 realistic positives**:
  - 50 AWS access keys in JSON (`{"aws_access_key_id": "AKIA..."}`), forms, and AWS Auth headers
  - 50 emails in JSON, query strings, and notification headers
  - 50 valid credit cards (Luhn compliant) in checkout and billing payloads
  - 50 high-entropy API secrets (Stripe `sk_live_...`, GitHub PATs, Bearer tokens)
  - 50 compound multi-secret payloads (e.g. Card + Email in single checkout payload)
- **250 adversarial hard negatives**:
  - 50 RFC 4122 UUIDs (36 chars, hex + hyphens — look-alikes for token entropy)
  - 50 Git commit SHAs (40 hex) and SHA-256 hashes (64 hex)
  - 50 JWT headers/payloads (`eyJhbGci...`) and base64 encoded data blocks
  - 50 random 16-digit order IDs / serial numbers
  - 50 benign technical strings (SQL queries, Nginx logs, sysctl commands, JavaScript code)

### Detection Results (Precision & Recall)

| Rule ID | Expected Pos | True Pos (TP) | False Pos (FP) | False Neg (FN) | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `aws-access-key` | 50 | 50 | 0 | 0 | **100.0%** | **100.0%** |
| `email` | 100 | 100 | 0 | 0 | **100.0%** | **100.0%** |
| `card` | 100 | 100 | 6 | 0 | **94.3%** | **100.0%** |
| `high-entropy-token` | 50 | 50 | 125 | 0 | **28.6%** | **100.0%** |

### Key Adversarial Findings
1. **16-Digit Order Number Collisions (`card`):**
   - Out of 50 arbitrary 16-digit numeric IDs, **6 (12%) passed the Luhn checksum purely by random chance**.
   - This empirically confirms the statistical mathematical property of Luhn modulo 10 (1 in 10 uniform digit strings pass by chance), resulting in **94.3% precision** and **100.0% recall**.
2. **Structural Look-Alikes (`high-entropy-token`):**
   - High-entropy tokens matched 125 adversarial negatives (UUIDs, Git hashes, base64 strings, and JWT segments), yielding **28.6% precision** and **100.0% recall**.
   - This validates the design decision in `rules.toml` to assign entropy detection `action = "log"` (audit trail) rather than automated blocking, as raw Shannon entropy on token strings cannot distinguish a cryptographic secret from a UUID or Git commit hash without semantic context.

### Reproduction Command
```bash
cargo run --example evaluate
```

---

## 2. Dynamic Certificate Minting & Moka Cache Performance

In Hudsucker v0.25.0 (`hudsucker/src/certificate_authority/rcgen_authority.rs:48, 65-68`), generated server TLS certificates are stored in an in-memory Moka cache (`Cache<Authority, Arc<ServerConfig>>`) with a 300-second TTL (`certificate_authority/mod.rs:12`).

| Measurement Type | Latency | Description |
| :--- | :--- | :--- |
| **Cold Handshake (1st request)** | **3.03 ms** | Generates RSA/ECDSA key pair, mints X.509 cert from local CA, inserts into Moka cache |
| **Warm Handshake (2nd+ request)** | **0.0003 ms** (0.3 µs) | In-memory Moka cache hit; immediate `Arc<ServerConfig>` reuse |
| **Cache Speedup Factor** | **12,110x** | Cache eliminates dynamic certificate generation overhead on subsequent requests |

---

## 3. Forwarding & Scanning Throughput Matrix

Evaluated across 3 trials with connection warmup and M1 efficiency core stabilization (median reported alongside min–max ranges):

| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | p50 Latency (ms) | p99 Latency (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1 KB** | 1 | Direct | 7,194.2 [2523.6–13440.1] | 0.07 | 4.65 |
| 1 KB | 1 | Proxy (No Inspect) | 3,025.2 [2641.2–3412.1] | 0.29 | 0.82 |
| 1 KB | 1 | Proxy (Inspect On) | 4,091.1 [2879.4–4259.4] | 0.22 | 0.62 |
| **1 KB** | 16 | Direct | 32,833.3 [31556.6–38324.5] | 0.41 | 1.25 |
| 1 KB | 16 | Proxy (No Inspect) | 10,462.4 [9684.4–11487.3] | 1.30 | 4.24 |
| 1 KB | 16 | Proxy (Inspect On) | **8,069.8** [2947.1–8088.4] | **1.53** | **5.93** |
| **1 KB** | 64 | Direct | 27,252.6 [95.1–36032.8] | 2.01 | 5.27 |
| 1 KB | 64 | Proxy (No Inspect) | 5,045.1 [101.6–5481.4] | 8.35 | 175.28 |
| 1 KB | 64 | Proxy (Inspect On) | 228.7 [176.0–3357.8] | 12.83 | 238.08 |
| **100 KB** | 1 | Direct | 6,339.5 [4740.1–8559.7] | 0.15 | 0.21 |
| 100 KB | 1 | Proxy (No Inspect) | 3,177.6 [2606.8–3395.6] | 0.27 | 0.73 |
| 100 KB | 1 | Proxy (Inspect On) | 370.0 [369.3–375.9] | 2.36 | 6.21 |
| **100 KB** | 16 | Direct | 19,308.5 [9507.1–27795.4] | 0.61 | 1.74 |
| 100 KB | 16 | Proxy (No Inspect) | 1,737.6 [24.2–3522.9] | 3.61 | 97.98 |
| 100 KB | 16 | Proxy (Inspect On) | 105.1 [23.6–1495.6] | 7.74 | 2856.41 |
| **100 KB** | 64 | Direct | 21,991.2 [21552.7–24188.8] | 2.57 | 7.30 |
| 100 KB | 64 | Proxy (No Inspect) | 2,784.7 [1371.8–3066.9] | 19.17 | 55.62 |
| 100 KB | 64 | Proxy (Inspect On) | 1,157.9 [42.7–1210.1] | 41.82 | 268.04 |
| **1 MB** | 1 | Direct | 1,753.1 [1437.0–2243.7] | 0.56 | 0.83 |
| 1 MB | 1 | Proxy (No Inspect) | 691.6 [375.9–961.7] | 1.39 | 2.44 |
| 1 MB | 1 | Proxy (Inspect On) | **51.9** [51.8–52.3] | **17.93** | **44.14** |
| **1 MB** | 16 | Direct | 5,056.2 [3384.9–5231.1] | 2.88 | 5.51 |
| 1 MB | 16 | Proxy (No Inspect) | 1,731.5 [1718.6–1807.3] | 7.52 | 21.02 |
| 1 MB | 16 | Proxy (Inspect On) | 168.7 [165.3–175.9] | 92.21 | 152.01 |
| **1 MB** | 64 | Direct | 4,928.6 [4325.3–5000.5] | 12.44 | 20.19 |
| 1 MB | 64 | Proxy (No Inspect) | 1,420.4 [1409.5–1423.4] | 39.40 | 107.45 |
| 1 MB | 64 | Proxy (Inspect On) | 170.2 [38.0–170.3] | 354.52 | 654.72 |

### Inspection Overhead Analysis
- **1 KB @ Concurrency 16:** Inspection adds **+0.23 ms p50** latency (1.53 ms vs. 1.30 ms) while retaining **77.1%** of pass-through proxy throughput (8,069.8 vs. 10,462.4 req/s).
- **Body Size Scaling:** Inspection cost scales linearly with body size. At concurrency 1, p50 latency increases by **~17.4 ms per MB scanned** (0.22 ms @ 1 KB vs. 2.36 ms @ 100 KB vs. 17.93 ms @ 1 MB), reflecting the throughput ceiling of linear DFA scanning and string allocations on large buffers.

### Reproduction Command
```bash
cargo run --release --example benchmark
```
