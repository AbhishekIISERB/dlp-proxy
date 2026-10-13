# DLP Proxy Benchmark & Evaluation Results

Generated: Oct 13, 2026  
Environment: Apple M1 (8-core arm64), macOS, rustc 1.94.1  
Commit: 48aa014

---

## 1. Detection Quality & Evaluation

Evaluation on a **400-sample labelled dataset** consisting of:
- **200 synthetic positives**:
  - 50 AWS access keys (`AKIA[0-9A-Z]{16}`)
  - 50 email addresses
  - 50 valid credit cards (Luhn checksum algorithm compliant)
  - 50 high-entropy tokens (Shannon entropy $\ge 4.0$ bits/char)
- **200 synthetic negatives**:
  - 50 lookalike identifiers / short keys (`ORDER-ID-...`, short `AKIA...`)
  - 50 natural language sentences
  - 50 invalid credit cards (Luhn checksum failures)
  - 50 low-entropy repeated/patterned strings

### Detection Precision & Recall

| Rule ID | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `aws-access-key` | 50 | 0 | 0 | **100.0%** | **100.0%** |
| `email` | 50 | 0 | 0 | **100.0%** | **100.0%** |
| `card` | 50 | 0 | 0 | **100.0%** | **100.0%** |
| `high-entropy-token` | 50 | 0 | 0 | **100.0%** | **100.0%** |

### Reproduction Command
```bash
cargo run --example evaluate
```

---

## 2. Throughput & Latency Benchmarks

Comparison between three configurations across 3 trials each (reporting the median):
1. **Direct**: Direct HTTP connection to local echo server
2. **Proxy (No Inspect)**: Hudsucker proxy with inspection bypassed (`policy.default = "allow"`)
3. **Proxy (Inspect On)**: Hudsucker proxy with full inspection active (regex scanning, Luhn checksums, Shannon entropy calculation, redaction pipeline)

### Benchmark Matrix

| Payload | Concurrency | Setup | Requests/sec | p50 Latency (ms) | p99 Latency (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1 KB** | 1 | Direct | 3932.8 | 0.25 | 0.30 |
| 1 KB | 1 | Proxy (No Inspect) | 3169.5 | 0.29 | 0.86 |
| 1 KB | 1 | Proxy (Inspect On) | 4040.7 | 0.22 | 0.50 |
| **1 KB** | 16 | Direct | 32599.1 | 0.43 | 1.50 |
| 1 KB | 16 | Proxy (No Inspect) | 9075.4 | 1.52 | 3.82 |
| 1 KB | 16 | Proxy (Inspect On) | 7951.5 | 1.70 | 4.32 |
| **1 KB** | 64 | Direct | 36719.4 | 1.71 | 2.47 |
| 1 KB | 64 | Proxy (No Inspect) | 7747.9 | 7.51 | 15.34 |
| 1 KB | 64 | Proxy (Inspect On) | 6658.3 | 9.05 | 17.52 |
| **100 KB** | 1 | Direct | 5644.3 | 0.16 | 0.28 |
| 100 KB | 1 | Proxy (No Inspect) | 3413.6 | 0.25 | 0.48 |
| 100 KB | 1 | Proxy (Inspect On) | 443.9 | 2.14 | 3.35 |
| **100 KB** | 16 | Direct | 27566.6 | 0.53 | 0.86 |
| 100 KB | 16 | Proxy (No Inspect) | 5995.5 | 2.27 | 5.99 |
| 100 KB | 16 | Proxy (Inspect On) | 1405.4 | 9.33 | 32.55 |
| **100 KB** | 64 | Direct | 24427.1 | 2.54 | 3.38 |
| 100 KB | 64 | Proxy (No Inspect) | 3996.3 | 12.43 | 44.84 |
| 100 KB | 64 | Proxy (Inspect On) | 1468.0 | 40.02 | 88.99 |
| **1 MB** | 1 | Direct | 1672.9 | 0.61 | 0.64 |
| 1 MB | 1 | Proxy (No Inspect) | 760.9 | 1.26 | 1.74 |
| 1 MB | 1 | Proxy (Inspect On) | 55.1 | 17.99 | 21.20 |
| **1 MB** | 16 | Direct | 4399.8 | 3.12 | 6.26 |
| 1 MB | 16 | Proxy (No Inspect) | 2057.2 | 7.22 | 10.57 |
| 1 MB | 16 | Proxy (Inspect On) | 198.4 | 66.31 | 123.51 |
| **1 MB** | 64 | Direct | 4967.2 | 11.82 | 18.77 |
| 1 MB | 64 | Proxy (No Inspect) | 1416.6 | 40.27 | 82.56 |
| 1 MB | 64 | Proxy (Inspect On) | 199.9 | 299.23 | 556.66 |

### Inspection Overhead Highlights
- **1 KB @ Concurrency 16**: Overhead of inspection vs proxy no-inspection is **+0.18 ms** p50 latency and **+0.50 ms** p99 latency.
- **1 KB @ Concurrency 64**: Overhead of inspection vs proxy no-inspection is **+1.54 ms** p50 latency and **+2.18 ms** p99 latency while sustaining **6,658 requests/sec**.

### Reproduction Command
```bash
cargo run --release --example benchmark
```

---

## 3. Benchmark Methodology & Caveats
- **Localhost Testing**: Localhost benchmarks flatter raw proxy throughput because there is no external network transit latency or packet loss.
- **Certificate Caching**: Hudsucker's `RcgenAuthority` caches TLS server configurations per authority in an in-memory Moka cache (configured to 1,000 entries with TTL). Warm requests avoid certificate generation overhead.
- **Fail Closed & Size Cap**: Requests exceeding `max_body_bytes` (1 MB default) are rejected with a 403 response before full in-memory buffer allocation.
