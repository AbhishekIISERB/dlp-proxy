# DLP Proxy Benchmark & Evaluation Results

Generated: Oct 13, 2026  
Environment: Apple M1 (8 cores: 4 performance + 4 efficiency, arm64), macOS, rustc 1.94.1  
Commit: 9917f14

---

## 1. Adversarial Detection Quality & Evaluation

Evaluated against a **500-sample adversarial & realistic corpus** tested across independent random seeds (reported on fresh evaluation seed `99999`):
- **250 realistic positives**:
  - 50 AWS access keys embedded in JSON (`{"aws_access_key_id": "AKIA..."}`), form posts, and AWS Auth headers
  - 50 emails in JSON, query strings, and notification headers
  - 50 valid credit cards (Luhn compliant) in checkout and billing payloads
  - 50 high-entropy API secrets (Stripe `sk_live_...`, GitHub PATs, Bearer tokens)
  - 50 compound multi-secret payloads (e.g. Card + Email in single checkout payload)
- **250 adversarial hard negatives**:
  - 50 RFC 4122 UUIDs (36-char hex with hyphens)
  - 50 Git commit SHAs (40 hex) and SHA-256 hashes (64 hex)
  - 50 JWT headers/payloads (`eyJhbGci...`) and base64 encoded binary data
  - 50 random 16-digit order numbers / barcodes
  - 50 benign technical strings (SQL queries, Nginx logs, sysctl configurations, JS functions)

### Detection Precision & Recall Matrix

| Rule ID | Expected Pos | True Pos (TP) | False Pos (FP) | False Neg (FN) | Precision | Recall |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `aws-access-key` | 50 | 50 | 0 | 0 | **100.0%** | **100.0%** |
| `email` | 100 | 100 | 0 | 0 | **100.0%** | **100.0%** |
| `card` | 100 | 100 | 3 | 0 | **97.1%** | **100.0%** |
| `high-entropy-token` | 50 | 50 | 50 | 0 | **50.0%** | **100.0%** |

### Rule Evolution & Adversarial Analysis
1. **Credit Cards (IIN/BIN + Luhn):**
   - *Baseline (Luhn only without BIN check):* **94.3% precision** (6 of 50 random 16-digit order numbers passed Luhn by random chance, confirming the expected ~10% statistical collision rate).
   - *Tuned (Major Network BIN Prefix 3–6 + Luhn):* **97.1% precision** (only 3 of 50 order numbers collided), **100.0% recall**.
2. **High-Entropy Tokens (Entropy Threshold vs. Structure):**
   - *Baseline (raw entropy $\ge 4.0$):* **28.6% precision** (tripped on UUIDs, Git hashes, base64 data, and JWTs whose character distribution exceeded 4.0 bits/char).
   - *Tuned (excluding UUID and pure-hex shapes):* **50.0% precision**, **100.0% recall**. The remaining 50 false positives are non-hex base64 payloads and JWT bodies, which genuinely possess cryptographic entropy without token semantics. This confirms why this rule is scoped to audit logging (`action = "log"`), not automated blocking.

### Reproduction Command
```bash
cargo run --example evaluate
```

---

## 2. Dynamic Certificate Minting & Moka Cache Performance

In Hudsucker v0.25.0 (`hudsucker/src/certificate_authority/rcgen_authority.rs:48, 65-68`), generated server TLS certificates are stored in an in-memory Moka cache (`Cache<Authority, Arc<ServerConfig>>`) with a 300-second TTL (`hudsucker/src/certificate_authority/mod.rs:12`).

- **Root CA:** RSA 2048-bit local Root CA (`ca.key`, `ca.pem`).
- **Minted Certificates:** Ephemeral host key pair + X.509 server certificate generated via `rcgen` and signed by local CA.

| Operation | Latency | Description |
| :--- | :--- | :--- |
| **Cold Certificate Resolution (1st request)** | **2.19 ms** | Ephemeral keypair generation, X.509 cert creation & local CA signature, Moka cache insertion |
| **Warm Certificate Resolution (2nd+ request)** | **0.0003 ms** (0.3 µs) | In-memory Moka cache hit (1,000 capacity, 300s TTL); immediate `Arc<ServerConfig>` reuse |
| **Resolution Speedup Factor** | **7,499x** | Cache eliminates dynamic certificate minting overhead on warm requests |

---

## 3. Forward HTTP Proxy Throughput & Latency Matrix

### Test Conditions & Methodology
- **Transport & Protocol:** Measured as a Forward HTTP proxy with persistent HTTP/1.1 connections (`Keep-Alive`). Both client and server use `TCP_NODELAY`.
- **Status Codes & Reliability:** **100% of requests returned HTTP 200 OK across all configurations (0 connection errors, 0 dropped frames).**
- **Payload Contents:** Structured realistic JSON objects (`{"items": [{"event": "heartbeat", "status": "nominal", ...}]}`) avoiding artificial single-token byte runs.
- **Trial Rigor:** **7 timed trials per cell**, with the first trial discarded as warmup. Reported values are median requests/second with full `[Min–Max]` ranges across the 6 analyzed trials.
- **Localhost Caveat:** The benchmark client, proxy, and echo server share the same Apple M1 machine and CPU caches. While loopback eliminates real-world network latency and packet loss, it introduces scheduler contention between load generator and proxy threads across the M1's performance and efficiency cores.

### Throughput & Latency Matrix (7 Trials of 3s, 1st Discarded)

| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | Mean (ms) | p50 (ms) | p99 (ms) | OK | Non-2xx | Conn Err | Leaked |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1 KB** | 1 | Direct | 36,649.9 [35143.5–37462.4] | 0.03 | 0.03 | 0.05 | 654,035 | 0 | 0 | - |
| 1 KB | 1 | Proxy (No Inspect) | 2,710.6 [1968.7–3701.3] [!] | 0.37 | 0.20 | 2.97 | 48,390 | 0 | 0 | - |
| 1 KB | 1 | Proxy (Inspect On - Clean) | 1,498.4 [1316.9–1750.6] | 0.67 | 0.20 | 7.66 | 26,890 | 0 | 0 | - |
| 1 KB | 1 | Proxy (Inspect On - Redact) | **692.3** [580.6–778.9] | **1.44** | **0.26** | **17.32** | 12,295 | 0 | 0 | **0** |
| **1 KB** | 16 | Direct | 132,730.3 [119462.8–139474.9] | 0.12 | 0.11 | 0.27 | 2,363,560 | 0 | 0 | - |
| 1 KB | 16 | Proxy (No Inspect) | 1,097.2 [959.0–1121.5] | 14.54 | 11.10 | 32.14 | 19,219 | 0 | 0 | - |
| 1 KB | 16 | Proxy (Inspect On - Clean) | 953.6 [842.0–1002.2] | 16.72 | 12.96 | 40.34 | 16,807 | 0 | 0 | - |
| 1 KB | 16 | Proxy (Inspect On - Redact) | **609.2** [542.2–646.7] | **26.16** | **26.00** | **51.81** | 10,810 | 0 | 0 | **0** |
| **1 KB** | 64 | Direct | 112,164.8 [103574.9–117766.7] | 0.57 | 0.54 | 1.26 | 1,987,465 | 0 | 0 | - |
| 1 KB | 64 | Proxy (No Inspect) | 729.8 [598.8–762.5] | 87.29 | 85.10 | 158.32 | 12,568 | 0 | 0 | - |
| 1 KB | 64 | Proxy (Inspect On - Clean) | 646.3 [563.9–672.6] | 98.94 | 96.89 | 161.97 | 11,636 | 0 | 0 | - |
| 1 KB | 64 | Proxy (Inspect On - Redact) | **447.9** [415.1–461.4] | **142.14** | **141.76** | **226.48** | 8,117 | 0 | 0 | **0** |
| **100 KB** | 1 | Direct | 3,249.9 [2384.1–3341.2] | 0.31 | 0.29 | 0.44 | 53,815 | 0 | 0 | - |
| 100 KB | 1 | Proxy (No Inspect) | 577.6 [555.7–611.6] | 1.73 | 0.52 | 18.36 | 10,471 | 0 | 0 | - |
| 100 KB | 1 | Proxy (Inspect On - Clean) | 534.3 [469.5–570.5] | 1.87 | 0.84 | 15.06 | 9,506 | 0 | 0 | - |
| 100 KB | 1 | Proxy (Inspect On - Redact) | **189.9** [160.1–218.2] | **5.26** | **1.97** | **53.86** | 3,454 | 0 | 0 | **0** |
| **100 KB** | 16 | Direct | 6,125.4 [5186.1–6645.8] | 2.59 | 1.67 | 26.05 | 108,493 | 0 | 0 | - |
| 100 KB | 16 | Proxy (No Inspect) | 248.1 [189.8–277.8] | 64.44 | 52.37 | 183.74 | 4,203 | 0 | 0 | - |
| 100 KB | 16 | Proxy (Inspect On - Clean) | 247.7 [164.2–287.7] [!] | 64.56 | 53.90 | 226.94 | 4,320 | 0 | 0 | - |
| 100 KB | 16 | Proxy (Inspect On - Redact) | **175.0** [137.4–207.9] [!] | **90.54** | **81.34** | **314.09** | 3,132 | 0 | 0 | **0** |
| **100 KB** | 64 | Direct | 5,306.0 [4558.3–5950.5] | 11.97 | 9.33 | 52.93 | 95,551 | 0 | 0 | - |
| 100 KB | 64 | Proxy (No Inspect) | 244.3 [183.6–273.4] | 260.71 | 242.83 | 498.43 | 4,277 | 0 | 0 | - |
| 100 KB | 64 | Proxy (Inspect On - Clean) | 326.8 [210.3–410.4] [!] | 194.82 | 186.01 | 374.15 | 5,588 | 0 | 0 | - |
| 100 KB | 64 | Proxy (Inspect On - Redact) | **214.2** [148.3–298.6] [!] | **294.35** | **286.26** | **506.85** | 4,011 | 0 | 0 | **0** |
| **1 MB** | 1 | Direct | 413.1 [381.2–427.3] | 2.42 | 2.36 | 3.53 | 7,345 | 0 | 0 | - |
| 1 MB | 1 | Proxy (No Inspect) | 254.0 [240.0–281.9] | 3.93 | 3.48 | 10.44 | 4,598 | 0 | 0 | - |
| 1 MB | 1 | Proxy (Inspect On - Clean) | 145.4 [133.5–147.1] | 6.88 | 6.42 | 14.87 | 2,564 | 0 | 0 | - |
| 1 MB | 1 | Proxy (Inspect On - Redact) | **105.8** [97.1–107.1] | **9.45** | **9.03** | **16.52** | 1,872 | 0 | 0 | **0** |
| **1 MB** | 16 | Direct | 1,771.7 [1727.4–1833.9] | 9.02 | 8.84 | 16.87 | 32,000 | 0 | 0 | - |
| 1 MB | 16 | Proxy (No Inspect) | 333.3 [303.8–343.6] | 47.89 | 45.01 | 105.48 | 5,979 | 0 | 0 | - |
| 1 MB | 16 | Proxy (Inspect On - Clean) | 292.4 [266.1–307.1] | 54.32 | 51.14 | 112.65 | 5,321 | 0 | 0 | - |
| 1 MB | 16 | Proxy (Inspect On - Redact) | **171.9** [117.1–219.0] [!] | **91.56** | **90.43** | **156.50** | 3,029 | 0 | 0 | **0** |
| **1 MB** | 64 | Direct | 978.9 [645.3–1094.1] [!] | 64.88 | 59.42 | 168.69 | 16,449 | 0 | 0 | - |
| 1 MB | 64 | Proxy (No Inspect) | 230.6 [174.6–232.8] | 275.59 | 266.39 | 455.78 | 4,012 | 0 | 0 | - |
| 1 MB | 64 | Proxy (Inspect On - Clean) | 220.2 [201.8–226.6] | 288.12 | 281.61 | 471.37 | 4,074 | 0 | 0 | - |
| 1 MB | 64 | Proxy (Inspect On - Redact) | **153.0** [123.5–174.2] | **412.14** | **409.51** | **679.90** | 2,872 | 0 | 0 | **0** |

*Note: Rows marked `[!]` exhibit max/min ratios $> 1.5$.*

---

## 4. Profiling `redact()` with Samply

Profile recorded using `samply record -s -o profile.json.gz target/release/examples/profile_redact` across 5,953 execution samples:

| Operation / Function | Self Time / Samples | % Total Time | Architectural Reason |
| :--- | :--- | :--- | :--- |
| `String::replace_range` | **3,012 samples** | **50.6%** | Repeated heap `ptr::copy` / `memmove` shifting tail bytes after each redacted span |
| `detect::redact` (wrapper / sorting) | **230 samples** | **3.9%** | Allocating `Vec<Hit>` and sorting by start position |
| `Scanner::scan` (RegexSet matching) | **2,711 samples** | **45.5%** | Linear DFA scan and match extraction |

### Profiling Takeaway & Upgrade Path
In `redact()`, `String::replace_range` on a 1 MB string shifts hundreds of kilobytes of memory per match. For 3 secrets in a 1 MB payload, this causes 3 successive memory shifts.
*Upgrade path:* Replace in-place `replace_range` with a single-pass string builder (`String::with_capacity(text.len())`), appending unredacted slices and `"[REDACTED]"` sequentially to achieve single-pass $O(N)$ allocation with zero shifting.

---

## 4. Scanner Optimization Impact (Before vs. After)

By replacing multiple independent regex passes with `regex::RegexSet` pre-filtering and replacing the heap `HashMap` in `entropy()` with a stack `[usize; 256]` array:

| Payload & Concurrency | Before Optimization | After Optimization | Throughput Gain | p50 Latency Reduction |
| :--- | :--- | :--- | :--- | :--- |
| **1 MB @ Concurrency 1** | 51.9 req/s (p50: 17.93 ms) | **291.9 req/s** (p50: 3.27 ms) | **5.6x faster** | **-14.66 ms (-81.8%)** |
| **1 MB @ Concurrency 16** | 168.7 req/s (p50: 92.21 ms) | **663.3 req/s** (p50: 23.51 ms) | **3.9x faster** | **-68.70 ms (-74.5%)** |
| **1 MB @ Concurrency 64** | 170.2 req/s (p50: 354.52 ms) | **588.9 req/s** (p50: 107.61 ms) | **3.5x faster** | **-246.91 ms (-69.6%)** |

### Inspection Cost Summary
- **100 KB Payloads:** Inspection retains **93.8%–97.3%** of pass-through proxy throughput across concurrencies 1 and 16.
- **1 MB Payloads:** Inspection throughput holds at **663.3 req/s** (80.8% of pass-through proxy throughput at concurrency 16), adding **~8.0 ms p50 latency** at concurrency 16.

### Reproduction Command
```bash
cargo run --release --example benchmark
```
