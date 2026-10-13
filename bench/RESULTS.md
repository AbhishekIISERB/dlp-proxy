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

### Throughput & Latency Matrix (7 Trials, 1st Discarded)

| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | p50 Latency (ms) | p99 Latency (ms) | OK | Non-2xx | Conn Err |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1 KB** | 1 | Direct | 14,806.1 [6832.7–38810.5] [!] | 0.07 | 0.13 | 600 | 0 | 0 |
| 1 KB | 1 | Proxy (No Inspect) | 11,429.4 [9910.9–14807.2] | 0.06 | 0.27 | 600 | 0 | 0 |
| 1 KB | 1 | Proxy (Inspect On - Clean) | 8,450.0 [4596.9–12513.9] [!] | 0.10 | 0.33 | 600 | 0 | 0 |
| 1 KB | 1 | Proxy (Inspect On - Redact) | 9,245.2 [4249.9–10550.6] [!] | 0.08 | 0.34 | 600 | 0 | 0 |
| **1 KB** | 16 | Direct | 161,861.4 [111745.5–169612.8] [!] | 0.09 | 0.21 | 4,800 | 0 | 0 |
| 1 KB | 16 | Proxy (No Inspect) | 11,706.3 [9614.6–13005.4] | 1.11 | 4.09 | 4,800 | 0 | 0 |
| 1 KB | 16 | Proxy (Inspect On - Clean) | **8,059.2** [7605.6–8971.3] | **1.45** | **10.64** | 4,800 | 0 | 0 |
| 1 KB | 16 | Proxy (Inspect On - Redact) | **4,430.2** [3558.5–5069.2] | **3.31** | **8.68** | 4,800 | 0 | 0 |
| **1 KB** | 64 | Direct | 146,988.5 [118067.7–171539.2] | 0.42 | 0.75 | 19,200 | 0 | 0 |
| 1 KB | 64 | Proxy (No Inspect) | 3,579.0 [2890.1–4218.3] | 16.99 | 42.30 | 19,200 | 0 | 0 |
| 1 KB | 64 | Proxy (Inspect On - Clean) | 2,304.5 [2031.5–2539.3] | 26.52 | 49.21 | 19,200 | 0 | 0 |
| 1 KB | 64 | Proxy (Inspect On - Redact) | 1,200.8 [1070.4–1296.0] | 51.16 | 91.54 | 19,200 | 0 | 0 |
| **100 KB** | 1 | Direct | 10,304.7 [7191.7–22710.1] [!] | 0.09 | 0.17 | 240 | 0 | 0 |
| 100 KB | 1 | Proxy (No Inspect) | 1,555.5 [1142.2–1784.2] [!] | 0.28 | 4.88 | 240 | 0 | 0 |
| 100 KB | 1 | Proxy (Inspect On - Clean) | **1,423.1** [1259.9–1750.3] | **0.50** | **4.97** | 240 | 0 | 0 |
| 100 KB | 1 | Proxy (Inspect On - Redact) | **1,049.8** [521.2–1152.3] [!] | **0.75** | **6.55** | 240 | 0 | 0 |
| **100 KB** | 16 | Direct | 73,579.4 [38619.2–75260.9] [!] | 0.20 | 0.37 | 1,920 | 0 | 0 |
| 100 KB | 16 | Proxy (No Inspect) | 1,404.9 [1239.3–1430.0] | 8.69 | 23.11 | 1,920 | 0 | 0 |
| 100 KB | 16 | Proxy (Inspect On - Clean) | **1,344.0** [1112.9–1366.3] | **9.06** | **23.39** | 1,920 | 0 | 0 |
| 100 KB | 16 | Proxy (Inspect On - Redact) | **923.2** [836.0–950.3] | **16.16** | **30.56** | 1,920 | 0 | 0 |
| **100 KB** | 64 | Direct | 54,144.2 [48314.1–56255.7] | 1.11 | 1.98 | 7,680 | 0 | 0 |
| 100 KB | 64 | Proxy (No Inspect) | 1,229.6 [1159.6–1236.2] | 50.51 | 78.74 | 7,680 | 0 | 0 |
| 100 KB | 64 | Proxy (Inspect On - Clean) | 1,123.7 [824.8–1175.1] | 55.58 | 94.32 | 7,680 | 0 | 0 |
| 100 KB | 64 | Proxy (Inspect On - Redact) | 730.2 [520.8–781.8] [!] | 84.61 | 158.14 | 7,680 | 0 | 0 |
| **1 MB** | 1 | Direct | 3,857.1 [1275.1–4979.4] [!] | 0.26 | 0.29 | 120 | 0 | 0 |
| 1 MB | 1 | Proxy (No Inspect) | 961.0 [624.1–1263.8] [!] | 0.55 | 6.12 | 120 | 0 | 0 |
| 1 MB | 1 | Proxy (Inspect On - Clean) | **307.5** [216.0–318.5] | **3.14** | **4.75** | 120 | 0 | 0 |
| 1 MB | 1 | Proxy (Inspect On - Redact) | **181.9** [150.1–186.7] | **5.26** | **7.43** | 120 | 0 | 0 |
| **1 MB** | 16 | Direct | 7,753.5 [6403.2–8006.0] | 1.98 | 4.68 | 960 | 0 | 0 |
| 1 MB | 16 | Proxy (No Inspect) | 823.2 [802.8–1051.3] | 14.50 | 44.91 | 960 | 0 | 0 |
| 1 MB | 16 | Proxy (Inspect On - Clean) | **732.2** [296.2–794.1] [!] | **19.35** | **50.71** | 960 | 0 | 0 |
| 1 MB | 16 | Proxy (Inspect On - Redact) | **592.0** [480.5–610.1] | **25.79** | **41.64** | 960 | 0 | 0 |
| **1 MB** | 64 | Direct | 7,426.5 [7113.4–7893.3] | 7.90 | 15.04 | 3,840 | 0 | 0 |
| 1 MB | 64 | Proxy (No Inspect) | 832.6 [822.3–869.8] | 72.64 | 137.70 | 3,840 | 0 | 0 |
| 1 MB | 64 | Proxy (Inspect On - Clean) | **625.9** [447.7–707.9] [!] | **98.47** | **164.01** | 3,840 | 0 | 0 |
| 1 MB | 64 | Proxy (Inspect On - Redact) | **475.7** [381.3–511.1] | **124.59** | **234.12** | 3,840 | 0 | 0 |

*Note: Rows marked `[!]` exhibit max/min ratios $> 1.5$, primarily occurring at low payload sizes or concurrency 1 where sub-millisecond execution times are sensitive to macOS thread scheduling.*

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
