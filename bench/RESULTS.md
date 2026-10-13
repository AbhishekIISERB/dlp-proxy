# DLP Proxy Benchmark & Evaluation Results

Generated: Oct 13, 2026  
Environment: Apple M1 (8 cores: 4 performance + 4 efficiency, arm64), macOS, rustc 1.94.1  
Commit: f439292  

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

| Payload | Concurrency | Setup | Requests/sec (Med [Min–Max]) | p50 Latency (ms) | p99 Latency (ms) | Errors |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1 KB** | 1 | Direct | 40,102.6 [35604.1–53252.9] | 0.02 | 0.04 | 0 |
| 1 KB | 1 | Proxy (No Inspect) | 10,648.3 [8429.2–12293.5] | 0.06 | 0.23 | 0 |
| 1 KB | 1 | Proxy (Inspect On) | 11,206.6 [3384.8–12420.8] [!] | 0.07 | 0.30 | 0 |
| **1 KB** | 16 | Direct | 156,300.2 [148497.0–170757.0] | 0.09 | 0.26 | 0 |
| 1 KB | 16 | Proxy (No Inspect) | 7,973.7 [5952.8–8906.2] | 1.29 | 15.13 | 0 |
| 1 KB | 16 | Proxy (Inspect On) | **5,080.8** [4050.9–5825.1] | **2.42** | **11.06** | 0 |
| **1 KB** | 64 | Direct | 155,618.4 [133419.6–162102.8] | 0.39 | 0.88 | 0 |
| 1 KB | 64 | Proxy (No Inspect) | 2,536.1 [1916.0–3287.0] [!] | 24.47 | 47.21 | 0 |
| 1 KB | 64 | Proxy (Inspect On) | 1,414.5 [1266.2–1590.8] | 40.01 | 464.52 | 0 |
| **100 KB** | 1 | Direct | 21,212.0 [7330.5–22323.5] [!] | 0.04 | 0.07 | 0 |
| 100 KB | 1 | Proxy (No Inspect) | 1,241.2 [815.2–1379.8] [!] | 0.29 | 10.96 | 0 |
| 100 KB | 1 | Proxy (Inspect On) | **1,207.6** [1183.2–1274.8] | **0.54** | **3.77** | 0 |
| **100 KB** | 16 | Direct | 72,375.0 [41015.4–75181.6] [!] | 0.21 | 0.36 | 0 |
| 100 KB | 16 | Proxy (No Inspect) | 1,196.8 [1143.3–1218.0] | 11.31 | 28.20 | 0 |
| 100 KB | 16 | Proxy (Inspect On) | **1,122.6** [1064.2–1145.8] | **11.11** | **27.25** | 0 |
| **100 KB** | 64 | Direct | 58,995.3 [57744.7–59626.6] | 1.03 | 2.11 | 0 |
| 100 KB | 64 | Proxy (No Inspect) | 1,079.0 [1055.5–1113.0] | 57.12 | 100.16 | 0 |
| 100 KB | 64 | Proxy (Inspect On) | 959.9 [896.3–991.7] | 65.34 | 105.04 | 0 |
| **1 MB** | 1 | Direct | 3,197.3 [2074.7–4163.3] [!] | 0.30 | 0.40 | 0 |
| 1 MB | 1 | Proxy (No Inspect) | 872.9 [716.8–1174.2] [!] | 0.54 | 9.03 | 0 |
| 1 MB | 1 | Proxy (Inspect On) | **291.9** [278.5–293.4] | **3.27** | **5.66** | 0 |
| **1 MB** | 16 | Direct | 7,821.6 [7468.8–8003.8] | 1.95 | 3.45 | 0 |
| 1 MB | 16 | Proxy (No Inspect) | 820.5 [690.6–900.6] | 15.48 | 36.71 | 0 |
| 1 MB | 16 | Proxy (Inspect On) | **663.3** [642.8–671.9] | **23.51** | **40.72** | 0 |
| **1 MB** | 64 | Direct | 6,873.0 [6083.0–7084.0] | 8.71 | 15.67 | 0 |
| 1 MB | 64 | Proxy (No Inspect) | 804.4 [731.9–816.8] | 76.25 | 133.87 | 0 |
| 1 MB | 64 | Proxy (Inspect On) | **588.9** [545.1–596.3] | **107.61** | **175.87** | 0 |

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
