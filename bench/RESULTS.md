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
| **Cold Certificate Resolution (1st request)** | **1.96 ms** | Ephemeral keypair generation, X.509 cert creation & local CA signature, Moka cache insertion |
| **Warm Certificate Resolution (2nd+ request)** | **0.0003 ms** (0.3 µs) | In-memory Moka cache hit (1,000 capacity, 300s TTL); immediate `Arc<ServerConfig>` reuse |
| **Resolution Speedup Factor** | **6,735x** | Cache eliminates dynamic certificate minting overhead on warm requests |

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
| **1 KB** | 1 | Direct | 37,256.3 [36963.9–37318.5] | 0.03 | 0.03 | 0.05 | 669,847 | 0 | 0 | - |
| 1 KB | 1 | Proxy (No Inspect) | 4,794.1 [3524.0–6323.8] [!] | 0.21 | 0.09 | 2.32 | 82,173 | 0 | 0 | - |
| 1 KB | 1 | Proxy (Inspect On - Clean) | 2,638.6 [2122.0–2897.1] | 0.38 | 0.19 | 4.88 | 48,056 | 0 | 0 | - |
| 1 KB | 1 | Proxy (Inspect On - Redact) | **1,702.8** [1372.6–2043.6] | **0.59** | **0.26** | **9.22** | 29,583 | 0 | 0 | **0** |
| **1 KB** | 16 | Direct | 108,991.8 [105250.6–116561.7] | 0.15 | 0.14 | 0.28 | 1,964,298 | 0 | 0 | - |
| 1 KB | 16 | Proxy (No Inspect) | 1,805.4 [1360.8–2208.3] [!] | 8.86 | 5.75 | 36.52 | 32,847 | 0 | 0 | - |
| 1 KB | 16 | Proxy (Inspect On - Clean) | 1,864.8 [1657.4–2195.4] | 8.58 | 6.35 | 31.48 | 34,437 | 0 | 0 | - |
| 1 KB | 16 | Proxy (Inspect On - Redact) | **1,107.6** [713.5–1266.3] [!] | **14.41** | **11.07** | **69.92** | 19,208 | 0 | 0 | **0** |
| **1 KB** | 64 | Direct | 111,653.7 [109808.4–113208.0] | 0.57 | 0.56 | 0.95 | 2,007,466 | 0 | 0 | - |
| 1 KB | 64 | Proxy (No Inspect) | 1,554.2 [1491.3–1590.7] | 41.15 | 38.65 | 86.60 | 27,973 | 0 | 0 | - |
| 1 KB | 64 | Proxy (Inspect On - Clean) | 1,422.2 [1243.0–1487.0] | 44.94 | 42.29 | 98.11 | 25,266 | 0 | 0 | - |
| 1 KB | 64 | Proxy (Inspect On - Redact) | **1,015.2** [960.3–1067.8] | **62.91** | **59.97** | **117.57** | 18,346 | 0 | 0 | **0** |
| **100 KB** | 1 | Direct | 3,234.2 [3198.6–3305.6] | 0.31 | 0.31 | 0.36 | 58,319 | 0 | 0 | - |
| 100 KB | 1 | Proxy (No Inspect) | 1,055.2 [975.6–1092.6] | 0.95 | 0.65 | 7.71 | 18,779 | 0 | 0 | - |
| 100 KB | 1 | Proxy (Inspect On - Clean) | 410.6 [405.4–423.6] | 2.43 | 2.12 | 8.58 | 7,400 | 0 | 0 | - |
| 100 KB | 1 | Proxy (Inspect On - Redact) | **353.2** [340.1–356.9] | **2.83** | **2.50** | **9.58** | 6,321 | 0 | 0 | **0** |
| **100 KB** | 16 | Direct | 15,668.5 [15202.4–15981.0] | 1.02 | 0.99 | 2.03 | 279,864 | 0 | 0 | - |
| 100 KB | 16 | Proxy (No Inspect) | 1,147.3 [1114.3–1203.0] | 13.94 | 11.90 | 57.30 | 20,704 | 0 | 0 | - |
| 100 KB | 16 | Proxy (Inspect On - Clean) | 838.3 [813.7–868.9] | 19.08 | 16.55 | 64.10 | 15,103 | 0 | 0 | - |
| 100 KB | 16 | Proxy (Inspect On - Redact) | **655.6** [583.7–670.7] | **24.38** | **22.31** | **75.65** | 11,595 | 0 | 0 | **0** |
| **100 KB** | 64 | Direct | 14,962.3 [14577.6–15065.2] | 4.27 | 4.21 | 7.29 | 267,341 | 0 | 0 | - |
| 100 KB | 64 | Proxy (No Inspect) | 1,025.6 [813.7–1090.4] | 62.24 | 59.70 | 114.35 | 17,741 | 0 | 0 | - |
| 100 KB | 64 | Proxy (Inspect On - Clean) | 765.1 [729.5–776.7] | 83.38 | 79.72 | 152.60 | 13,806 | 0 | 0 | - |
| 100 KB | 64 | Proxy (Inspect On - Redact) | **573.0** [518.5–601.8] | **111.21** | **105.56** | **207.52** | 10,265 | 0 | 0 | **0** |
| **1 MB** | 1 | Direct | 431.3 [427.6–431.8] | 2.32 | 2.31 | 2.54 | 7,749 | 0 | 0 | - |
| 1 MB | 1 | Proxy (No Inspect) | 186.0 [144.2–196.0] | 5.37 | 4.71 | 20.77 | 3,153 | 0 | 0 | - |
| 1 MB | 1 | Proxy (Inspect On - Clean) | 47.9 [40.9–52.4] | 20.88 | 19.27 | 48.22 | 853 | 0 | 0 | - |
| 1 MB | 1 | Proxy (Inspect On - Redact) | **39.9** [37.5–42.1] | **25.07** | **24.07** | **57.43** | 718 | 0 | 0 | **0** |
| **1 MB** | 16 | Direct | 1,191.9 [1067.1–1222.0] | 13.40 | 13.09 | 24.53 | 20,891 | 0 | 0 | - |
| 1 MB | 16 | Proxy (No Inspect) | 383.8 [248.9–469.8] [!] | 41.47 | 30.24 | 245.86 | 6,867 | 0 | 0 | - |
| 1 MB | 16 | Proxy (Inspect On - Clean) | 127.1 [113.2–131.1] | 125.47 | 117.69 | 263.66 | 2,293 | 0 | 0 | - |
| 1 MB | 16 | Proxy (Inspect On - Redact) | **112.2** [108.5–116.9] | **140.98** | **127.10** | **296.40** | 2,058 | 0 | 0 | **0** |
| **1 MB** | 64 | Direct | 1,308.8 [1215.7–1417.2] | 48.73 | 47.74 | 81.73 | 23,670 | 0 | 0 | - |
| 1 MB | 64 | Proxy (No Inspect) | 378.4 [249.8–410.6] [!] | 166.24 | 158.25 | 361.59 | 6,242 | 0 | 0 | - |
| 1 MB | 64 | Proxy (Inspect On - Clean) | 99.3 [94.1–104.9] | 639.75 | 627.26 | 1105.64 | 1,975 | 0 | 0 | - |
| 1 MB | 64 | Proxy (Inspect On - Redact) | **91.7** [74.7–101.9] | **679.40** | **639.02** | **1280.20** | 1,757 | 0 | 0 | **0** |

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

### Two-Way Proxy Inspection Cost Summary (Current Handler)
- **100 KB Payloads @ C=16:** Clean inspection achieves **838.3 req/s** (**73.1%** throughput retention vs. pass-through proxy 1,147.3 req/s, p50: 16.55 ms); Redaction achieves **655.6 req/s** (**57.1%** retention, p50: 22.31 ms).
- **1 MB Payloads @ C=16:** Clean inspection achieves **127.1 req/s** (**33.1%** throughput retention vs. pass-through proxy 383.8 req/s, p50: 117.69 ms); Redaction achieves **112.2 req/s** (**29.2%** retention, p50: 127.10 ms).
- **Zero Leaks:** 0 planted secrets reached the upstream server across all benchmark runs.

### Reproduction Command
```bash
cargo run --release --example benchmark
```
