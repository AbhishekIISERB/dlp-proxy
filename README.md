# DLP Proxy

A lightweight, TLS-intercepting HTTP Data Loss Prevention (DLP) proxy written in Rust on top of [hudsucker](https://github.com/omjadas/hudsucker) and Tokio. It enforces per-domain policies and inspects outbound HTTP request bodies for sensitive data (API keys, credit card numbers, emails, and high-entropy secrets) to block or redact them before they leave your machine.

---

## 5-Minute Quick Start

### 1. Prerequisites
- Rust 1.86+ (cargo)
- OpenSSL (for generating the local CA)

### 2. Generate the Local Root CA
The proxy signs intercepted HTTPS certificates on the fly using your local Root CA. Generate a private key and self-signed certificate:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 365 -subj "/CN=DLP Proxy CA"
```

> **Security Note:** `ca.key` is automatically ignored in `.gitignore`. Never commit or share your private key.

### 3. Build & Run the Proxy
```bash
cargo run --release
```
The proxy starts on `http://127.0.0.1:3000`.

### 4. Send Requests Through the Proxy

**Test Redaction (Credit Card):**
```bash
curl --proxy http://127.0.0.1:3000 --cacert ca.pem -X POST https://httpbin.org/post \
  -H "Content-Type: text/plain" \
  -d "Paying with card 4111 1111 1111 1111"
```
The upstream server receives: `"Paying with card [REDACTED]"`.

**Test Blocking (AWS Access Key):**
```bash
curl --proxy http://127.0.0.1:3000 --cacert ca.pem -X POST https://httpbin.org/post \
  -H "Content-Type: text/plain" \
  -d "My key is AKIAIOSFODNN7EXAMPLE"
```
Returns `403 Forbidden: Blocked by DLP Proxy`.

---

## Request Path & Architecture

1. **Client TLS Termination:** Client establishes an HTTPS connection through the proxy. Hudsucker completes the client TLS handshake using a dynamic certificate minted by `RcgenAuthority` from your local CA.
2. **Domain Policy (`policy.rs`):** The handler extracts the request host and checks `rules.toml`.
   - `block`: Immediately aborts with a 403 Forbidden response.
   - `allow`: Forwards directly to upstream untouched.
   - `inspect`: Continues to inspection stage.
3. **Body Ingestion & Decompression:** The body is size-checked against `max_body_bytes` and decompressed using Hudsucker's streaming decoder if compressed (gzip, deflate, brotli, zstd).
4. **Pattern & Secret Detection (`detect.rs`):**
   - **RegexSet Pre-filtering:** Single-pass multi-pattern DFA match before position extraction.
   - **Luhn Algorithm:** Validates candidate 13–19 digit sequences for credit card checksum compliance.
   - **Shannon Entropy Check:** Computes bits-per-character entropy on candidate tokens using a stack-allocated zero-allocation frequency array.
5. **Action Enforcement:**
   - **Block:** Halts request and responds with 403.
   - **Redact:** Non-overlapping hits are redacted from back to front to preserve byte indices; `Content-Length` is updated.
   - **Log:** Allows the request through and records match IDs.
6. **Audit Logging (`log.rs`):** Emits one structured JSON line per decision containing host, path, rule IDs, and action—**never logging matched sensitive text or raw payload bodies**.
7. **Upstream Forwarding:** Intercepted requests are forwarded upstream over TLS with **strict upstream certificate verification enabled**.

---

## Guardrails & Security Model

- **Upstream Certificate Verification Stays On:** Upstream TLS certificates are verified against standard webpki roots. The proxy will not forward traffic to invalid or MITM'd upstreams.
- **Fail Closed:** Any inspection failure, decode failure, or payload exceeding `max_body_bytes` results in a 403 block.
- **Linear-Time Detection:** Powered by Rust's `regex` engine (guaranteed linear runtime, immune to ReDoS attacks).
- **Log Decisions, Not Data:** Sensitive tokens are never written to stdout, logs, or disk.

---

## Code Budget & Shortcut Ledger

The core codebase is held strictly under the architecture budget using the **Ponytail rule ladder**:

| File | Job | Line Budget | Actual Lines |
| :--- | :--- | :--- | :--- |
| `main.rs` | Load CA, config, start proxy | 60 | 53 |
| `config.rs` | Parse `rules.toml` | 50 | 48 |
| `policy.rs` | Per-domain allow/block/inspect lookup | 50 | 44 |
| `detect.rs` | RegexSet, Luhn check, zero-alloc entropy, redaction | 120 | 104 |
| `handler.rs` | Hudsucker HTTP request handler | 120 | 115 |
| `log.rs` | Structured JSON decision logger | 40 | 22 |
| **Total Core Code** | | **440** | **386** |

### Shortcut Ledger (`grep -rn "ponytail:" src/`)

1. `src/policy.rs:39`: Exact host match only.  
   *Upgrade path:* Support wildcard globbing and suffix matching (e.g. `*.example.com`).
2. `src/handler.rs:59`: Reads body into memory up to size cap.  
   *Upgrade path:* Stream inspection with sliding window and rolling size cap.
3. `src/handler.rs:73`: Text bodies only.  
   *Upgrade path:* Support multipart/form-data and binary format decoders.
4. `src/config.rs:44`: Reads config from disk on startup.  
   *Upgrade path:* Config hot-reloading with `notify`.
5. `src/detect.rs:49`: RegexSet pre-filters rules before exact position extraction.  
   *Upgrade path:* Aho-Corasick literal pre-filtering for fixed prefixes (`AKIA`, `sk_live_`).

---

## Benchmark & Quality Summary

Measured on **Apple M1 (arm64)** running **macOS** with **rustc 1.94.1**:

### 1. Adversarial Detection Quality (500-Sample Corpus)
- **AWS Keys:** 100.0% Precision, 100.0% Recall
- **Emails:** 100.0% Precision, 100.0% Recall
- **Credit Cards:** **94.3% Precision**, **100.0% Recall** (6 out of 50 adversarial 16-digit order numbers passed Luhn by random chance, confirming the expected 1-in-10 false positive rate).
- **High-Entropy Tokens:** **28.6% Precision**, **100.0% Recall** (125 false positives on UUIDs, Git commit SHAs, base64 data, and JWTs, demonstrating why entropy detection is scoped to `action = "log"` rather than automated blocking).
- *(Run `cargo run --example evaluate`)*

### 2. Dynamic CA Certificate Minting Latency
Measured using Hudsucker's `RcgenAuthority` (`hudsucker/src/certificate_authority/rcgen_authority.rs:48, 65-68`):
- **Cold Request (Keygen + X.509 Minting):** **3.03 ms**
- **Warm Request (Moka Cache Hit, 300s TTL):** **0.0003 ms** (0.3 µs)
- **Cache Speedup Factor:** **12,110x**

### 3. Forwarding & Inspection Throughput
- **1 KB Payload @ Concurrency 16:** **8,069.8 req/s** (p50: 1.53 ms, p99: 5.93 ms) vs. pass-through proxy **10,462.4 req/s** (p50: 1.30 ms). Inspection overhead is **+0.23 ms p50**.
- **Body Size Scaling:** Inspection cost scales at **~17.4 ms per MB scanned** at concurrency 1 (0.22 ms @ 1 KB vs. 2.36 ms @ 100 KB vs. 17.93 ms @ 1 MB).
- *(Full matrix available in `bench/RESULTS.md` via `cargo run --release --example benchmark`)*

---

## Resume Bullets

- *Built a TLS-intercepting HTTP proxy in Rust on hudsucker and Tokio, with per-domain policy and regex, Luhn and entropy detection that blocks or redacts sensitive request data.*
- *Evaluated on a 500-sample adversarial corpus: achieved 100% recall across all rules, 94.3% precision on cards against 16-digit order numbers (where ~10% pass Luhn by chance), and quantified false-positive trade-offs for entropy detection on UUIDs and Git SHAs.*
- *Measured dynamic CA cert minting at 3.03 ms cold vs. 0.3 µs warm using Hudsucker’s Moka cache. At 1 KB payload (16 concurrent connections), inspection added 0.23 ms p50 latency, scaling to ~17 ms per MB scanned at concurrency 1.*
- *Held the codebase to 386 lines using a Ponytail rule ladder, documenting all shortcuts with explicit upgrade paths, and verified with table-driven and end-to-end integration tests.*

---

## Sources & References

1. **Hudsucker Proxy**: [github.com/omjadas/hudsucker](https://github.com/omjadas/hudsucker) (v0.25.0)
   - `RcgenAuthority` Moka cache: `hudsucker/src/certificate_authority/rcgen_authority.rs` lines 48 (`cache: Cache<Authority, Arc<ServerConfig>>`) & lines 65–68 (`Cache::builder().max_capacity(...).time_to_live(...)`).
   - Cache TTL constant: `hudsucker/src/certificate_authority/mod.rs` line 12 (`CACHE_TTL: u64 = 300`).
2. **Luhn Algorithm**: ISO/IEC 7812-1 standard for credit card account number verification.
3. **Shannon Entropy**: Claude Shannon, *A Mathematical Theory of Communication* (1948).
