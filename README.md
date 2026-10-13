# DLP Proxy

A lightweight, TLS-intercepting HTTP Data Loss Prevention (DLP) proxy written in Rust on top of [hudsucker](https://github.com/omjadas/hudsucker) and Tokio. It enforces domain policies and inspects outbound HTTP request bodies for sensitive data (API keys, credit card numbers, emails, and high-entropy secrets) to block or redact them before they leave your machine.

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
The proxy will start on `http://127.0.0.1:3000`.

### 4. Send a Request Through the Proxy

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
   - **Regex Matching:** Linear-time scanning for structured patterns (`AKIA...`, emails).
   - **Luhn Algorithm:** Validates candidate 13–19 digit sequences for credit card checksum compliance.
   - **Shannon Entropy Check:** Computes bits-per-character entropy on candidate tokens to catch unstructured secret keys.
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

## Threat Model & Limitations

- **Certificate Pinning:** Applications utilizing certificate pinning (or custom trust stores that reject the local CA) will abort the TLS handshake.
- **Binary & Multipart Payloads:** Currently inspects valid UTF-8 text bodies. Non-UTF-8 binary bodies are logged and forwarded (`// ponytail: text bodies only`).
- **Chunked Across Requests:** Secrets segmented across multiple distinct HTTP requests or web sockets are not reconstructed.
- **Client Trust Scope:** Only test devices configured with `ca.pem` trust the proxy.

---

## Code Budget & Shortcut Ledger

The core codebase is held strictly under the ~500-line architecture budget using the **Ponytail rule ladder**:

| File | Job | Line Budget | Actual Lines |
| :--- | :--- | :--- | :--- |
| `main.rs` | Load CA, config, start proxy | 60 | 47 |
| `config.rs` | Parse `rules.toml` | 50 | 48 |
| `policy.rs` | Per-domain allow/block/inspect lookup | 50 | 44 |
| `detect.rs` | Regex, Luhn check, entropy, redaction | 120 | 89 |
| `handler.rs` | Hudsucker HTTP request handler | 120 | 115 |
| `log.rs` | Structured JSON decision logger | 40 | 22 |
| **Total** | | **440** | **365** |

### Shortcut Ledger (`grep -rn "ponytail:" src/`)

1. `src/policy.rs:39`: Exact host match only.  
   *Upgrade path:* Support wildcard globbing and suffix matching (e.g. `*.example.com`).
2. `src/handler.rs:59`: Reads body into memory up to size cap.  
   *Upgrade path:* Stream inspection with sliding window and rolling size cap.
3. `src/handler.rs:73`: Text bodies only.  
   *Upgrade path:* Support multipart/form-data and binary format decoders.
4. `src/config.rs:44`: Reads config from disk on startup.  
   *Upgrade path:* Config hot-reloading with `notify`.
5. `src/detect.rs:38`: One regex pass per rule.  
   *Upgrade path:* Compile rules into `regex::RegexSet` for single-pass scanning.

---

## Benchmark & Quality Summary

Measured on **Apple M1 (arm64)** running **macOS** with **rustc 1.94.1**:

### Detection Quality (400-Sample Labelled Dataset)
- **Precision:** 100.0%
- **Recall:** 100.0%
- *(Run `cargo run --example evaluate`)*

### Performance (1 KB Payload, Concurrency 16)
- **Proxy (No Inspect):** 9,075.4 req/s (p50: 1.52 ms, p99: 3.82 ms)
- **Proxy (Inspect On):** 7,951.5 req/s (p50: 1.70 ms, p99: 4.32 ms)
- **Inspection Overhead:** **+0.18 ms p50**, **+0.50 ms p99**
- *(Full matrix available in `bench/RESULTS.md` via `cargo run --release --example benchmark`)*

---

## License & Credits

- Underlying MITM engine: [hudsucker](https://github.com/omjadas/hudsucker) (dual-licensed Apache-2.0 and MIT).
- DLP inspection layer is licensed under MIT OR Apache-2.0.
