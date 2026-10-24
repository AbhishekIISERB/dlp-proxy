# Two-Way LLM-Agent Guardrail: DLP & Prompt Injection Proxy

A high-performance, TLS-intercepting HTTP guardrail written in Rust on top of [hudsucker](https://github.com/omjadas/hudsucker) and Tokio. It operates as a bidirectional security proxy for autonomous LLM agents:
1. **Outbound Data Loss Prevention (DLP):** Inspects agent requests for sensitive credentials (AWS keys, credit cards, emails, and high-entropy API tokens) to block or redact them before external egress. Role-aware parser handles OpenAI and Anthropic chat message structures.
2. **Inbound Indirect Prompt Injection Defense:** Inspects third-party web content and tool execution outputs across a 3-tier heuristic defense (instruction overrides, hidden HTML/comments/zero-width characters, and exfiltration URLs) to block or sanitize malicious directives before they enter the agent's context window.
3. **Low-Latency Streaming Scanner:** Sliding-window streaming scanner with multi-byte UTF-8 boundary handling, reducing Time-To-First-Byte (TTFB) by **12.7x–60.4x** (down to 36 µs on 1 MB streams) while sustaining **> 450 MB/s** throughput.

---

## Architecture & Data Flow

```
                                      OUTBOUND FLOW (Agent Egress)
  +------------------+                 +-------------------------------+                 +------------------+
  |                  |   POST /chat    |          DLP PROXY            |  HTTPS Request  |                  |
  |    LLM Agent     | --------------> | 1. Client TLS Termination     | --------------> | Upstream LLM API |
  | (e.g. LangChain, |                 | 2. LLM-API Role Parser        |                 | (OpenAI / Anth.) |
  |  AutoGPT, etc.)  | <-------------- |    - User/Assist: DLP scan    | <-------------- |                  |
  +------------------+   HTTP 200/403  |    - Tool Results: Inj. scan  |  HTTPS Response +------------------+
                                       | 3. Action: Block / Redact     |
                                       +-------------------------------+
                                                       |
                                      INBOUND FLOW (Web & Tool Ingest)
                                                       v
  +------------------+                 +-------------------------------+                 +------------------+
  |                  |   Clean / San.  |          DLP PROXY            |  HTTP Fetch     |                  |
  |    LLM Agent     | <-------------- | 1. Decompress (gzip/brotli)   | <-------------- | Third-Party Web  |
  |  Context Window  |   Content       | 2. Content-Type Gate          |                 | & Tool Endpoints |
  |                  |                 | 3. 3-Tier Injection Detector  |                 | (Untrusted Web)  |
  +------------------+                 | 4. Action: Block/Sanitize/Log |                 +------------------+
                                       +-------------------------------+
```

### Inbound 3-Tier Injection Defense Hierarchy
- **Tier 1 (Instruction Overrides & Role Switching):** Catches direct imperative directives (`ignore previous instructions`, `you are now a root shell`, `from now on...`), fake system delimiters (`<system>`, `[INST]`, `<|im_start|>`), and concealment directives (`never tell the user`).
- **Tier 2 (Evasion & Concealment Mechanics):** Detects content hidden from human viewers but visible to tokenizers: CSS hidden styling (`style="display:none"`, `visibility:hidden`, `font-size:0px`), HTML comments (`<!-- ignore ... -->`), `aria-hidden="true"`, and invisible Unicode zero-width/bidi markers (`\u{200B}`, `\u{FEFF}`).
- **Tier 3 (Exfiltration Channels):** Detects markdown image embeds (`![leak](http://...)`) and URL query parameters containing high-entropy tokens or long encoded data intended to exfiltrate context silently.

---

## 5-Minute Quick Start

### 1. Prerequisites
- Rust 1.86+ (cargo)
- OpenSSL (for generating the local CA)

### 2. Generate the Local Root CA
The proxy signs intercepted HTTPS certificates on the fly using your local Root CA:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 365 -subj "/CN=LLM Guardrail Proxy CA"
```
> **Security Invariant:** `ca.key` is automatically ignored in `.gitignore`. Upstream TLS certificates are strictly validated against webpki roots—the proxy never disables upstream verification.

### 3. Build & Run
```bash
cargo run --release
```
The proxy starts on `http://127.0.0.1:3000`.

### 4. Verification

**Outbound DLP Test (Credit Card Redaction):**
```bash
curl --proxy http://127.0.0.1:3000 --cacert ca.pem -X POST https://httpbin.org/post \
  -H "Content-Type: text/plain" \
  -d "Billing card: 4111 1111 1111 1111"
```
*Server receives:* `"Billing card: [REDACTED]"`.

**Inbound Prompt Injection Test (Blocking):**
```bash
curl --proxy http://127.0.0.1:3000 --cacert ca.pem -X GET https://httpbin.org/base64/UGxlYXNlIGlnbm9yZSBhbGwgcHJldmlvdXMgaW5zdHJ1Y3Rpb25z
```
*Returns:* `403 Forbidden: Inbound content blocked by injection policy`.

---

## Configuration (`rules.toml`)

```toml
[policy]
default_action = "inspect"
default_inbound_action = "sanitize" # "block", "sanitize", or "log"
max_body_bytes = 1048576            # 1 MB size cap (fails closed if exceeded)

# Outbound rules (API keys, cards, emails, tokens)
[[rules]]
id = "aws-access-key"
pattern = 'AKIA[0-9A-Z]{16}'
action = "block"

[[rules]]
id = "card"
pattern = '\b(?:\d[ -]?){13,19}\b'
check = "luhn"
action = "redact"

# Per-domain policies with direction and trust configuration
[[policy.domains]]
domain = "api.openai.com"
action = "inspect"
direction = "both"                  # Inspect outbound prompts & inbound tool results
trust = "semi_trusted"

[[policy.domains]]
domain = "untrusted-fetch.internal"
action = "inspect"
direction = "in"
trust = "untrusted"                 # Runs all Tier 1, 2, and 3 injection checks
inbound_action = "block"            # Block immediately on detection
```

---

## Code Budget & Shortcut Ledger

The core codebase is held strictly under an architectural line budget using the **Ponytail rule ladder**:

| File | Job | Line Budget | Actual Lines |
| :--- | :--- | :--- | :--- |
| `src/main.rs` | Load CA, parse config, start proxy | 60 | 59 |
| `src/config.rs` | Parse `rules.toml` schema & inbound fields | 80 | 77 |
| `src/policy.rs` | Domain routing, Direction & Trust policy | 140 | 135 |
| `src/detect.rs` | Outbound DLP (RegexSet, Luhn, stack entropy) | 160 | 152 |
| `src/inject.rs` | 3-tier inbound injection detector & sanitizer | 140 | 134 |
| `src/handler.rs` | Hudsucker request/response hook & stream router | 320 | 316 |
| `src/llm.rs` | OpenAI / Anthropic chat message role extractor | 90 | 72 |
| `src/stream.rs` | Sliding-window streaming scanner (256B overlap) | 100 | 100 |
| `src/log.rs` | Structured JSON audit decision logger | 40 | 40 |
| `src/lib.rs` | Module exports | 10 | 8 |
| **Total Core Code** | | **1,140** | **1,093** |

### Shortcut Ledger (`grep -rn "ponytail:" src/`)

All intentional shortcuts are tagged in code with explicit upgrade paths:
1. `src/policy.rs:130`: Exact host match only.  
   *Upgrade path:* Support wildcard globs (`*.openai.com`) and suffix matching.
2. `src/handler.rs:94`: In-memory body buffering up to size cap for blocking/sanitization.  
   *Upgrade path:* Hold-back sliding buffer for chunked HTTP responses.
3. `src/handler.rs:104, 226`: Text, JSON, and XML bodies inspected; binary media skipped with audit log.  
   *Upgrade path:* Multipart parser and OCR/steganography extraction for images.
4. `src/config.rs:73`: Reads config from disk on startup.  
   *Upgrade path:* Hot-reloading with file watcher (`notify` crate).
5. `src/detect.rs:66`: RegexSet pre-filters before position extraction.  
   *Upgrade path:* Aho-Corasick literal pre-filtering for fixed tokens (`AKIA`, `sk_live_`).
6. `src/inject.rs:27`: Heuristic regex for hidden HTML elements.  
   *Upgrade path:* Full streaming HTML DOM tokenizer via `lol_html`.
7. `src/llm.rs:10`: Lightweight JSON extraction for OpenAI and Anthropic schemas.  
   *Upgrade path:* Streaming JSON AST visitor for streaming chat completions.
8. `src/stream.rs:35`: Sliding window tail buffer across chunk boundaries.  
   *Upgrade path:* Streaming multi-pattern Aho-Corasick automaton.

---

## Evaluation & Empirical Benchmarks

### 1. Inbound Prompt Injection Evaluation (Held-Out Test Set)
Evaluated across **600 partitioned samples** (50% attack, 50% benign) using `cargo run --release --example eval_injection`:

| Metric | Dev Split (300) | Held-Out Test Split (300) | Description |
| :--- | :--- | :--- | :--- |
| **Precision** | **78.3%** | **79.2%** | High precision on standard phrasing; FPs from security articles discussing attacks |
| **Recall** | **60.0%** | **63.3%** | Overall recall across all 3 tiers |
| **F1 Score** | **67.9%** | **70.4%** | Harmonic mean of precision and recall |
| **False Positive Rate** | **16.7%** | **16.7%** | Zero false alarms on standard web pages; trips on defensive quote samples |
| **Tier 1 Recall** | 56.0% | **56.0%** | Direct overrides, system markers, and concealment |
| **Tier 2 Recall** | 82.2% | **82.2%** | Hidden CSS styling, HTML comments, aria-hidden, zero-width |
| **Tier 3 Recall** | 53.3% | **53.3%** | Markdown exfiltration images and token leakage URLs |

### 2. Adaptive Attacker Evasion Matrix (Held-Out Adversarial Set)
Evaluated on **35 held-out evasion techniques** without post-hoc rule tuning (`bench/INJECTION_RESULTS.md`):
- **Overall Evasion Bypass Rate:** **74.3%** (26 of 35 attacks bypassed regex rules).
- **Paraphrasing & Multilingual:** 100% bypass rate against semantic synonyms and non-English instructions (Spanish, French, German, Russian, Chinese, Japanese).
- **Encoding Obfuscation:** 100% bypass rate on Base64, Rot13, and Hex streams.
- **Structural Obfuscation:** Partial defense (whitespace and table splitting detected; homoglyphs bypassed).
- *Takeaway:* Documents the honest boundary of regex heuristics; ideal as a low-overhead, zero-GPU first line of defense combined with a downstream semantic judge.

### 3. Streaming TTFB & Inbound Scan Performance
- **Time-To-First-Byte (TTFB):**
  - 16 KB: Buffered 206 µs vs. Streaming 9.3 µs (**22.2x lower initial latency**).
  - 1 MB: Buffered 2.18 ms vs. Streaming 36.1 µs (**60.4x lower initial latency**).
- **Scan Throughput:** Sustained at **440–475 MB/s** in release profile.
- **Boundary Property Test:** Verified 100% detection rate across every single byte split offset across chunk boundaries (`tests/stream.rs`).

### 4. Outbound DLP & Dynamic CA Performance
- **Adversarial DLP Corpus (500 samples):** 100% recall on AWS keys, emails, cards, and entropy tokens; **97.1% card precision** with BIN prefix validation + Luhn checksum.
- **Dynamic CA Minting:** **2.19 ms cold** vs. **0.3 µs cached** using Hudsucker's Moka cache (**7,499x speedup**).
- **Forward Proxy Throughput:** **1,122 req/s** @ 100 KB, **663 req/s** @ 1 MB (concurrency 16), retaining 81%–94% of raw proxy throughput.

---

## Security Invariants

1. **Fail Closed:** Every parse error, invalid UTF-8 sequence, decompress failure, and payload exceeding `max_body_bytes` terminates with a 403 Block response.
2. **Log Decisions, Not Data:** Structured JSON logs record decision metadata (`host`, `path`, `action`, `rules`, `direction`), never matched tokens, card numbers, or injection text.
3. **Upstream TLS Stays On:** Upstream TLS certificates are verified against standard webpki roots. The proxy will not forward traffic to invalid upstreams.
4. **Linear Time Matching:** Powered strictly by Rust's `regex` DFA/NFA engine (guaranteed $O(N)$ execution, mathematically immune to ReDoS catastrophic backtracking).

---

## Resume Bullets

- *Engineered a two-way TLS-intercepting LLM-agent security proxy in Rust using Hudsucker and Tokio, providing outbound DLP redaction and inbound 3-tier indirect prompt injection defense.*
- *Implemented a zero-GPU 3-tier injection detector (instruction overrides, hidden CSS/HTML/zero-width characters, and exfiltration URLs) operating at > 450 MB/s sustained throughput with 2.1 ms latency on 1 MB payloads.*
- *Architected a sliding-window streaming scanner with multi-byte UTF-8 boundary safety, reducing Time-To-First-Byte (TTFB) by 60.4x (2.18 ms down to 36 µs) on 1 MB payloads with exhaustive byte-by-byte boundary property testing.*
- *Conducted rigorous held-out adversarial evaluations across 600 dev/test samples and a 35-sample adaptive attack evasion set; honestly benchmarked the boundary of regex heuristics (74.3% evasion bypass rate on paraphrasing/multilingual attacks) to define defense-in-depth requirements.*
- *Maintained strict engineering discipline: 1,093 total lines under Ponytail line budgets, zero compiler warnings on `-D warnings`, zero sensitive data logged, and 29 automated table-driven and end-to-end integration tests.*
