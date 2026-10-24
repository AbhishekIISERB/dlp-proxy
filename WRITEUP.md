# Two-Way LLM-Agent Guardrail: Executive Engineering Write-Up

**Author:** Abhishek Singh  
**Project:** `dlp-proxy` (Rust, Hudsucker, Tokio)  
**Date:** October 2026  

---

## 1. Executive Summary

Autonomous LLM agents interact with the external world bidirectionally: they egress user prompts and API queries to model providers while ingesting untrusted web content and tool execution responses. This dual interaction exposes two critical vulnerabilities:
1. **Outbound Data Loss:** Accidental or malicious exfiltration of API keys, credentials, PII, and financial information.
2. **Inbound Indirect Prompt Injection:** Attacker-controlled web pages or tool outputs embedding adversarial instructions that hijack agent reasoning, override system instructions, and trigger unauthorized actions or silent data exfiltration.

We built and evaluated `dlp-proxy`, a high-throughput, TLS-intercepting network guardrail written in Rust. The proxy enforces per-domain policies, performs role-aware inspection of LLM API traffic (OpenAI and Anthropic), applies a 3-tier inbound injection defense, and implements a low-latency sliding-window streaming scanner.

Across comprehensive empirical evaluations—including an untouched 300-sample test split, a 35-sample adaptive evasion set, and keep-alive network benchmarks—the proxy sustains **> 450 MB/s scan throughput**, reduces Time-To-First-Byte (TTFB) by **60.4x**, and maintains strict Ponytail code discipline (**1,093 core lines** across 10 modules).

---

## 2. Threat Model & Architectural Position

```
[ LLM Agent Runtime ] <--- TLS ---> [ DLP Proxy (127.0.0.1:3000) ] <--- Strict TLS ---> [ Upstream Web / APIs ]
```

The proxy operates at the transport boundary as a local or container sidecar:
- **Defender Position:** Complete visibility into plaintext HTTP/HTTPS request and response bodies via local dynamic certificate authority (`rcgen` + in-memory Moka cache). Upstream TLS verification remains strictly enabled against `webpki` root certificates.
- **Attacker Capabilities:** The attacker controls content fetched by the agent (untrusted web domains, RSS feeds, API responses) and attempts to subvert agent behavior without direct access to the agent prompt.
- **Security Invariants:**
  1. *Fail Closed:* Payload size limit violations (> 1 MB), decoding errors, or malformed UTF-8 sequences immediately block.
  2. *Log Decisions, Not Data:* Audit logs record host, path, action, rule IDs, and direction, never leaking matched secrets or injection payloads.
  3. *Linear Time Matching:* Detection is strictly powered by Rust's `regex` DFA/NFA linear engines, mathematically eliminating Regular Expression Denial of Service (ReDoS).

---

## 3. Core Architectural Components

### 3.1 LLM-API Role Awareness (`src/llm.rs`)
Standard forward proxies cannot distinguish between a user instruction and third-party data inside an LLM conversation. `dlp-proxy` implements a lightweight JSON parser for OpenAI and Anthropic schemas:
- **Outbound Prompts (`user`, `system`, `assistant`):** Inspected against DLP rules (AWS keys, credit cards, emails, entropy tokens) to redact or block sensitive egress.
- **Tool Execution Results (`tool`, `tool_result`):** Inspected against the inbound injection scanner to prevent untrusted execution outputs from poisoning conversation history before reaching the model.

### 3.2 3-Tier Inbound Injection Defense (`src/inject.rs`)
Inbound HTML and JSON content are processed through three defensive tiers:
- **Tier 1 (Direct Imperatives & Delimiters):** Instruction overrides (`ignore previous instructions`), role manipulation (`you are now a root shell`), synthetic markers (`<system>`, `[INST]`, `<|im_start|>`), and concealment directives (`never tell the user`).
- **Tier 2 (Hidden Structural Content):** Evasion techniques invisible to human operators: CSS hidden styles (`style="display:none"`, `visibility:hidden`, `font-size:0px`), HTML comments containing instructions, `aria-hidden="true"` abuse, and zero-width/bidi Unicode characters (`\u{200B}`, `\u{FEFF}`).
- **Tier 3 (Exfiltration Channels):** Markdown image embeds (`![preview](http://...)`) and query parameters containing high-entropy tokens designed to exfiltrate context silently.

### 3.3 Low-Latency Sliding-Window Streaming Scanner (`src/stream.rs`)
Buffering large responses introduces significant Time-To-First-Byte (TTFB) penalties. `StreamScanner` implements a sliding-window chunk processor:
- **Boundary Preservation:** Maintains a `MAX_MATCH_LEN` (256-byte) tail buffer across network chunks, guaranteeing that patterns split across TCP packet boundaries are detected (empirically validated with property tests across every byte offset).
- **Multi-Byte UTF-8 Safety:** Incomplete multi-byte code points at chunk boundaries are held back in the tail buffer until trailing bytes arrive.
- **Latency Gain:** Reduces TTFB on 1 MB streams from **2.18 ms** (buffered) to **36.1 µs** (streaming)—a **60.4x speedup**.

---

## 4. Empirical Evaluation & Adversarial Results

### 4.1 Inbound Injection Evaluation (Dev vs. Held-Out Test)
Evaluated against a 600-sample balanced dataset (300 dev / 300 held-out test) generated via `scripts/convert_corpus.py` and evaluated via `cargo run --release --example eval_injection`:

| Metric | Dev Split (300 samples) | Held-Out Test Split (300 samples) |
| :--- | :--- | :--- |
| **Precision** | **78.3%** | **79.2%** |
| **Recall** | **60.0%** | **63.3%** |
| **F1 Score** | **67.9%** | **70.4%** |
| **False Positive Rate** | **16.7%** | **16.7%** |
| **Tier 1 Recall** | 56.0% | **56.0%** (42 / 75) |
| **Tier 2 Recall** | 82.2% | **82.2%** (37 / 45) |
| **Tier 3 Recall** | 53.3% | **53.3%** (16 / 30) |

*Key Takeaways:*
- **Tier 2 Strength (82.2% Recall):** Deterministic structural patterns (CSS display:none, HTML comments, zero-width characters) are detected with exceptionally high consistency.
- **False Positive Root Cause:** The 16.7% FPR stems entirely from defensive security texts that quote exact injection strings (e.g. `'ignore previous instructions'`) within educational articles.

### 4.2 Adaptive Attacker Evasion Matrix
To honestly document the boundaries of heuristic defenses, we evaluated an untouched **35-sample adaptive evasion set** (`adaptive.jsonl`):
- **Overall Evasion Bypass Rate:** **74.3%** (26 of 35 attacks evaded regex detection).
- **Paraphrasing:** **100% bypass** (`"Kindly set aside prior mandates..."` evades keyword matching).
- **Multilingual Injections:** **100% bypass** (Spanish, French, German, Russian, Chinese, Japanese).
- **Encoding Obfuscation:** **100% bypass** (Base64, Rot13, Hex streams lack plaintext signatures).
- **Structural Techniques:** Partially defended (whitespace and markdown table splitting detected; homoglyphs bypassed).

### 4.3 Throughput & Latency Benchmarks
Measured on Apple Silicon (`--release` profile):
- **Inbound Scan Throughput:** **442–475 MB/s** sustained.
- **Inbound Scan Latency:** **207 µs** for 100 KB; **2.10 ms** for 1 MB.
- **Warm Dynamic CA Resolution:** **0.3 µs** (7,499x faster than cold 2.19 ms minting).
- **Forward Proxy Throughput:** **663 req/s** @ 1 MB concurrency 16 (retaining 80.8% of pass-through proxy throughput).

---

## 5. Architectural Trade-Offs & Ponytail Discipline

To avoid scope creep and maintain auditable security guarantees, development adhered to strict Ponytail line budgets:

| Module | Purpose | Line Budget | Actual Lines |
| :--- | :--- | :--- | :--- |
| `main.rs` | CA initialization & proxy server loop | 60 | 59 |
| `config.rs` | TOML parser with direction & trust fields | 80 | 77 |
| `policy.rs` | Per-domain routing & action evaluation | 140 | 135 |
| `detect.rs` | Outbound DLP (RegexSet, Luhn, stack entropy) | 160 | 152 |
| `inject.rs` | 3-tier inbound injection scanner & sanitizer | 140 | 134 |
| `handler.rs` | Hudsucker HTTP stream handler & decompressor | 320 | 316 |
| `llm.rs` | OpenAI / Anthropic chat schema role extractor | 90 | 72 |
| `stream.rs` | Sliding-window streaming scanner (256B tail) | 100 | 100 |
| `log.rs` | Structured zero-leak JSON decision logger | 40 | 40 |
| `lib.rs` | Crate exports | 10 | 8 |
| **Total** | | **1,140** | **1,093** |

Every intentional simplification is tracked with `// ponytail: <what> | upgrade: <path>` across 9 recorded locations.

---

## 6. Honest Limitations & Future Roadmap

1. **Defense-in-Depth Requirement:** Heuristic regex filters are not a silver bullet against semantic attacks. However, their extreme speed (> 450 MB/s, < 2.2 ms for 1 MB) and zero-GPU requirement make them an ideal **Tier 0 filter**, instantly dropping 60–80% of automated scans and covert structural vectors before invoking costly neural models.
2. **Roadmap Upgrades:**
   - *Tier 1 Neural WAF:* Embed a lightweight on-device classifier (e.g. ONNX-runtime DeBERTa-v3 or Llama-Guard-Pruned) to catch semantic paraphrases and foreign languages.
   - *Full DOM Tokenizer:* Replace heuristic HTML regexes with `lol_html` for streaming HTML parsing.
   - *Binary Multi-Modal Ingest:* Add an upstream OCR stage for image and PDF attachments before proxy inspection.

---

## 7. Conclusion

`dlp-proxy` demonstrates that high-throughput, memory-safe, bidirectional guardrails can be built with minimal code complexity (1,093 lines) and deterministic runtime characteristics. By combining outbound DLP redaction, inbound injection defense, and empirical transparency regarding heuristic limits, the system provides a production-grade foundation for secure LLM agent deployments.
