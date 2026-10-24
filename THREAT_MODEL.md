# Threat Model: Two-Way LLM-Agent Guardrail (`dlp-proxy`)

## 1. Overview & Position
`dlp-proxy` is a local, TLS-intercepting forward HTTP(S) proxy positioned between an autonomous LLM agent (or agent framework) and external networks / LLM inference APIs:

```
[ LLM Agent / Runtime ]
       ▲            │
Inbound│     Outbound
Content│            │DLP Scan
Scan   │            ▼
 ┌─────┴────────────┴─────┐
 │       dlp-proxy        │  <-- Local Host Boundary
 └─────┬────────────┬─────┘
       │            ▲
       ▼            │
 [ External Web / APIs / LLM Providers ]
```

The system enforces a dual-guardrail defense:
- **Inbound Guardrail (Injection Defense):** Inspects untrusted external content (web pages, tool outputs, external API responses) fetched by the agent to detect and mitigate indirect prompt injection before the content enters the agent's context window.
- **Outbound Guardrail (DLP Defense):** Inspects outgoing agent requests to prevent exfiltration of sensitive data (credentials, API keys, card numbers, personal data, and high-entropy secrets).

---

## 2. Attacker Capabilities & Assumptions
The attacker is assumed to:
1. **Control Untrusted Content:** Have full write access to external web pages, documents, tool outputs, search snippets, or API responses retrieved by the agent over HTTP/S.
2. **Craft Indirect Prompt Injections:** Inject malicious instructions designed to hijack the LLM's control flow, reassign roles, mimic system or chat framing markers, or execute hidden instructions.
3. **Attempt Data Exfiltration:** Embed outbound exfiltration channels (e.g., Markdown images, HTML image tags, webhook links, DNS prefetch links, URL query parameters) intended to coax the agent into leaking conversation context, system prompts, or local secrets.
4. **Employ Obfuscation:** Use CSS styling (`display:none`, `visibility:hidden`, zero font sizes), HTML comments, Unicode zero-width characters, bidirectional control characters, or base64 encoding to conceal instructions from human operators or naive scrapers while remaining visible to LLM tokenizers.

---

## 3. Attacker Goals
1. **Agent Hijack (Control Flow Compromise):** Override developer-specified system prompts, alter the agent's operating objective, force unauthorized tool invocations (e.g., executing malicious bash commands, sending arbitrary emails, altering database records).
2. **Data Exfiltration:** Exfiltrate confidential context, environment variables, credentials, or proprietary data retrieved from internal tools to an attacker-controlled endpoint.
3. **Security Control Bypass:** Circumvent outbound DLP filters or inbound filters via fragmentation, encoding, or structural obfuscation.

---

## 4. Defender Position & Invariants
`dlp-proxy` operates as a bump-in-the-wire network guardrail with strict invariants:

1. **Fail-Closed Enforcement:** Any inspection failure, decompression error, UTF-8 decode error, or request/response exceeding `max_body_bytes` results in a fail-closed block (HTTP 403 or truncated/blocked body).
2. **Log Decisions, Not Data:** The proxy never logs sensitive payload tokens, matched text, prompt bodies, or user secrets. Log entries record only timestamp, host, path, action, rule IDs, and direction (`in` vs `out`).
3. **Upstream TLS Integrity:** Upstream TLS certificates are strictly verified using standard WebPKI roots (`webpki-roots` / `rustls`). The proxy never disables upstream certificate verification.
4. **Linear-Time Matching:** All regular expression matching is powered by Rust's `regex` engine (finite automata guaranteeing $O(N)$ execution time with respect to input length), eliminating Regular Expression Denial of Service (ReDoS).
5. **Two-Way Defense-in-Depth:** If an indirect injection evades the inbound detector, the outbound DLP layer acts as a backstop preventing exfiltration of credentials or sensitive data.

---

## 5. Explicit Out-of-Scope Items
The following threats and operational models are explicitly outside the scope of `dlp-proxy`:

1. **Non-HTTP Communication Channels:** Traffic traveling over non-HTTP(S) transports (raw TCP/UDP sockets, DNS tunnels, SSH, WebSockets not inspected by HTTP handlers, local Unix domain sockets, shared memory, filesystem IPC).
2. **Model-Internal Defenses:** Token-level attention manipulation, model weights, latent space steering, activation monitors, or internal fine-tuning defenses.
3. **Air-Gapped / Network-Bypassing Attacks:** Attacks where the agent executes untrusted code locally that performs malicious filesystem or OS operations without initiating external network requests.
4. **End-to-End Encrypted Tunnels Within HTTP:** Payloads transported inside opaque application-layer encryption (e.g., encrypted payloads inside HTTPS where the proxy lacks the private keys or pre-shared keys).
5. **Zero-Overlap Semantic Paraphrases:** Heuristic and regex detection cannot guarantee 100% recall against novel, highly abstract paraphrasing that shares no structural, lexical, or syntactic markers with known injection techniques. Detection limits and adaptive evasion rates are formally documented in `LIMITATIONS.md`.
