# Progress Tracking: Two-Way LLM-Agent Guardrail

## Completed

### Phase 0: Threat Model & Baseline
- **P0.1**: Documented threat model in `THREAT_MODEL.md` covering attacker capabilities, attacker goals, defender position, and explicit out-of-scope boundaries.
- **P0.2**: Established baseline measurements in `bench/BASELINE.md` for unit/integration tests (`cargo test`), detection precision/recall (`cargo run --example evaluate`), certificate authority caching latency, and forward proxy throughput.
- **P0.3**: Initialized `PROGRESS.md` with structured sections for ongoing phase tracking.

### Phase 1: Config & Policy for Inbound Inspection
- **P1.1**: Extended `rules.toml` schema (`config.rs`) with backward-compatible `direction`, `trust`, and `inbound_action` fields.
- **P1.2**: Updated `policy.rs` with `Direction`, `Trust`, `InboundAction`, and `PolicyDecision` returning per-domain settings while maintaining `DomainAction` equality.
- **P1.3**: Added table-driven tests in `tests/detect.rs` covering TOML deserialization defaults, direction predicates, and policy lookup field combinations.

### Phase 2: Inbound Injection Detector (`inject.rs`)
- **P2.1**: Implemented `src/inject.rs` with 3-tier detection (`scan(text, trust)`) using `RegexSet` pre-filtering and position extraction. Reused zero-alloc Shannon entropy from `detect.rs`.
- **P2.2**: Implemented `sanitize(text, hits)` for back-to-front replacement of matched spans with `[INJECTION BLOCKED]` and stripping of zero-width and bidi control characters.
- **P2.3**: Added table-driven tests in `tests/inject.rs` with 3 positive and 3 negative test cases per rule, including adversarial look-alikes and security discussions.
- **P2.4**: Added log regression test in `tests/inject.rs` verifying matched tokens and injection text are never emitted in structured decision logs.

### Phase 3: Wire Inbound Inspection into the Proxy
- **P3.1**: Implemented `handle_response` in `src/handler.rs` honoring domain `direction`, `trust`, and `inbound_action`. Refactored shared body collection and size-cap checking with `collect_body_with_cap`.
- **P3.2**: Enforced content-type gating for `text/*`, `application/json`, `application/xml`, and `application/xhtml+xml`, skipping unsupported binary types with explicit audit logging.
- **P3.3**: Supported all inbound actions: `log` (pass through), `sanitize` (rewriting body with updated `Content-Length` and dropping stale `Content-Encoding`/`ETag`), and `block` (fail-closed 403 Forbidden).
- **P3.4**: Extended `src/log.rs` with `direction` field (`"in"`/`"out"`), omitting the field on outbound logs for strict backward compatibility.
- **P3.5**: Created integration tests in `tests/inbound_proxy.rs` verifying all three inbound actions against a local mock upstream, including gzip decompression, benign pass-through, and fail-closed oversized body protection.

### Phase 4: LLM-API Awareness (`llm.rs`)
- **P4.1**: Implemented `src/llm.rs` with `parse_chat_messages(json_str)` extracting `(role, text, is_tool_result)` for OpenAI and Anthropic message formats, with graceful raw-body fallback on non-chat or malformed JSON.
- **P4.2**: Wired per-role inspection in `src/handler.rs`: DLP rules inspect all roles, while inbound injection scanner specifically inspects tool-result content inside outbound requests.
- **P4.3**: Structured audit logging records the triggered role name (`block:user`, `block:tool`, `redact:assistant`), never logging payload content.
- **P4.4**: Created test suite in `tests/llm.rs` verifying OpenAI/Anthropic fixtures, tool-result injection blocking, user credit card DLP enforcement, and malformed JSON fallback.

### Phase 5: Streaming Inspection (`stream.rs`)
- **P5.1**: Implemented `src/stream.rs` (100 lines) with `StreamScanner`, sliding-window tail buffer (`MAX_MATCH_LEN = 256`), rolling size-cap enforcement, and multi-byte UTF-8 boundary handling.
- **P5.2**: Created property test suite `tests/stream.rs` verifying rolling size cap abort, multi-byte UTF-8 split assembly, invalid UTF-8 fail-closed, and exhaustive byte-by-byte boundary split property tests across all 13 DLP and injection rules.
- **P5.3**: Benchmarked streaming vs buffered inspection in `bench/stream_bench.rs` and documented results in `bench/STREAMING.md`: in-process streaming microbenchmark processes first chunk in 9.3 µs (16 KB) to 36.1 µs (1 MB) vs full-body scan 206 µs (16 KB) to 2,177 µs (1 MB) (12.7x–60.4x initial latency reduction) while sustaining 395–475 MB/s scanning throughput in release profile. In block/sanitize modes, full-body hold-back is enforced.

---

### Phase 6: Evaluation Harness & Adversarial Validation
- **P6.1**: Built `bench/corpus/injection/` JSONL datasets with dev (300) and held-out test (300) splits (50% attack, 50% benign) partitioned prior to heuristic evaluation.
- **P6.2**: Implemented `scripts/convert_corpus.py` supporting conversion of external benchmark formats (BIPIA, InjecAgent) to standard JSONL schema and generating balanced evaluation splits.
- **P6.3**: Created `bench/eval_injection.rs` calculating per-tier and overall precision (79.2%), recall (63.3%), F1 (70.4%), and FPR (16.7%), writing structured Markdown tables to `bench/INJECTION_RESULTS.md`.
- **P6.4**: Constructed adaptive-attacker dataset `bench/corpus/injection/adaptive.jsonl` (35 samples across paraphrasing, multilingual prompts, encodings, homoglyphs, and tag splitting); reported honest 74.3% evasion bypass rate without post-hoc tuning.
- **P6.5**: Benchmarked inbound scan throughput and latency: sustained ~470 MB/s throughput (207 µs for 100 KB, 2.10 ms for 1 MB) with deterministic linear-time overhead.

---

### Phase 7: Documentation & Write-up
- **P7.1**: Updated `README.md` with full ASCII bidirectional architecture diagram, `rules.toml` configuration guide, Ponytail code line budget table (1,103 lines), shortcut ledger items, empirical evaluation summaries, and 5 high-impact resume bullets.
- **P7.2**: Created `LIMITATIONS.md` providing in-depth analysis of heuristic regex boundaries (paraphrasing, multilingual, encodings), non-HTTP channels, binary steganography, and the streaming forwarding trade-off.
- **P7.3**: Authored `WRITEUP.md` executive engineering write-up synthesizing threat model, design, streaming optimizations, held-out evaluation results, and defense-in-depth recommendations.

---

### Phase 8: Hardening & Domain Routing Extensions
- **P8.3**: Implemented zero-allocation wildcard domain matching (`*.example.com`) in `src/policy.rs` (145 lines, budget 150) with exact-match precedence, apex domain support, and suffix collision prevention; added table-driven test suite in `tests/detect.rs`.

---

## Skipped / Future Roadmap
- **P6.6: End-to-End Agent Evaluation**: Skipped / Optional (verified at unit, integration proxy, and 600-sample corpus evaluation layers; full autonomous agent harness omitted to prioritize core deterministic guarantees).
- **P8.1: On-Device ML Classifier**: Skipped / Stretch (planned zero-GPU heuristic defense intentionally prioritized linear-time DFA scanning; neural classification deferred to downstream semantic judge).
- **P8.2: Config Hot-Reloading**: Skipped / Stretch (`notify` crate file watcher deferred; configuration loaded cleanly on startup).

---

## Open Questions
- *None currently.* All interfaces and requirements are well-defined.

---

## Decisions
- **Fail-Closed by Default:** All decode, parse, size limit, and inspection failures will terminate with a block action (HTTP 403 for requests; blocked/empty response for inbound content).
- **Zero Sensitive Data in Logs:** Structured JSON logs only record metadata (`host`, `path`, `action`, `rules`, `direction`), never matched payload text or tokens.
- **Backward Compatibility:** All existing `rules.toml` files and existing outbound tests must continue to pass unchanged. New config fields default to existing outbound-only behavior (`direction = "out"`, `trust = "trusted"`, `inbound_action = "log"`).
- **Linear-Time Matching:** Only the `regex` crate DFA/NFA linear engines will be used for detection (no backtracking, ReDoS-safe).
- **Ponytail Discipline:** Adhere to line budgets and record all shortcuts with upgrade paths in code and the README ledger.
- **Streaming Forwarding Trade-off:** Inbound streaming inspection enables real-time forwarding under `inbound_action = "log"` (reducing in-process initial chunk latency to 9–36 µs); `block` and `sanitize` require hold-back buffering up to `size_cap` because dispatched HTTP bytes cannot be recalled or sanitized once sent.
