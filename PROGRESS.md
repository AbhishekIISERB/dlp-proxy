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

---

## In Progress
- Transitioning to **Phase 5: Streaming inspection (`stream.rs`)**.

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
