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

---

## In Progress
- Transitioning to **Phase 3: Wire inbound inspection into the proxy**.

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
