# Progress Tracking: Two-Way LLM-Agent Guardrail

## Completed

### Phase 0: Threat Model & Baseline
- **P0.1**: Documented threat model in `THREAT_MODEL.md` covering attacker capabilities, attacker goals, defender position, and explicit out-of-scope boundaries.
- **P0.2**: Established baseline measurements in `bench/BASELINE.md` for unit/integration tests (`cargo test`), detection precision/recall (`cargo run --example evaluate`), certificate authority caching latency, and forward proxy throughput.
- **P0.3**: Initialized `PROGRESS.md` with structured sections for ongoing phase tracking.

---

## In Progress
- Transitioning to **Phase 1: Config and policy for inbound inspection**.

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
