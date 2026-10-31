# DHT signed-address tracking integration

Implementation contract and acceptance plan. User authorized edits and a local commit in this checkout; no push or production configuration changes. Execution receipts and final gate results are recorded separately from this design document.

## Scope

Integrate unsalted BEP44 signed DNS records as a first-class `DHT` target through Settings, config/REST validation, collector, monitor persistence/restart, managed-IP/relationship views and alert delivery. Reuse the proven read-only standalone protocol behavior, not its standalone SQLite/watch process. No malware execution, C2 connection, DHT publication, or automatic registration of the research target in a production config.

## Contract

- Target: `{name: <display label>, type: "DHT", dht_public_key: <exact 64 hex>, dht_options: <optional bounded lookup options>}`.
- Identity and runtime/history storage name include the public key, not only the display label. Key changes are a new target/incarnation.
- Exactly one logical provider `DHT` per target, independent of configured DNS servers or ENS/SNS provider settings.
- `dht_query.py`: `validate_dht_config(public_key, options=None)`, `fetch_dht_records(public_key, options=None, *, cancelled=None)`, `reconcile_dht(previous_state, observation, public_key)`.
- Lookup returns verified records and bounded coverage metadata; no records, errors and cancellation are not empty authoritative address sets.
- Monitor reconciliation runs inside target ownership/admission. Persist a bounded `meta.dht_state` high-water/conflict state and `meta.dht_observation` latest attempt/status. Retain last-confirmed snapshot on miss/stale/conflict/undecodable signed payload, including after three failures and restart.
- Snapshot includes `dht_public_key`, `dht_options`, selected verified `dht_record`; `values` preserves raw DNS value hex and `decoded_ips` feeds existing managed-IP paths.
- No same-sequence conflicting value can silently replace a confirmed record. A newer verified, decoded empty value can withdraw addresses.
- Public numeric IPv4 peers only; bounded DNS/UDP/work/records, only `find_node`/`get` and `ro=1`. No private-peer override in product. Validate configuration before write/job/network admission.
- Fixed small global lookup admission capacity, finite per-lookup budgets and cancellation checks; normal DNS/ENS/SNS behavior remains unchanged.
- Verify weak-key rejection and cancellation after verification/projection as well as the actual main SIGTERM latch. DHT anti-rollback checkpoints use the existing ledger independently of best-effort history writes; pending/uncertain evidence blocks automatic restart admission until deliberate operator recovery.
- UI displays full public key, read-only meaning, signed-record provenance and stale/error/coverage warnings rather than claiming current C2/infection or global latest truth.

## Verification gates

1. TDD for protocol authentication/decoding, input admission, fixed lookup bounds and cancellation.
2. Config/identity/provider/collector tests, restart and state-machine tests, managed IP/results/history/delivery integration.
3. Authenticated legacy and versioned API precheck/config/force/read tests; invalid requests cannot schedule/dial.
4. Real browser Settings registration/save/reload and DHT state display against an isolated test application. Keep synthetic evidence separate from live data.
5. Read-only live query through the application collector/engine with isolated storage, no production service/config or outgoing alerts.
6. Independent review; canonical `make test`, `make lint`, browser tests and diff checks on final source.
7. Explicit-path stage and local commit; verify commit contents and preserve pre-existing untracked files. No push.

## Initial checkout

- Branch: master; base commit 2fae16f.
- Tracked tree initially clean.
- Pre-existing caller-owned untracked paths: .hermes/, README.md.orig, check.md, diff.patch, logic.md, solana.py. Do not read, delete, stage or overwrite them.
- Root has no AGENTS.md/CLAUDE.md/.cursorrules. Canonical Python tests/lint are in Makefile; Playwright uses isolated port 18765 and must not reuse a production server.
