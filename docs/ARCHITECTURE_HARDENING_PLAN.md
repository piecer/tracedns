# Architecture hardening implementation

## Current partial-package scope — 2026-09-29

This package contains the previously accepted Stage 1–3 foundation, observation-authority fixes and finite capture/redaction/shared capture-decode components only. Product and test bytes remain the accepted working-tree bytes. The unaccepted Builder discovery-retirement delta, aggregate-v1 candidate, new publication HTTP/UI path, split publication/search/general activation and Stage 5 are excluded or remain incomplete. Preserve the existing reader path.

The stage approvals, pending checkpoints and continuation wording below are historical campaign records, not authority to resume excluded stages while preparing this partial package. Some original scratch evidence and the historical measurement lock are missing; complete historical preservation cannot be claimed. A fresh, exact-source partial-package verification and independent packaging review determine this package's readiness without retroactively converting any historical BLOCK to PASS. Keep the original resource limits and cumulative experiment budgets unchanged. Source packaging does not authorize commit, merge, push, deployment, service interruption or real-provider traffic.

## Authority and scope

The user approved the five sequential implementation stages from the architecture review of `687eae36b6bcb9f56a9601dc109a019e617c5306`. Continue to the next stage after the current stage's implementation, independent review, and verification gates pass; do not request repeated routine implementation approvals.

The frozen review and executable proofs are retained outside the repository at `/home/piecer/.hermes/reports/tracedns-architecture-review-687eae3/`. Preserve existing untracked files and old worktrees. No commits/pushes, service restarts, production configuration writes, or live provider traffic are authorized by this implementation request. Stage patches and verification receipts are retained independently. Operational deployment acceptance remains separate from isolated server/browser acceptance.

Maintain current API names/config keys, raw observation/history evidence, auth/RBAC/CSRF/audit, graph/map presentation, and existing capacity limits. Do not substitute unbounded synchronous fallbacks or silently truncate canonical evidence.

## Stage order and acceptance

### 1 — State and job lifecycle safety (implemented; independent reviews passed)

State owner contract:
- One application-owned state repository owns target admission generations, observation state, history commit fencing, and purge.
- Reads/aggregations clone under the existing state lock and traverse their private snapshot.
- Configuration definitions, provider settings and opaque target leases are captured together under the config lock. Admission validates the original lease; matching the same identity after delete/re-add never grants old work a new lease.
- Captured work cannot admit a removed target, mutate a delete/re-add generation, recreate a purged history file, or admit an addition for a revoked target.
- Configuration mutation invalidates affected target generations before releasing the config mutation lock. Lock order is configuration -> repository/target coordination -> observation state; network calls never execute under these locks.
- Purge (including final file removal) finishes inside the config mutation lock before a later re-add can become admissible. History replace and purge use the repository coordination lock and never reacquire config while holding it.
- Addition notification admission and dedupe consumption occur together under valid target leases. Already-admitted delivery may finish after subsequent revocation; no network lock is held. Revocation before admission produces neither delivery nor dedupe consumption. Stage 3 makes this admitted intent durable without changing this ordering contract.
- Serialization happens outside the state lock. The final history replace and deletion participate in the same target-generation check/commit boundary. Unique temporary files are discarded on stale publication or failure.
- Existing helper signatures remain compatible; production bootstrap explicitly passes the shared owner instead of relying on a global object registry.
- Main cleanup executes on exceptions as well as normal stop; handle SIGTERM with the same stop request as SIGINT without stopping unrelated services.

Job owner contract:
- Relationship processes use an explicit spawn context with per-task configuration.
- Terminal job state retains only the bounded public result, not the completed Future or exception traceback.
- Server shutdown permanently stops this service's admission before draining. An already-admitted handler cannot create another executor after shutdown.
- Server background close has one monotonic 3-second default budget covering drain, terminate, kill escalation and bounded reaping of service-owned workers. Reserve time for kill/reap rather than spending the whole budget waiting for graceful completion. Report survivor counts truthfully if the OS does not reap within the bound; never wait unboundedly or touch unrelated workers. A real subprocess regression uses a worker that ignores SIGTERM. Running cancellation remains truthful and distinct from queued cancellation.
- Preserve queue/owner limits, audit identity, result quality and retrieval semantics.

Blocking gates: event-controlled aggregation/purge, delete-before-scheduling, delete-before-replace, delete/re-add late success and error, stale captured configuration; real process inherited-lock test; production admission/completion payload retention; HTTP preparation versus shutdown; subprocess exit/owned-worker cleanup. Existing canonical tests/lint and isolated E2E must pass after integration and independent review.

Independent state review found one supported comma/newline configuration regression; persistent RED tests reproduced it and canonicalization before lease capture fixed it. Focused re-review passed all 47 persistent and 25 independent state gates. Jobs review passed, including real default-budget shutdown with no owned survivors. Final integrated canonical evidence and exact source snapshot are retained in the campaign scratch directory; no commit or operational deployment is implied.

### 2 — Configuration, target authority and scheduling (implemented; independent reviews passed)

- Unify config/settings/decoder candidate validation, revision checks, durable write failure propagation and runtime publication. Failed writes/compilation leave the prior committed definition usable. Decoder CRUD uses the same revision contract as configuration; update shipped UI/client docs and tests together.
- Force requests select configured target identities; execute authoritative configured type/decoder/options, not arbitrary request-owned definitions. Revalidate generation before publication.
- Maintain a separate periodic full-scan deadline; forced work never indefinitely replaces baseline monitoring or eligible removal reconciliation. Use injected monotonic time for fairness tests.
- A canonical active-target projection is shared by startup, configuration changes and reconciliation. Retired resolver/provider observations remain historical evidence, not active votes. Forced resolver subsets must not retire other configured providers.
- Gates: config/decoder legacy-v1 parity, failures and restart, stale concurrent writers, force definition substitution/removal, backlog fairness, provider replacement, ENS/SNS restart disappearance.

Stage 2 contract decisions (prerequisite review accepted; Stage 1 acceptance recorded):
- Use one serialized configuration commit service, preserving shared-dict identity. Prepare validation, decoder callables and local state transition before the atomic config replace. Failed validation/compilation/replace leaves the prior config, revision and callable usable. Persist the complete bootstrap configuration (including unknown public keys), excluding runtime/private keys; external file edits require restart.
- Configuration, settings and decoder CRUD share the existing global revision CAS on both route families. Authenticated mutations require an integer, non-boolean matching revision; decoder preview remains revision-free. Preserve existing direct helper test compatibility. POST name conflicts fail; PUT remains upsert; deletion of a decoder referenced by a configured target fails 400. Decoder collection writes through ordinary config receive the same compilation/validation. Startup invalid definitions are reported and not silently made callable.
- Publish registry maps consistently through synchronized reader snapshots/lookups; preserve imported mapping identities or migrate every reader. Pin the decoder view to a captured scan, and revoke affected target leases when decoder definitions change. Never run decoder code/network I/O under registry/config/state locks.
- Disk replace is the authoritative commit point, not a filesystem+RAM transaction. Post-commit optional adapter or history-cleanup failure must acknowledge the committed revision with a sanitized warning, not claim rollback. Failed cleanup blocks reuse of that target until cleanup succeeds; retry only obsolete history, never replacement state. Startup must exclude/purge orphaned deleted-target history before admitting new work, and fail closed on unresolved cleanup. Optional adapter application runs in writer order outside the config/state locks.
- Decoder UI mutations use the catalog's loaded revision, retain drafts on 409, and update from the committed response. Do not rebase another dirty form's revision or call loadCfg after decoder save. Update API/OpenAPI and the old decoder durability caveat together.
- Force admission selects authoritative configured definitions and captures their original leases. FIFO pending limits remain 64 globally, 4 per authenticated actor, and 64 targets/servers per request; running work is additional. Stale generation before dispatch fails the entire request with one terminal audit; never rebind old intent. DNS overrides are configured subsets and affect only DNS; ENS/SNS use their configured providers and work without DNS servers. Reject missing required providers rather than querying DNS addresses as chain endpoints.
- Snapshot reads do not consume queued work. Use a single non-preemptive runner with a separate injected-monotonic deadline: startup full first; next full due at last full completion plus current interval; due full before another force; force completion does not reset the deadline. Enqueue/config/stop wakes idle waiting. Relevant target/provider/decoder changes schedule full next, while interval changes recompute from the previous full completion. Coalesce missed periods, do not catch up in bursts.
- A config-stale full scan cannot advance the removal baseline/grace; rescan current configuration. Force may cancel grace for positive observations only. Generation validation and reconciliation-state admission are atomic relative to config publication, with external delivery outside locks. Shutdown fails pending force requests truthfully, without claiming running work cancelled. Preserve raw retired-provider history but exclude it from active voting.

Stage 2 independent reviews passed for configuration/decoder/bootstrap/UI and scheduler/state/force, including the signal correction. The OpenAPI mismatch for explicit empty DNS subsets was reproduced through authenticated ENS/SNS admission and corrected; DNS without a resolver still fails admission. Both original signal-stop schedules (state/config lock inversion and stop immediately before Condition.wait) now exit normally in persistent real-signal subprocess tests. The focused re-review passed 71 tests and independent admission/audit/FD/thread/handler/fairness probes against the real registry. Its source hashes match except for the separately verified schema/documentation/test correction. Parent integration probes passed, and final canonical/browser evidence and the accepted source snapshot are retained in the campaign directory. These gates do not claim native Windows/macOS validation, a wall-clock bound for blocked provider calls, exactly-once durable audit storage, production deployment, or live provider acceptance.

### 3 — Durable delivery (implemented and independently reviewed; final promotion gates required)

- Persist notification intent independently of its delivery attempt; acknowledgements are per destination. Retrying one failed destination must not resend a confirmed successful destination.
- Bound pending intent, work per pass and retries; persist backoff and terminal failure. Expose delivery health without secrets.
- Preserve the 24-hour removal grace and opt-in MISP removal. Expired removal intent cannot disappear before durable delivery admission.
- A process crash after remote success but before local acknowledgement may duplicate delivery unless the upstream supports idempotency; do not claim exactly-once remote delivery.
- Make MISP item acknowledgement truthful and use verified TLS for all shipped MISP search paths; private CA configuration is explicit rather than a silent bypass.
- Freeze the storage/intent admission and retry contract in this document before starting the stage's product changes. Gates include restart, same-observation retries, partial channels, history/intent storage failures, capacity, redaction and no-network fixtures.

The user explicitly approved the recommended observation-first policy: continue recording DNS observations when notification capacity is exhausted, preserve already-admitted pending work, and visibly account for new notifications that could not be admitted. Do not stop monitoring merely to preserve notification completeness, evict admitted work, claim lost notifications were delivered, or reinterpret capacity recovery as historical replay authorization. Durable local intent with retries applies to successfully admitted work, not every observed transition. If storage itself is unavailable, expose degraded/unknown accounting rather than promise durable failure counters on an unwritable medium. The prior design review's observation-backpressure proposal is superseded; its evidence remains historical. The recovery protocol and finite budgets must be reviewed against this approved behavior before the core delivery implementation starts.

Stage 3 independently executable transport correction: remove the explicit MISP search TLS bypass on every legacy/versioned alias, keep verified TLS as the default, and sanitize exception/response logging. Add actual handler/fake-transport regressions before product changes; do not send real provider requests. This correction does not depend on the outbox storage choice.

The adopted core protocol, budgets, mapping interfaces and 37-case acceptance matrix are in `docs/DELIVERY_CONTRACT.md`. One bounded SQLite ledger commits eligible intent, detector cursor and known-loss accounting before independent observation/history publication. There is no PREPARED token or delivery-finalization gate on continued observation. Successfully admitted alerts can outlive missing raw-history writes; no cross-file atomicity is claimed. Queue pressure counts missed destination-item obligations while consuming the cursor, never replaying them when capacity returns. Unwritable/uncertain storage exposes sticky incomplete accounting, not fictitious durable counters. Existing admitted work survives source deletion. Unclean recovery uses a visible conservative addition rebaseline and 24-hour hold on uncertain removal grace; clean restarts preserve timers. Storage/worker and adapter work use isolated ownership; core producer and health/UI integration follow the frozen interfaces. MISP-search correction has a scoped independent PASS; Stage 3 as a whole remains unaccepted.

Stage 3 closure checkpoint: core, adapters, health HTTP, delivery UI and private-CA settings are integrated. Independent reviews reproduced and then cleared F1–F5, K1–K4, form repair authorization, failed-thread-start cleanup, diagnostic redaction and truthful headline defects. On the exact 266-file repaired source, parent gates passed 1,098 tests, lint, 38 external authority/lifecycle probes, actual-main SIGTERM and 22 Chromium E2E cases. Independent actual-main browser runs verified both-channel blank-preserve saves versus explicit repair, ACK/history continuity through contention/loss, durable reopen without replay, CA form/handler checks, native deadlines/visibility and narrow/desktop reflow. Parent verified their source/artifact manifests and owned-process cleanup. These are scoped execution receipts, not counts to sum into another suite total.

All 37 delivery conditions now have concrete evidence. C05 additionally uses an independently reviewed exact-default first-binding-capacity test and a smaller-count isolation control; neither the 4,096-receipt nor 8-MiB production ceiling changed. Its recipes are promoted verbatim to `tests/test_delivery_capacity_contract.py`. The historical mathematical finding that 4,096 occupied receipts cannot fit this reservation policy remains true; that occupancy is not promised. Final acceptance requires fresh canonical test/lint/browser gates after this test/document promotion and an accepted snapshot/37-row receipt in the campaign directory. That receipt, not an earlier checkpoint, authorizes Stage 4.

Limitations remain explicit: native history navigation passed but BFCache restoration was not observed (`persisted=false` with unchanged no-store security headers); no real-provider TLS/private-CA handshake, native Windows process ownership, physical power-loss or production deployment is claimed. CA browser evidence covers configuration/validation/redaction, not a live remote handshake. Known-loss counters remain lower bounds after storage uncertainty. Component cost measurements do not constitute a universal latency SLO.

### 4 — Bounded publications and search (pending)

- Preserve request-side no-source-traversal for prepared views and bounded page/response output.
- One oversized raw-results projection must not disable unrelated IP/domain pages. Preserve canonical observations; expose stable capacity errors for unservable units rather than perpetual 202.
- A permanently rejected source generation is not rebuilt every interval; a changed generation can recover.
- Replace browser domain-by-domain history search with a bounded server search API, explicit cursor/coverage metadata and time/scan/response budgets. No unlimited Promise.all fan-out.
- Freeze exact publication/search budgets and response schemas before product changes. Gates: original oversized corpus, small requested pages, cold/last-good/recovery, Unicode byte limits, no-match operation counts, auth/REST and browser pagination.

### 5 — UI ownership and integration (pending)

- Centralize the actual auth/HTTP error contract and fetch+body elapsed deadline.
- Relationship run state owns job ID, busy lease, submit/poll/cancel and recoverable errors. Release UI resources once; retain bounded late-ack reconciliation so POST abort does not silently orphan an accepted job.
- Bind precheck results to an input signature and request generation; late responses cannot overwrite current validation or submit a different domain.
- Extract controllers along these tested ownership boundaries; keep existing graph/map/table renderers and prepared-section semantics.
- Gates use shipped HTML, auth and application scripts together: stalled submit/body, late ack, 503/invalid JSON/network polling, cancel 409, overlapping runs, A->B input/B->A response, clear/type/decoder changes, failure-preserved drafts.

## Verification and closure discipline

Each behavior follows RED -> GREEN -> refactor. Promote audit reproductions into persistent tests. No stage is complete on a subset of its gates. Reviewers are read-only and implementation workers use dedicated worktrees/file ownership. Integrate before running fresh canonical commands; do not claim tests from a changing tree.

Canonical gates: `make test`, `make lint`, `git diff --check`. The existing project venv and node_modules can be reused from isolated worktrees. Browser gate: existing Playwright E2E plus new fault/ordering cases; never reuse a production server on the fixture port. Maintain docs/API, generated OpenAPI parity where contracts change, and final executable coverage of every named finding.

Stage status must state implemented versus verified separately. Keep operational network, production deploy and long-duration load gaps explicit. No status updates erase the frozen audit evidence.
