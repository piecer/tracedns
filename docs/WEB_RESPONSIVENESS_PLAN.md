# Web responsiveness implementation

Base: `0368dd23ffd09544ee989e6472348fa2a2c5b99b`. User approved sequential implementation; no production deployment/restart or commits requested. Existing user-owned untracked files are excluded.

## Contracts and stages

1. **Request recovery and lock isolation** (verified)
   - Cached response serialization/socket writes never hold a shared cache lock.
   - UI reads have a deadline covering authentication, transport and body, release ownership on failure, and can recover without reloading.
   - Transient authentication bootstrap failure is retryable; unauthorized sessions remain fail-closed; mutations are never automatically replayed.
   - Existing data remains visible with truthful failure/staleness state.
2. **Read/enrichment separation** (verified)
   - Browser reads opt into cache-first background enrichment without waiting for external lookup or persistence.
   - One bounded service owns queued/running enrichment, deduplicates IP work, bounds retained reports and retries, and has explicit shutdown ownership.
   - Existing synchronous API behavior remains compatible; authorization still gates external lookup.
3. **Background read snapshots** (verified)
   - Browser reads consume versioned prepared data. Cold state is explicit; last good stale data is labelled, not presented as current.
   - One coalesced builder snapshots source state consistently, builds outside request/monitor locks, and publishes monotonically.
   - Full-history counting/provenance and deletion/retention semantics remain unchanged. No raw evidence is truncated to accelerate UI reads.
   - Snapshot retention and server worker lifetimes are bounded. Stop admission before shutdown; do not pretend running work has ended.
4. **Bounded presentation and conditional reads** (verified in isolated integration)
   - Large tables are paginated, with counts/navigation preserving access to every entry.
   - Identical data preserves existing rows; timestamp-only changes update cells rather than rebuilding unrelated content.
   - Active-visible-view polling, request-generation checks, and version/conditional-read semantics prevent stale renders and redundant work.
   - Browser fault/recovery tests exercise the actual shipped scripts and real HTTP server where feasible.

## Verification gates

Each stage requires RED-before-GREEN regression tests, focused verification and independent review. Canonical final gates: `make test`, `make lint`, JavaScript syntax, `git diff --check`, isolated browser E2E. A separate production deployment is unavailable: local fixture/TCP tests are not proof of production remediation.

Required scenarios: slow cached writer versus unrelated request; pending headers/body/auth; transient auth failure then healthy transport; delayed stale response; slow VT without blocking base read; bounded queue/deduplication; cold snapshot; changed/deleted/retained history during build; bounded rebuild work and retention; repeated browser refresh/render lifecycle; role-safe cache/conditional responses.

Implementation file ownership: parent owns backend and integration; isolated stage-1 frontend worker owns auth/request scripts and their tests. Future stages begin only after the preceding stage's acceptance gate. No concurrent owner edits to the same file.

## Evidence

Stage 1: cached slow-writer test was RED on the original handler and GREEN after releasing the cache lock before sending. Authentication/refresh recovery has 16 executable Node scenarios including real partial-body socket cancellation. Independent backend and frontend reviews passed; two startup-retry findings were reproduced, persisted as regression tests and repaired. Integrated canonical tests: 462 passed; lint and existing browser E2E (2 tests) passed. No production deployment was attempted.

Stage 2 contract: `vt_mode=background` is an opt-in on existing `/ips` and `/domain-analysis` routes, with default synchronous behavior unchanged. `include_vt=0` never enqueues. Published VT metadata is separate from the disk-backed lookup cache. Server binding starts services; shutdown stops admission and close shares a one-second service drain budget. Running non-cooperative work remains reported until actual return.

Stage 2 evidence: independent re-review passed after persisting/fixing clean-VT completion invalidation and canonical IPv6 lookup-key regressions. Canonical tests: 497 passed; Node recovery checks: 18 passed; lint passed. Predecessor integration browser E2E: 2 passed. Source/display address spelling remains unchanged.

Stage 3 contract: `read_mode=background` negotiates prepared `/results`, `/ips`, and `/domain-analysis` reads. No source snapshot, history traversal or external lookup runs in these read requests. Cold/unavailable publication returns 202 with `snapshot.ready=false`, never an empty-success table. A single server-owned builder checks observation/config versions once per second, coalesces work and retains one last-good publication up to 32 MiB encoded. Configuration mutations hard-invalidate before publication and after state purge so a delayed old build cannot restore removed data after acknowledgement. Source detection is periodic, not a guarantee that the snapshot matches the instant of an HTTP request. Original source state/history retention is unchanged. Browser activation and bounded/conditional transport are stage 4.

Stage 3 evidence: canonical tests 544 passed and lint passed. Independent review passed, including the actual config-replacement-before-purge race and delayed obsolete build: deleted domains could not be republished after mutation acknowledgement. Real HTTP cold/stale responses passed on both route families.

Stage 4 backend evidence (before browser integration): canonical tests 551 passed and lint passed. Independent authenticated HTTP probes followed next offsets through 205 result domains, 210 IPs, and 4,201 domain display units per route family, with exact coverage. Sanitized bodies remained at most 1 MiB (largest probe 1,043,031 bytes) with exact Content-Length. Byte admission preceded enrichment; conditional reads retained auth/RBAC/CSRF and redaction-sensitive versions. Irreducible entries returned 422 without queue admission. The new real-server browser regression was RED before frontend integration (250 mounted Status rows exceeded the 200-row ceiling).

Stage 4 frontend contract: all four pollers use prepared reads and retain validators only for the exact mounted query after a successful render. Navigation follows server-issued offsets, including byte-shortened pages. Primary tables mount at most 200 rows; heavy value cells have bounded previews with explicit plaintext expansion. Timestamp-only updates retain row/cell identity. Domain statistics are explicitly page-only; deletion eligibility still uses full-domain lifecycle facts. Snapshot time, periodic freshness, pending VT and backend totals remain visible. Cold/error/422 responses preserve the last good display; synchronous raw downloads are explicit and labelled, never automatic fallback. The Valid IP recent-seconds control is included in the request and resets pagination when changed.

Stage 4 frontend evidence: integrated canonical suite passed 552 tests; three Playwright E2E cases passed, including shipped browser scripts against a disposable real authenticated server with synthetic source data. This is not deployment acceptance or live DNS/VT evidence. The recent-seconds omission was reproduced and repaired. The first independent frontend review then reproduced a late-render failure leaving new domain statistics beside an old primary table. A persisted RED test covers late primary/summary failures, retained filter/selection/node identities, unchanged responses and subsequent healthy recovery. Rendering prepares all domain panels before committing. Chromium fixtures: 14 passed; request recovery: 18 passed. Independent re-review passed, including fresh producer-to-browser parity for all four views and extended late-summary/timestamp-only fault injection. A scratch-only negative control removing stats deferral reproduced three failures.

E2E log investigation: two instrumented runs passed all three tests. All six captured generic request errors were disconnected socket writes (`BrokenPipeError`) after headers had been sent; no 503 attempt or browser-observed 5xx occurred. Existing settings/decoder handlers can attempt a second error response after a failed 200 socket write, making internal status logs misleading. This logging/exception-handling cleanup is a separate follow-up, not evidence of service unavailability or a repaired production incident.

Deployment boundary: implementation and isolated integration are complete; no commit, production restart or deployment was performed. The separately operated environment still needs the matching backend/HTML/JS revision deployed together and its real workload measured. Original operational root cause is not established by these synthetic-source regressions.
