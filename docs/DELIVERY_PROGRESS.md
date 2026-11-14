# Cached delivery progress, version 1

Both authenticated admin/operator aliases, `/delivery-health` and
`/api/v1/delivery-health`, preserve their exact legacy key sets when the query
selector is absent. `?progress=1` selects the closed version-1 extension. Empty,
invalid or duplicate `progress` selectors return 400. Both branches remain at
most 4096 UTF-8 bytes. The shared schemas in `http_api/delivery_health.py` are
also the source of the generated OpenAPI document. Unknown/missing extended
fields are invalid; legacy internal-field redaction is unchanged.

The extension adds exactly `progress_version`, `counts_age_seconds`, `progress`,
`recovery`, and `lookup`. All counters/timestamps/ages are integers in
0..9223372036854775807; unknown optional values are explicit null. The browser
accepts that wire range but labels values beyond exact JavaScript integer/date
precision unavailable rather than displaying rounded counts.

* `progress`: `state`, `operation`, `channel`, `last_progress_at`,
  `last_progress_age_seconds`, `in_flight_age_seconds`, `stall_after_seconds`,
  and `channels`. State is not_started/idle/active/stalled/recovering/failed/
  stopping/stopped. Operation is null or recover_storage/seal_batches/claim/
  provider_step/finish_step/observation_hook/sightings_step. Channel is null,
  teams or misp. Each channel has state, last_attempt_at and
  in_flight_age_seconds; states are disabled/idle/queued/retry_wait/blocked/
  active/stalled/unavailable.
* `recovery`: state (ready/recovering/backoff/uncertain/stopped/failed),
  nullable retry_in_seconds, targets_rebaselining, and absence_state
  (ready/awaiting_full/unknown). Storage dispatch recovery is separate from
  per-target addition rebase and the complete-full absence gate.
* `lookup`: nullable last_attempt_at and last_success_at, in_flight,
  failed_targets, uncertain_targets, coverage (complete/partial/unknown),
  and counts_stale. Success means an accepted target observation, **not**
  universal source coverage. Failed or partial evidence never authorizes
  absence. Generation retirement fences late results. DHT verified-positive
  evidence is not global network coverage.

## What progress means

The sole delivery worker publishes at actual operation boundaries. At 60
monotonic seconds without boundary progress an active operation is stalled;
59.999 seconds is not. An unexpectedly frozen ordinary idle loop also stalls.
Deliberate recovery waits remain recovering. There is no heartbeat that marks a
blocked callback healthy, no automatic restart/replacement, and no reclamation
of a live callback's claim. An unexpected failure is terminal for that worker.
A false stop remains stopping with its advancing in-flight age and retained
ownership; only successful quiescence is stopped. `worker_running` retains its
legacy thread/pass-liveness meaning and is not proof of progress.

A stalled destination makes another queued enabled destination unavailable
because there is only one dispatcher. Blocked obligations retain their blocked
state even when disabled. Provider return, attempted activity and durable ACK
are different facts. ACK totals and destination last-success timestamps still
come exclusively from durable finish, including an ACK before a blocked local
observation hook. A stalled classification describes lack of observed boundary
progress, not proof of thread death or delivery failure.

## Cache-only reads and time

The runtime joins producer-published bounded memory snapshots. Health reads do
not access SQLite, capture/traverse source state, retry recovery, validate
adapters, or acquire config/repository/store/pass/lookup/audit locks. Security
request authentication retains its existing independent behavior.

Counts, oldest receipt identity, wall/monotonic anchors and channel queue
summaries publish together. All status-only updates retain that sample. Oldest
outstanding age advances with monotonic elapsed time even while SQL and callback
progress are frozen. Refreshing the same oldest receipt cannot make it younger
when wall time rolls backward. Epoch-zero receipt timestamps are valid; an empty
queue yields null. A cold owner establishes new process-local anchors.
`counts_age_seconds` is the age of the SQL count sample, not a promise that the
queue is current. Failed refresh leaves counts stale. Invalid/nonfinite clock
inputs cannot become unbounded JSON values.

## UI and operational limits

The compact console keeps backend/worker state and loss/uncertainty in the basic
health view. **Delivery details** lazily mounts progress, accounting and recovery
evidence; closing it does not declare recovery or erase historical losses.
Manual diagnostics stay in a separate initially closed operations disclosure.
An ordinary health read failure retains the last accepted snapshot as stale;
authentication/audit warnings remain independently owned. See
[console views](VIEW_PRESENTATION.md) for scope and lifecycle details.

The existing panel requests the extension, renders fixed labels through
textContent and retains 15-second polling pacing, 10-second stream timeout,
single flight, visibility/page lifecycle, authentication, no-store and bounded
4096-byte streaming. An exact legacy response is supported with the explicit
label “progress unavailable on this server.” Unknown progress is not inferred
healthy from thread liveness. Observation policy is **continue**, not an assertion
that every source is currently progressing.

Diagnostics version 1 remains the same closed schema; its records are historical,
not the live stall oracle. Isolated Chromium tests use the production handler,
authentication, runtime, SQLite and worker with synthetic transports and
fixture-only clock controls. They are not deployed-service or physical
screen-reader validation. No production configuration or service restart is
required for these tests.
