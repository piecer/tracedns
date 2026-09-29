# Stage 3 — observation-first delivery contract

**Adopted Stage-3 implementation contract; implementation acceptance remains pending.** Source authority: the 195-file accepted Stage-2 snapshot at `/home/piecer/.hermes/cache/scratch/tracedns-hardening-tnkc2rhx/stage2-accepted`. Policy authority: live `docs/ARCHITECTURE_HARDENING_PLAN.md:58–69`, particularly the explicitly approved paragraph at line 67. The earlier `stage3-contract-review.md` is historical; its refusal of observations and single-PREPARED finalization freeze are NOT carried forward.

## 1. Decision

Use **one bounded, application-owned SQLite delivery ledger**, next to—not instead of—the existing domain history JSON. Its transaction commits notification eligibility, detector cursors, loss counters and per-destination work together. **Commit delivery admission before publishing the corresponding new observation to the shared dictionaries or attempting its history write.** Admission describes a fresh, lease-valid collected observation; it is NOT conditional on successful persistence of the complete canonical history document.

This last definition is essential and explicit: an admitted alert can survive a crash even when that observation's full JSON history did not reach disk. Its bounded IP/label/action/time payload remains valid evidence of what the collector obtained, but the API must not claim that its raw history was saved. This is a deliberately smaller contract than an atomic history-plus-delivery transaction. We do not pretend two files can commit atomically.

When delivery admission is unavailable or over budget, still publish and attempt to persist the observation. Consume the transition in the notification detector and count unadmitted destination obligations where writable; otherwise expose lower-bound/unknown accounting. Existing admitted work is never evicted. Recovery of capacity is **not** authorization to generate notifications from missed transitions or historical events.

There is **no PREPARED state, history commit token, history finalization gate, or delivery-dependent history purge gate**. Admission is one SQLite COMMIT. This eliminates the token-overwrite/deletion problem rather than solving it with a growing token list or a second journal. Durable admission/attempt tokens live only in the ledger and survive target deletion. A bounded IP detector cursor is necessary to prevent duplicate admission when the ledger committed but history still contains older data.

Non-goals: canonical history migration, a broker, multiple delivery workers, multi-host leases, manual replay/rebind/cancel endpoints, exactly-once remote delivery, a new monitoring platform, or the parent's independently owned MISP HTTP/TLS patch.

## 2. What the accepted application actually does

All locations below are in the accepted snapshot, not the concurrently changing root checkout.

| Path | Actual behavior and integration consequence |
|---|---|
| `monitor/engine.py:191–200,277–295,317–375,377–413` | History is persisted per resolver, including INIT and failure-drop, before domain-level union extraction. Returns from `persist_owned` are ignored. Refactor the **whole domain observation publication**, not just the alert call, so a private candidate and its before/after managed projection exist before writes. Preserve every event, failure-drop threshold, decoder provenance and lifecycle rule. |
| `monitor/engine.py:485–543` | Additions accumulate across domains; grace suppression and process-local dedupe precede one Teams/MISP wrapper call. Replace production dedupe/admission with ledger ownership, while retaining one ordinary small-cycle Teams batch. |
| `monitor/engine.py:545–582` | Full projection uses all configured providers, even on a forced resolver subset. Reconciliation already runs through config lock and repository generation fencing. A force only cancels grace from `CycleResult.positive`. These authority rules remain. |
| `monitor/repository.py:39–68,70–130,132–184` | Startup purges orphans; configure revokes original object leases and purges obsolete files; cleanup failure blocks reuse. `commit_history` fences replace but does not fsync its directory. The current `TargetLease` is an in-process object identity, NOT a restart-stable token. |
| `history_manager.py:43–87,90–138`; `monitor/runtime_state.py:76–93` | Loader, writer and clone helper keep only `meta/events/current`, with 1,000 events. An invented `_delivery_commit` would currently be discarded in several places. Selected protocol adds no such field, so these public and canonical shapes remain unchanged. |
| `monitor/removal_grace.py:73–83,96–137,167–184` | Expiry pops grace before external alerting; persistence errors are swallowed. Replace production mutation with a transaction that retires grace only with admitted work **or explicit missed accounting**. Keep the facade for compatibility. |
| `dns_monitor.py:265–279,281–305,332–357` | Alert startup falls back to INI based on adapter readiness; history restores current; repository may immediately purge; full baseline is memory-only. Open the ledger and seed its baseline before the first query. INI fallback must instead depend on configuration provenance, not readiness. |
| `monitor/config_service.py:223–283` | Config replacement is authoritative; repository revocation runs before config lock release; optional runtime settings apply outside it. A delivery apply failure cannot roll back that committed config or silently use an older destination. |
| `monitor/targets.py:6–15`; `monitor/state_utils.py:9–58` | Configured provider projection excludes retired votes while retaining raw evidence. Domain addition handling has the existing A/TXT/ENS/SNS interpretation; do not broaden record-type semantics in this stage. |
| `alerts.py:178–191,280–285,289–354` | Teams returns a Boolean, wrappers throw it away; output lists only the first 60 entries; MISP uses mutable module globals. Introduce immutable bound adapters and typed results, not another unchecked Boolean wrapper. |
| `mispupdate_code.py:238–307,313–389` | Add/delete response envelopes are not validated; failed adds enter the local existing set; malformed event shapes can masquerade as absence. Attribute-level acknowledgement requires replacement of that behavior. |
| `mispupdate_code.py:89–175,195–225,291–303` | Daily sightings are a separate best-effort side effect. Preserve observation-triggered behavior separately; never generate it on outbox retry, and never include it in attribute delivery ACK. |

Existing acceptance tests to preserve/extend include `test_alert_batching.py:18–64`, `test_ip_removal_grace.py:17–117`, `test_stage2_projection.py:9–37`, `test_stage2_reconciliation.py:10–74`, `test_monitor_state_ownership.py`, `test_monitor_deletion_race.py`, and Stage-2 bootstrap/config/scheduler suites. The 684-test/lint/5-E2E Stage-2 receipt was supplied by the parent; this review does not claim to rerun it.

## 3. Ledger scope and finite budgets

### Storage and owner

Path: `<history_dir>/delivery.sqlite` (not `.json`, so the history loader cannot mistake it for a domain). Use Python's existing stdlib `sqlite3`; **do not share the authentication/audit database or its connection**. One `DeliveryStore` serializes all access to its own connection; no cursor escapes its lock, including rollback/close. Health reads use an immutable cached projection, not concurrent reads through that connection.

Use `journal_mode=DELETE`, `synchronous=FULL`, `foreign_keys=ON`, `temp_store=MEMORY`, 4-KiB pages, `max_page_count=16384`, `busy_timeout=50` milliseconds and a 2-MiB page-cache target. No WAL or long-lived reader transaction. SQLite handles only local delivery metadata, not DNS raw results or history events. Owner-only directory/database/journal permissions; no secrets in rows. Use an application owner lock for this ledger; never run two independent dispatchers against it. Unsupported/read-only/open-failed ledger means delivery-degraded observation mode, not observer shutdown.

Create a constant-size owner-only `delivery.initialized` sentinel containing schema/epoch identity after initial schema commit, with file and directory fsync. Its purpose is to distinguish a missing established ledger from ordinary first-feature setup. A present sentinel plus missing/corrupt DB is an error, never empty recreation. A crash between DB creation and sentinel creation can finish the sentinel from the valid DB epoch. Deletion of both files or rollback of the entire storage volume cannot be distinguished from an old installation without an external authority; do not promise detection of that event.

### Hard logical limits (defaults, not open decisions)

| Resource | Limit / treatment |
|---|---|
| Outstanding destination-item obligations | **4,096**, including unsealed, pending, in-flight, retry and blocked. A two-channel IP consumes two slots. No eviction of any admitted nonterminal obligation. |
| Outstanding payload/progress/rendered batch bytes | **8 MiB** measured encoded bytes. Reserve rendered-body space at admission; a later seal must not discover it cannot retain an already admitted payload. Metadata is separately bounded below. |
| One domain admission | At most **256 eligible IP tuples**, **64 KiB** compact UTF-8 candidate payload, **1,024 UTF-8 bytes per label**. Oversized unit loses that entire eligible notification unit with exact candidate/destination count, not a silently admitted prefix. Canonical DNS/history evidence is not truncated. |
| Notification detector cursors | **4,096 targets**, **16,384 target/IP memberships**, **4 MiB** serialized projections, at most **4,096 IPs for one target**. Only managed-IP sets and compact authority/projection identifiers; no raw provider snapshots. |
| Last completed full baseline | **8,192 distinct IPs**, **2 MiB**, including labels. Stored independently of domain cursor movement. |
| Pending removal grace | **8,192 IPs**, **2 MiB**, including original `missing_since`, labels and optional conservative recovery hold. |
| Recent 60-second duplicate suppression | **4,096 keys**, **1 MiB**. Expire before evaluating capacity. Suppression is not an ACK and never extends a retry's life. |
| Terminal diagnostics | At most **256** sanitized summaries, at most **7 days**, at most **128 KiB**; discard payloads only after receipts terminal. Fixed cumulative counters survive summary pruning. |
| Control / counters | **64 KiB** logical reserve, constant number of rows and closed reason/channel enums. Queue fullness cannot consume this reserve. This is NOT a guarantee of disk space for a later filesystem write. |
| SQLite physical allocation | **64 MiB main DB** page cap. Provision **160 MiB private spool space** for main DB, rollback journal and bounded scratch; do not assert that the logical 8-MiB payload cap also bounds SQLite overhead. No VACUUM, backups, free-form SQL or ever-growing WAL in the runtime. Page-cap/I/O failures use the degraded path. |
| Delivery worker | One thread, at most **32 actual provider HTTP calls per pass**, then yield and check stop. Recovery/cleanup reads at most **256 rows per page**; no unbounded `fetchall`. |
| Teams batch | At most **60 items**, **24 KiB actual encoded request body**. Persist exact rendered body/time/membership before dispatch. A normal small cycle is one addition message, not one per domain. |
| Retry | **8 claimed workflow attempts** total; persisted delays **30, 60, 120, 240, 480, 960, 1,920 seconds**. Retry-After bounded to **30–3,600 seconds**, never less than ordinary backoff. |
| Provider I/O | **3s connect / 10s read**, no automatic retries or redirects, **2 MiB response bytes**, **2,000 attributes** per authoritative event evaluation. Truncated/malformed/oversized read is NOT absence. |
| MISP per-receipt lifetime work | At most **4,096 provider HTTP calls**, including reads, deletes, retries and crash-interrupted claims. Fixed-size one-attribute deletion progress, not an unbounded list of IDs. Exhaustion is terminal `provider_work_limit`. |
| Health | Authenticated local cached response at most **4 KiB**; visible-tab UI polling no more frequently than **15s**. |

The spool allowance is a deployment resource budget, not protection against filesystem quota changes or an external actor growing arbitrary files. SQL page and application logical caps are enforced before allocation where possible; journal/I/O failure must be handled, never described as impossible because a reserve exists. No standalone new knob/config form is required for these Stage-3 defaults; inject smaller limits in tests.

### Minimal tables / invariant ownership

- `control`: schema/epoch, sequences, configured source signature/revision, session clean marker, coverage state, cumulative counters and persisted accounting completeness.
- `cursor`: target incarnation, source/projection signature, last consumed managed-IP set, last source-operation UUID, tracking state. This is the **notification detector**, not canonical observation storage.
- `baseline`: the last valid completed-full active IP/label map. Do not derive it from `cursor`, which may be ahead because a full cycle crashed halfway.
- `grace`: IP, labels, `missing_since`, optional `not_before`, per-expiry identity.
- `receipt`: immutable source-operation UUID/item/action/channel/binding, compact payload, creation sequence, state, attempt count, due time, current attempt token, bounded MISP phase/progress, operation count. **No cascading foreign key to cursor/target.**
- `batch`: Teams immutable membership/body and claim state; at most one open partial builder for the current cycle/binding/action. Member receipts remain the capacity unit.
- `recent`: the bounded 60-second suppression keys.
- `terminal`: bounded sanitized diagnostics. Reuse constant control counters rather than a row per loss.

## 4. Executable observation admission protocol

### 4.1 Candidate production and authority

`run_domain_cycle` first produces a private `DomainObservation`: all resolver results, exact existing INIT/change/failure-drop/lifecycle mutations, fresh-positive evidence, and the complete configured-provider managed-IP union. Keep resolver concurrency and failure rules. Apply changes to a detached candidate, not the live target dictionaries while collector futures finish. Record events in the same completion order as today. Serialize history preparation outside `state_lock`; retain the 1,000-event policy and all raw values.

The repository owns source acceptance. Under **config lock -> repository coordination**, revalidate the original target lease, captured provider/decoder authority and candidate version. No reacquisition by name. Validate and allocate ordinary in-memory structures before committing an irreversible ledger transaction. Never call a provider under any of these locks. Hold `state_lock` only for short checks/publication, not serialization or SQLite/fsync.

Production has one monitoring runner, so this is a domain-sized change, not a new scheduler. The repository remains the sole production history mutator/purger. Direct helper compatibility is not permission for production to bypass it.

### 4.2 One ledger transaction; no finalization

For a valid candidate in covered mode:

1. Select the persisted notification cursor for the matching target incarnation/projection. Compare its managed IPs to the candidate union. On initial feature enrollment only, initialize from existing active current history **before querying**, so old observations do not become additions. A genuinely new configured target with no prior observations has an empty cursor and its fresh first result still produces INIT additions.
2. Begin a short `BEGIN IMMEDIATE`. Validate the expected cursor version/source-operation identity. Apply existing grace suppression and bounded 60-second duplicate suppression. Determine enabled destination obligations from the captured committed configuration and binding identities.
3. For an eligible unit within all count/byte limits, insert **all** its required destination receipts, reserve its eventual Teams rendering footprint, and consume its dedupe state. For an over-budget unit, insert no new receipts and atomically increment `missed_total`/reason/channel counters by the number of eligible destination obligations. Dedupe, disabled channels and grace-suppressed reappearance are not missed deliveries.
4. In the SAME transaction consume the candidate IP cursor, including overflowed and disabled-channel transitions. Thus a later identical answer does not re-create missed work when space becomes available. Allocate the immutable source-operation UUID before the transaction; a same-process ambiguous COMMIT readback looks up that exact UUID, never invents another.
5. Commit. **This is the whole local delivery admission boundary.** There is no second promote/finalize write. A failed return from COMMIT is treated as uncertain until independent reopen/readback establishes the row/cursor outcome; do not dispatch merely because memory expected a commit.
6. Independently publish the observation into existing dictionaries under the valid source lease and attempt its canonical history replace. Preserve dict identities required by existing leases. History storage success/failure is reported separately. Improve the history result to distinguish definitely not replaced from replace-visible-but-directory-durability-uncertain; don't claim fsync failure rolled back a replace. This reporting is not an outbox prerequisite.

If ledger admission returns unavailable/busy/uncertain, **do step 6 anyway**. Switch this observer to GAP mode, keep old admitted work, count known unadmitted obligations in bounded volatile scalars when their fate is known, and do not enqueue them later. A maybe-committed transaction is not counted as definitely missed until its UUID is resolved; public `accounting_complete=false` covers that uncertainty. If canonical history also fails, memory can still show the fresh valid observation, with history persistence degraded; there is no promise of raw durability on unwritable media.

Source admission and observation publication are held within the same repository/config coordination boundary, so target deletion cannot interleave between them. Ordinary Python process death can interrupt after SQLite commit; durable delivery remains legitimate because source authority was checked **at admission**, not because JSON was subsequently written. If an unexpected post-commit memory error occurs, do not reverse receipts or falsely claim rollback: mark observation publication degraded and let the next collection repair current state.

### 4.3 Why both original crash gaps are closed

- **History-before-intent:** healthy source publication cannot make history newer before the ledger decision. On a crash after ledger commit but before history, the receipt survives and the persisted detector cursor prevents a repeated identical observation from admitting it again. No missing history token must be rediscovered. In GAP mode history can advance without intent by approved policy, explicitly outside complete delivery coverage.
- **Absence-before-grace:** the completed-full baseline is persisted before any next full scan mutates domain history. Domain cursor/history advancement never overwrites it. If the process crashes after a domain became empty but before full reconciliation, restart still has the old IP in `baseline`; the next valid complete full scan can start grace. An interrupted full scan is not a completed absence observation, so the original crash instant is not fabricated as `missing_since`.
- **Finalization unavailable:** there is no source finalization. Failure sealing a Teams batch or persisting an ACK stops only that delivery operation; cursor/history collection continues. Already admitted rows remain occupied and recoverable.

### 4.4 What bounded tracking overflow means

Delivery queue capacity and detector coverage are different. A full receipt queue does NOT prevent cursor/baseline/grace updates in their reserved budgets.

If a domain's new cursor projection cannot fit its separate limits, consume the observation anyway, atomically count its known eligible obligations as missed if the ledger can write, and mark that cursor untracked. Do not keep comparing future observations against its obsolete stored IP set. Preserve an existing admitted receipt independently. Once its projection fits, install the **current** union as a new baseline, without backfill; only subsequent fresh transitions can admit. If even a compact untracked cursor row cannot fit, expose coverage loss in constant control state and use the live pre/post observation only for best-effort loss counting—never allocate a side map proportional to unlimited targets.

For an oversized completed-full baseline or insufficient grace storage, retain existing pending grace and existing admitted work, mark removal tracking incomplete, and count `tracking_overflow` separately. Do not silently truncate a canonical map or pretend a missing future expiry can be enumerated. Existing grace can still be canceled by fresh positives and can mature on a valid complete full scan; new missing entries that cannot be represented make `accounting_complete=false`. When full tracking fits again, seed from the then-current active map without retroactively manufacturing missing intervals. A tracking failure is not the same as a known expired removal: the former may hide an uncountable future obligation; the latter increments exact missed destination units.

## 5. Full reconciliation, grace and GAP recovery

### Normal full and force rules

- First-feature startup seeds `baseline` from the configured active projection before any queries. Import `ip_removal_grace_state` once, preserving every representable original `missing_since`; record import completion transactionally. Leave the old file untouched and disable its production writer only after successful import. Oversized/corrupt import means visible incomplete removal coverage, not silent empty migration or stopping DNS observation.
- `reconcile_full` runs only under Stage-2's existing entire-generation/all-original-leases gate. A stale full cannot advance baseline, start/expire grace or clear pending state. A configuration-invalid completion schedules the existing fresh full scan as today.
- In one transaction: cancel present IPs, start newly missing IPs using the saved prior baseline and completion time, evaluate previously pending absence against **86,400 seconds**, admit enabled destination receipts for expiry or increment exact missed obligations on receipt overflow, retire only those resolved expiries, and install the new baseline.
- Expiry at capacity is intentionally lossy, not deferred replay: `grace deletion + missed increment + new baseline` is one COMMIT. This is the approved replacement for the old wording that expiry could leave grace only through successful notification admission. No grace entry vanishes with neither intent nor explicit loss/unknown outcome.
- If that transaction rolls back, durable baseline/grace remain unchanged. Runtime observation still advances. Enter GAP rather than letting a later retry invent outage-time notifications. GAP recovery treats known overdue-but-unadmitted expiries as missed and retires them atomically; it does not dispatch them as historical work.
- Force uses the original force request's whole lease set and **fresh positive evidence only**, not cached full projection, for grace cancellation. It never advances full baseline or expires removals. Domain addition/cursor commits happen as described above; at force completion, cancellation is a separate short transaction under the whole-force lease gate, deliberately not described as atomic with those earlier commits. A failed cancellation taints grace coverage and enters the conservative GAP recovery rule. Full-scan positive cancellation stays at valid full reconciliation, not an unfenced per-domain callback.
- Target/provider configuration changes do not allow retired provider snapshots to vote. Rebase affected **domain addition cursors** to the newly active pre-query projection when authority changes, just as today's domain before/after comparison does; retired IPs must not suppress fresh additions. Keep the last completed full baseline until a valid next full replaces it, preserving existing reconciliation semantics.

### Recovering a healthy store without historical replay

During an outage use the application's existing live observation state to identify fresh transitions and maintain only bounded counter/health shadows; never retain an unbounded retry list of unadmitted candidates. The ledger's old detector cursor must not be used to replay the outage on recovery.

The same-process recovery barrier pauses **new delivery admission only**, not collection: resolve any ambiguous source-operation UUID; checkpoint known loss scalars idempotently using one process UUID plus cumulative per-reason totals in a single fixed control row (not a growing per-process table); then replace delivery cursors with the currently observed configured projections. Preserve every admitted receipt and its sequence/attempt count. Do not compare these new cursor baselines with old history to make additions. Subsequent freshly collected transitions are eligible again.

For removals, maintain the distinction:

1. An ordinary crash with an incomplete full scan retains the last completed-full baseline. A fresh valid full after restart may establish a **new** missing interval from that baseline; this closes the absence gap.
2. A detected ledger outage or a grace-cancellation failure taints the absence interval. Never send an old overdue expiry just because storage returned. Count known skipped overdue destination obligations as missed; for still-pending potentially valid intervals retain original `missing_since` for diagnostics but impose `not_before = recovery_full_completion + 86,400`. Fresh positive observations cancel them. New intervals start only from a valid new full.
3. On an unclean session restart, old admitted delivery still retries, but the first fresh full is an **addition rebaseline**, not an addition replay. Differences from the durable cursor that can be enumerated are counted as missed `recovery_gap`; unchanged source data is not counted again. For existing grace, apply the conservative recovery hold above because a lost positive cancellation cannot be excluded. Previously unseen disappearance relative to the saved full baseline starts grace at that fresh full completion. The hold can delay removal; it never shortens the required grace. Clean shutdown/reopen preserves exact existing timers without this extra hold.

This conservative first-full behavior is a concrete recovery choice, not a requirement to freeze monitoring. It trades potentially missed new additions during recovery for no automatic historical replay and makes those known misses visible. Small ordinary healthy cycles retain existing alert semantics.

### Completeness and an unwritable medium

Before observing with a usable initialized ledger, commit a session-open marker; mark clean only after stopping source admission, draining available local writes and closing the worker safely. A reopening conservatively sets public cumulative `accounting_complete=false`: a previous process might have observed while it could not write even an outage marker. It stays false for that accounting epoch; repair or emptying the queue does not turn historical uncertainty into completeness.

Known loss while unavailable lives only in bounded in-memory counters and can disappear with the process. Exactly how many observations, recipients or transient grace cancellations occurred during a completely unrecordable interval is unknowable. A stale clean marker can also outlive a launch that could not mark itself open. No on-disk protocol can distinguish that launch from no launch when **nothing** could be written. Report this limit; do not promise durable counters or an exact absence timeline in that case. Recorded clean restarts preserve timers; detected unclean/gap periods apply the conservative hold, and all reopened accounting is explicitly incomplete. Corrupt/missing established storage disables dispatch rather than reconstructing it from raw history.

## 6. Target deletion, restart identity and destination identity

### Source ownership

The live Stage-2 `TargetLease` remains the authority for any new admission and observation publication. A ledger cursor has a random durable incarnation UUID for dedupe/diagnostics; it never grants source authority. During the same process, deletion/re-add receives a new incarnation; an old captured lease cannot use it.

On restart, attach existing cursor state only when the saved committed configuration revision and canonical target/provider/decoder signature match the current authoritative configuration and the session is eligible for ordinary recovery. Do not treat equality of a domain name as authority. A changed revision/signature or unclean session invokes the rebaseline barrier. Known current-process unrelated configuration changes may update the signature/revision without fabricating target reincarnation; a restart cannot infer an unrecorded delete/re-add from equal final definitions. First-feature enrollment and genuine post-start new-target INIT remain separate from outage rebaseline.

Config deletion revokes the live lease exactly as Stage 2 does and purges raw state. It may delete cursor/unused dedupe state in a best-effort ledger maintenance transaction, but **does not delete receipt/batch rows, their source-operation UUIDs, payloads, binding or attempt tokens**. If SQLite is unavailable, config still commits/revokes, history purge still proceeds, and cursor cleanup waits. There is no history token to preserve by blocking purge. Existing history-cleanup failure may still block re-add under the accepted Stage-2 contract; delivery pressure introduces no additional target reuse block.

On recovery, orphaned cursors are pruned without cascading to receipts. Dispatch does not demand a still-configured source target: the original authority check occurred at admission. Unadmitted work from a deleted generation is not resurrected by looking up the current name. Startup orphan history cleanup cannot erase ledger admission proof.

### Destination ownership

Bind each receipt to an opaque keyed fingerprint, not mutable `alerts.py` globals. MISP binding = endpoint + event identity (not API key); same destination with rotated key uses current credentials. Teams binding includes the complete webhook address because the secret URL is also its destination. Keep the private fingerprint key in owner-only store metadata; never expose it or fingerprints via health. Do not persist webhook/API key/credential-bearing URLs.

Endpoint/event rotation, disablement, unapplied adapter revision or missing client yields `blocked_config` with stable reasons including **`old_binding_blocked`**, not forwarding. Re-enabling the exact same binding resumes the same work/attempt count. Turning off MISP removal blocks not-yet-claimed removal operations; an already claimed immutable outbound attempt may complete. No retained old credentials, no manual replay, no automatic rebind.

At claim, obtain an immutable adapter from the committed config and revalidate binding/readiness/removal policy under config ownership, then persist the claim. Subsequent network runs unlocked. A config change after this outbound-admission boundary does not revoke an already admitted call; the next call/step must revalidate. An optional runtime apply failure leaves config committed and delivery blocked, not silently using the previous adapter.

Bootstrap provenance is deterministic: a present JSON `alerts` object, including `{}` or explicit clears, is authoritative; INI is used only when that object is absent. Never fall back because a configured client failed to initialize.

## 7. ACK, retry, batching and shutdown

Receipt states: `unsealed`, `pending`, `in_flight`, `retry_wait`, `blocked_config`, `acked`, `failed`. Stable action enum `Added|Removed`; channels `teams|misp`. Only actual destination success can become `acked`. Admission, dedupe, disabled configuration and history save are not ACKs.

One worker persists claim/attempt identity before outbound I/O. Every finish/retry/failure update compares exact `(receipt or batch ID, attempt token, expected state)`. Restart moves interrupted claims to persisted retry-wait without resetting attempts; lost or stale completions cannot overwrite newer claims. No lease/heartbeat framework is needed for one process owner and one worker. Persist errors stop further outbound claims, not observation; reopen/readback resolves uncertain ACK persistence. Remote success before durable ACK can duplicate on recovery. UI/API must say **at-least-once attempt semantics**, not exactly-once delivery.

Per-destination independence: Teams success plus MISP failure persists Teams ACK once and retries only MISP. Multi-item MISP outcomes never aggregate into a truthful-all-success Boolean unless every item was verified. Terminal/exhausted admitted work increments `failed_total`, not `missed_total`; it consumed capacity and was attempted. Payload GC happens only after terminal state/counters committed. Removed terminal summaries cannot regenerate work because cursors consumed transitions independently of receipt retention.

Keep FIFO across `(binding, IP)`, including different domains referring to the same MISP event/IP. A delayed removal cannot run after a later addition for that destination/IP. Blocked/retrying predecessors hold later conflicting work; other IPs/channels continue. A terminal predecessor releases order, without permission for later manual replay. A Teams batch may be claimed only when all its members satisfy predecessor order; do not reorder its sealed contents to hide a blocked item.

Teams: one persisted partial batch per cycle/action/binding, seal at cycle end for a normal small cycle; seal a full 60-item or 24-KiB chunk early for larger cycles and carry the remainder into the next bounded chunk. Restart seals persisted unsealed partial cycles without recollection. Seal failure retains admitted rows/byte reservations; observation proceeds. Freeze title/body/local timestamp for retry. Explicit 2xx is ACK of webhook acceptance, not human receipt; 3xx is not success and redirects are not followed.

MISP: new adapter returns typed `acked|continue|retry|blocked|failed` plus a bounded stable reason/phase, never raw response/exception. Validate event identity, expected IP/type and response envelope. Addition ACK requires authoritative existing exact `ip-src` or validated add success; a failed add never becomes locally existing. Removal uses bounded authoritative event read, then one exact matching attribute-ID delete step, then another read. Persist only the current bounded ID/phase and counters; successful deletion is not repeated if a later authoritative read shows it absent. A malformed/missing event is not proof of absence; removal ACK requires a complete valid read with no matching attributes. Each underlying HTTP read/delete counts toward the 32-call pass and 4,096-call lifetime cap. Positive progress can span passes within one workflow attempt; a transient failure starts backoff and a later workflow attempt, not a per-attribute immediate retry loop. Attempt and total-call caps persist across restart.

Transient transport errors/timeout/429/5xx/ambiguous responses retry. Payload/protocol/resource exhaustion is terminal with an explicit stable code. Authentication/TLS/configuration/client availability blocks until appropriate configuration repair; it is not a tight polling loop. A repeated ambiguous remote response is bounded by attempt/work caps. Do not claim TLS correctness from this design: the parent owns the separate HTTP MISP correction and integration must use its verified policy.

Existing daily sightings: remove sighting generation from retryable attribute ensure/delete operations. On the first observation-triggered add workflow only, if the valid initial MISP event read already contains that IP, invoke the existing daily enqueue hook once, guarded by a consumed first-observation flag before the hook. Retain existing daily throttling and best-effort queue; restart/retries must never call this hook as new observation. A crash after consuming the flag can lose a sighting, consistent with its explicitly best-effort scope. Existing removal cleanup of queued sightings remains best-effort after confirmed attribute absence. Do not delete old queued sightings, include sightings in attribute ACK, or silently upgrade their queue's durability claim. Their provider calls are scheduled separately within the same pass call budget, not an unbounded retry-triggered `flush_sightings_batch` loop.

Shutdown: fence new claims, request worker stop and wait at most **3 seconds** for it. If a socket call is still running, report it and retain its durable in-flight attempt; do not close a connection it can still use or mark session clean. It may be a daemon worker for process exit, with no late publication after owner close. Socket read timeout and SQLite busy timeout do not bound a stuck kernel filesystem call or total streaming HTTP elapsed time. This stage does not claim hard real-time observation under kernel/fsync hangs; ordinary capacity, lock contention and returned storage errors must never cause deliberate monitoring backpressure. That OS-level limitation is distinct from freezing observations until a delivery row can finalize.

## 8. Exact internal APIs and file ownership

Proposed signatures are implementation contracts, not claims these APIs exist today:

```python
@dataclass(frozen=True)
class DomainObservation:
    lease: TargetLease
    source_version: int
    projection_signature: str
    candidate_current: dict
    candidate_history: dict
    managed_ips: frozenset[str]
    fresh_positive_ips: frozenset[str]
    observed_at: int
    source_operation_id: str
    cycle_id: str

@dataclass(frozen=True)
class AdmissionResult:
    outcome: Literal['admitted', 'consumed', 'missed', 'gap', 'stale']
    admitted_receipts: int
    missed_receipts: int             # known, not inferred uncertainty
    ledger_committed: bool
    accounting_complete: bool

class DeliveryStore:
    def bootstrap(self, active_projection, legacy_grace, authority) -> RecoveryState: ...
    def record_domain(self, observation, authority, bindings) -> AdmissionResult: ...
    def reconcile_full(self, authority, active_map, completed_at, bindings) -> ReconcileResult: ...
    def cancel_force_positive(self, authority, fresh_positive_ips) -> ReconcileResult: ...
    def enter_gap(self, reason, known_loss_counts) -> None: ...  # always updates cached health
    def recover_gap(self, authority, current_projection, full_result, loss_checkpoint) -> RecoveryState: ...
    def seal_cycle(self, cycle_id) -> SealResult: ...
    def claim_next(self, bound_adapter, now) -> Optional[DeliveryClaim]: ...
    def finish_step(self, claim, provider_result, now) -> FinishResult: ...
    def retire_target_cursor(self, incarnation) -> MaintenanceResult: ...
    def health_snapshot(self) -> DeliveryHealth: ...
    def close(self, *, clean: bool) -> None: ...

class MonitorStateRepository:
    def accept_observation(self, observation, *, config_store, delivery) -> ObservationCommitResult: ...
    # existing capture/valid/configure/commit_history contracts remain

class DeliveryWorker:
    def run_pass(self, *, max_provider_calls=32) -> PassResult: ...
    def stop(self, *, join_seconds=3.0) -> StopResult: ...

class BoundDestinationAdapter:
    def execute_step(self, claim) -> ProviderStepResult: ...
    # one bounded provider operation; no recursive unmetered helper loop
```

`ObservationCommitResult` separates `source_accepted`, `history_persistence` (`saved|failed|uncertain`) and `delivery: AdmissionResult`. It must not collapse history failure into a successful save or delivery outage into a rejected DNS observation. `ReconcileResult` separates source-generation validity from delivery coverage; delivery failure does not tell the scheduler to repeatedly force full scans or starve its ordinary cadence. `record_domain`'s durable cursor CAS is internal idempotency; its `authority` has already been validated inside the repository/config boundary, not a caller-supplied substitute for `TargetLease`.

Implementation ownership:

| Owner | Files / responsibility |
|---|---|
| Core publication owner (one serialized slice) | `monitor/engine.py`, `monitor/repository.py`, `monitor/removal_grace.py`, `dns_monitor.py`, focused `history_manager.py` result reporting; private candidates, authority, observer bypass, startup/shutdown and cursor/grace integration. Do not split competing edits across these files. |
| Store/worker owner, stable interface first | New `monitor/delivery_store.py`, `monitor/delivery_worker.py`, `monitor/delivery_types.py`; SQLite schema, finite budgets, transactions, GAP bookkeeping, batching, claims/ACK and health cache. Core integration follows interface tests. |
| Adapter owner | `alerts.py`, `mispupdate_code.py`, relevant runtime settings integration; immutable binding/typed ACK/bounded steps and separated sightings. No change to the parent's HTTP MISP TLS patch without coordination. |
| Config/bootstrap coordination | Core owner serializes any `monitor/config_service.py` and `http_api/settings_handlers.py` changes with adapter owner. Preserve disk-authoritative config revision and warning semantics. |
| Health/UI owner after schema freeze | `http_api/basic_handlers.py`, `http_api/context.py`, `http_server.py`, `http_api/rest.py`, `security/policy.py`, `http_api/openapi.py`, `docs/API.md`, `docs/openapi.json`, main console HTML/JS. Integration into `http_api_handlers.py` must wait for parent TLS ownership release. |

Lock rule: config -> repository coordination -> delivery store for short ledger work, with short `state_lock` checks/publication outside SQL execution. No store-owned method calls config or repository while holding its connection lock; worker captures adapter authority in the same forward order. No network/history serialization under state/SQL locks. Config cleanup never waits for delivery capacity. Health never takes the SQL connection from a publisher. All cursors/rollback/close belong to the same serialized operation; Python 3.10 compatibility is required.

## 9. Public health contract

Authenticated **GET `/delivery-health` and `/api/v1/delivery-health`**, admin/operator only; preserve existing authentication/authorization and versioned routing conventions. Both use the same closed schema and cached local snapshot. A store failure still permits HTTP **200** with degraded/unknown cached health; use 503 only when even the health owner is absent. Health transport success is not delivery success. Do not make local observability disappear exactly when SQLite is unavailable.

```json
{
  "status": "degraded",
  "observation_policy": "continue",
  "storage_ok": false,
  "worker_running": true,
  "coverage": "gap",
  "accounting_complete": false,
  "missed_total": 12,
  "missed_unpersisted": 3,
  "failed_total": 2,
  "acked_total": 40,
  "pending": 8,
  "retry_wait": 1,
  "blocked": 2,
  "oldest_pending_age_seconds": 120,
  "capacity": {
    "used_receipts": 11,
    "max_receipts": 4096,
    "used_payload_bytes": 9000,
    "max_payload_bytes": 8388608
  },
  "channels": {
    "teams": {"enabled": true, "pending": 3, "blocked": 0, "last_success_at": null, "last_error": "delivery_storage"},
    "misp": {"enabled": true, "pending": 5, "blocked": 2, "last_success_at": null, "last_error": "old_binding_blocked"}
  },
  "tracking_complete": false,
  "counts_stale": true,
  "last_error": "delivery_storage"
}
```

The example is illustrative schema data, **not execution output**. Enums: `status=disabled|ok|degraded|blocked`; `coverage=covered|gap|rebaselining`; nullable timestamps/age/error codes. Counts are nonnegative bounded integers, cumulative counters saturate at signed 64-bit max and set accounting incomplete on saturation. `pending` excludes blocked/retry-wait; outstanding used capacity includes unsealed/in-flight as part of pending. `missed_total` counts durably recorded **destination-item obligations never admitted**, not messages, failed attempts, disabled channels or suppressed entries. `missed_unpersisted` is the known volatile increment not yet included in `missed_total`; idempotent checkpoint/clear prevents double counting. `failed_total` counts terminally unsuccessful admitted destination-item obligations. `acked_total` counts verified ACKed obligations. No invariant equates observed IP count with these counters.

`accounting_complete=false` means `missed_total` plus the volatile known increment is only a lower bound for the accounting epoch. It is sticky after an outage, tracking gap, ambiguous fate, counter saturation or store reopening. `storage_ok=true` later does not clear it. Cached counts may be stale; set `counts_stale` rather than showing zero. An all-disabled configuration is `disabled` only if there is no outstanding old-binding work or relevant degraded state; old blocked work remains visible.

No IP, label, domain, receipt/attempt/source ID, filesystem path, fingerprint, endpoint, key, response body or exception string appears in health, logs or stable reason labels. Canonical history/results projections remain unchanged. Main console displays “observation continues; N notifications not admitted”, lower-bound/unknown accounting, pending/blocked/failed and last success. Never display “sent” because enqueue succeeded. No retry button or replay endpoint.

## 10. RED matrix — acceptance cases, not a vague test list

All integration tests use the real accepted producer/repository wiring after refactor, fake collectors/adapters, injected clocks and scratch storage. No DNS/VT/Teams/MISP traffic. Use independent store objects/connections after crashes; same-connection reads are insufficient transaction evidence.

| ID | Fixture / forced boundary | Required RED assertion |
|---|---|---|
| C01 | Real domain INIT/change, SQLite commit paused before canonical history publication; kill child | Restart has exactly one admitted receipt per enabled destination and advanced cursor despite older/missing raw history. Same fresh answer creates no second local intent. |
| C02 | Kill before SQLite COMMIT | Neither receipt nor cursor/loss partial is durable. No source/history publication occurred through the healthy path; recovery does not invent an ACK. |
| C03 | Source COMMIT succeeds but caller receives injected error | Lookup exact operation UUID resolves once; no new UUID resubmit, no false missed increment or premature dispatch. |
| C04 | History temp-write failure, replace failure, directory-fsync-after-replace failure | Observation publication/delivery status separated; admitted work survives; history result is failed/uncertain, not fictitious rollback. Next cycle still collects. |
| C05 | Simultaneous default ceilings: 4,096 receipts and 8 MiB reserved bytes; fill by real admission to the first binding limit, then one eligible two-destination unit. Companion count-isolation fixture reduces only receipt capacity to 3, with two existing receipts. | Old receipts/batches/reservations unchanged; no prefix admission; cursor advances; missed increases by two; canonical history/current contains new observation. Drain through the metered worker; identical observations after more than 60 seconds and independent reopen create no replay or additional misses. Count control proves both destinations fit bytes but only one fits the remaining receipt slot. |
| C06 | Byte cap, 257 tuples, multibyte label/payload boundary | Exact all-or-nothing unit loss counts; no truncation of raw evidence; limits use encoded bytes and rendering reservation. |
| C07 | SQLite busy, read-only/open failure, actual SQLITE_FULL and returned I/O error | Repeated subsequent DNS cycles/history writes proceed; cached health degraded; no delivery-dependent stale-last-good freeze. Separate kernel-hang limitation remains explicit. |
| C08 | Teams seal failure / ACK persistence failure while collecting multiple later changes | Admitted work stays occupied, later observations advance, no single-slot finalization freeze; claim stream halts safely on ACK uncertainty only. |
| C09 | Ledger commit before history, receipt terminal then GC; identical observation | Cursor, not retained terminal payload, prevents duplicate; no history scan/resurrection. |
| R01 | Baseline contains IP; persist absent domain/cursor/history; kill before full reconciliation | Restart still has prior full baseline; fresh valid full starts new grace at its completion, no immediate removal and no lost baseline. |
| R02 | Grace at 86,399 then 86,400 seconds; clean restart | No early delivery; exact boundary eligible; stored original missing_since preserved. |
| R03 | Expiry transaction paused after grace delete; rollback | Grace and counters/receipts all return to prior state. On success either intent or exact missed increment commits with retirement. |
| R04 | Expiry when queue full, then free queue and repeat same absent full | One missed obligation per enabled destination; no repeated count, no deferred replay, baseline still progresses. |
| R05 | Force subset sees one positive and has cached other provider positives | Only fresh force-positive grace canceled; no absence/baseline/expiry advancement. All original force leases checked. |
| R06 | Configuration changes during full / empty stale full / provider replacement | Stale reconciliation does nothing; retired raw values remain evidence but not votes; force subset does not retire other configured providers. |
| R07 | Lost positive-cancellation write; GAP recovery / unclean restart | Original missing_since diagnostic retained, conservative 24-hour recovery hold or current positive cancellation applied, no overdue historical expiry sent. |
| R08 | Cursor/baseline/grace/import size cap | DNS/history unaffected; admitted queue retained; no obsolete cursor delta replay; tracking incomplete and accounting lower bound; re-enrollment baseline-only. |
| O01 | Delete before candidate admission; delete/re-add before late success/failure | Old lease cannot publish, change failure counters, create receipts or acquire new authority by name. |
| O02 | Delete after ledger COMMIT but before cycle seal; delete with ledger unavailable | Admitted token/payload survives and can deliver; source purge proceeds without token tombstone; re-add does not reuse old cursor. |
| O03 | Restart config deleted target; orphan purge runs | Outbox retries admitted old target without history; orphan cursor cleanup cannot cascade receipt deletion. |
| O04 | Identical definition delete/re-add across config revisions, including failed ledger cleanup | Revision/signature mismatch invokes rebaseline; old TargetLease never rebound; no assumption that current name or object identity survived restart. |
| D01 | Teams ACK, MISP transient failure, restart | Only MISP retried; channel receipts, attempts and next-due persisted. |
| D02 | Remote success then process death before ACK | Possible duplicate documented/tested; no false exactly-once claim or premature ACK. |
| D03 | Eight transient workflow failures, repeated restarts and Retry-After | Exact finite attempts/backoff, no reset; terminal failure counted once; no tight loop. |
| D04 | Mixed MISP add envelopes, raised exceptions, malformed event or mismatched IP/event | Only proven items ACK; failed add never enters existing set; malformed read is not absence. |
| D05 | Several matching attribute IDs, partial delete then crash | Confirmed absent ID not blindly retried; remaining match removed via bounded steps; ACK only after authoritative complete absence; pass/lifetime call caps include every subcall. |
| D06 | Same IP across two domains, old retrying removal then new addition | FIFO per binding/IP across domains; unrelated destination/IP continues; no late old removal after new add. |
| D07 | Endpoint/event/webhook rotation, API key rotation, disable, remove-opt-in off, adapter apply failure | old_binding_blocked/no forwarding; same binding key repair resumes without reset; claim-time authority determines in-flight completion. |
| B01 | Existing two-domain small-cycle batch test through real ledger | One ordinary Teams addition request containing both; no per-domain sends. |
| B02 | 61+ items / encoded body threshold / crash partial cycle | Bounded complete split, no “first 60” silent payload omission; stable retry bodies; restart seals admitted partial batch only. |
| S01 | First observation already-existing MISP IP then retries/restart | Daily sighting hook at most once for observation path, not generated by retries; attribute ACK independent of best-effort hook failure. |
| S02 | Secret sentinels in webhook/key/URL/exception/provider body | None in store fields designated nonsecret, health, logs, public history, errors or schema; IOC payload remains private local storage only. |
| H01 | Legacy/v1 routes, admin/operator/read-only/unauthenticated | Exact RBAC/routing/OpenAPI parity, <=4-KiB response, no provider/SQL/history traversal in health request. |
| H02 | Writable overflow, unreadable store, stale cache, process loss of volatile misses | missed_total semantics/lower bound/accounting_complete/counts_stale correct; UI unknown never zero/sent. |
| L01 | Store close versus in-flight callback; 3-second stop | No use-after-close, no late stale-token ACK, no clean-session marker with a live callback; report unresolved work, preserve recoverability. |
| L02 | Independent HTTP readers/config writer/observer/worker barriers | No store-to-config lock inversion, no shared-connection transaction visibility leak, no provider I/O under locks. |
| P01 | Existing Stage-1/2 suite plus new source-projection parity | Canonical raw events/INIT/lifecycle/failure threshold, schedules, auth/audit and delete fencing unchanged except the explicitly documented delivery admission timing/recovery policy. |

C05 clarification: these are simultaneous upper bounds, not a guarantee of 4,096 occupied receipts within the byte budget. Keep every default unchanged in the first fixture and report its actual occupancy; do not inflate byte capacity or fabricate SQL rows/reservations to reach the count ceiling. The smaller-count companion uses the test-limit injection explicitly permitted in section 3. Persistent recipes are in `tests/test_delivery_capacity_contract.py`. This clarification changes neither production limits nor the observation-first policy.

Implement in order: store atomicity/budget RED tests; core private-candidate/observer-bypass integration; full baseline/grace/recovery; immutable adapter ACK/worker; health schema/UI; then exact-tree independent review and canonical test/lint/E2E. Do not label Stage 3 accepted from the primitive probe or a unit-only subset. Keep parent TLS integration serialized and verify the combined source tree after it lands.

## 11. Bounded local feasibility evidence and limits

Probe: `/home/piecer/.hermes/cache/scratch/tracedns-hardening-tnkc2rhx/stage3-observation-first-probe.py`.
Machine-readable successful rerun: `/home/piecer/.hermes/cache/scratch/tracedns-hardening-tnkc2rhx/stage3-observation-first-probe-results.json` (writer contention measured 0.0507 s on that rerun). The matrix contains **37 unique RED case IDs**. Final SHA-256 verification matched **all 195 accepted-snapshot manifest entries**, with zero mismatches; initial/final tracked-only root status listings matched. This verifies snapshot preservation, not an assertion that the parent stopped working on its separate root patch.

Executed with `/home/piecer/dev/src/tracedns/.venv/bin/python`, `PYTHONDONTWRITEBYTECODE=1`. Stdlib only, scratch-only files, no network, no product imports/edits, no services. Results: **Python 3.10.12; SQLite 3.37.2; five probe groups passed**:

- Child `os._exit` before COMMIT: receipt rows **0**, cursor rows **0**, exit **21**, integrity check OK.
- Child exit after COMMIT but before any history write: receipt rows **1**, cursor rows **1**, exit **22**; independent reopen preserved both, identical observation had empty delta, deleting the cursor left its receipt token intact.
- Toy capacity **1**: cursor plus missed counter committed without evicting existing work; expiry delete/counter rollback preserved both old grace and old counter, successful transaction changed both; separate full baseline stayed intact.
- Second writer hit the configured **50-ms** busy timeout in approximately **0.0505 s** in the recorded successful run.
- Real page-limited SQLite-full failure (maximum **8 pages**) rolled back all inserted payload rows; independent reopen integrity OK; final DB **8,192 bytes**.

The first run hit the intended disk-full condition but the assertion itself used `sqlite3.SQLITE_FULL`, unavailable in Python 3.10. The scratch probe was corrected to assert the actual exception text and rerun successfully. This is a concrete compatibility issue to cover in product error classification; do not invent 3.11-only exception attributes for the current Python.

These prove local transaction/crash primitives and the logical feasibility of admission-before-history with a separate detector. They do **not** prove power-loss durability on every filesystem, production schema budget overhead, complete engine integration, native Windows/macOS support, provider response compatibility, actual remote idempotency or an OS-level fsync deadline. Those remain implementation/operational gates, not fabricated successes.

Created this design document and its two scratch feasibility artifacts. Also recorded the admission-contract review and Python-3.10 probe lessons in the agent's existing `executable-contract-planning` skill; this is procedural memory, not product implementation. The accepted snapshot and product/worktree files were read-only. Root `http_api_handlers.py` ownership remains with the parent; no staging, commits, product deletions, restarts, credentials or provider requests were performed.


## 12. Parent integration boundary (normative)

The parent adopts the protocol and budget matrix above. This is a local observation-first contract, not a promise of atomic raw-history plus remote delivery. An admitted alert may survive without its full raw-history write. Unclean recovery may suppress/count first-full additions and extend uncertain removal grace by 24 hours; clean restarts preserve timers. These limitations must remain visible in operator documentation and regression evidence.

To permit isolated storage and transport implementation without competing type-file edits, adapters use closed mapping envelopes at their boundary:

- A binding descriptor contains `channel` (`teams|misp`), `binding_id` (opaque keyed digest), `enabled` (bool), `ready` (bool), `allow_removed` (bool), and nullable stable `error`. It contains no credentials or endpoint. The provider registry owns credential-bearing immutable adapter objects privately.
- A claim mapping contains `claim_id`, `attempt_token`, `channel`, `binding_id`, `action`, `attempt`, `provider_calls`, `progress`, `payload`, and `observation_hook_consumed`. Payload contains `entries` (IP/label/source-type triples); a sealed Teams payload additionally contains exact `body` (JSON object with title/text). Progress is a bounded JSON object. Internal store types may wrap this mapping, but must expose the same fields without leaking credentials.
- `adapter.execute_step(claim)` performs at most one provider HTTP call and returns exactly `state` (`acked|continue|retry|blocked|failed`), `reason` (nullable closed stable code), `progress` (bounded mapping), `retry_after` (nullable number), `provider_calls` (0 or 1), and `observation_hook` (nullable bounded local-only hook descriptor). No raw response/exception enters that envelope.
- The delivery worker persists any observation-hook consumed flag before invoking the separately owned best-effort local sighting hook. Provider calls for sighting flushing are separately budgeted; attribute retries never produce new sighting observations. Network calls never occur in a local hook.
- Store worker accepts injected provider lookup/claim-admission and rendering callbacks; production registry attachment belongs to parent integration. It must not import a not-yet-existing adapter module or fabricate its interface. Store-side claim/finish tests use exact mapping fixtures; combined tests later use the real adapter class.
- Adapter owner implements a new `monitor/delivery_adapters.py`, edits `alerts.py` and `mispupdate_code.py` only as required, and returns explicit bootstrap/config attachment instructions. It does not edit `monitor/config_service.py`, HTTP handlers, core engine or frontend. Parent owns those integration sites. Preserve callable compatibility for existing legacy helpers and prove their acknowledgements truthful.
- Store/worker owner implements `monitor/delivery_store.py`, `monitor/delivery_worker.py`, supporting `monitor/delivery_types.py` as needed, and new exclusively named store/worker tests. It provides an exact integration guide and acceptance-case coverage matrix; it does not edit the core producer, adapters, HTTP or frontend.

Do not reduce the 37-case acceptance matrix to primitive feasibility results. Each ownership slice must report partial/uncovered gates explicitly; the parent integrates the real producer and requires independent exact-tree review plus canonical/browser verification before Stage 3 acceptance.
