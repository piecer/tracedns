# Owned lookup runtime

`dns_monitor.main` explicitly creates one `LookupRuntime` attached to its state
repository. The runner pumps target admission and completions while four fixed
controllers call the existing `engine.run_domain_cycle` seam. A single global
provider population calls the existing `engine.collect_snapshot` seam. Calls
without the explicit lookup owner remain synchronous compatibility adapters;
they are not the production scheduling path.

## Capacity and time

- Global provider occupancy is `clamp(max_workers, 1, 64)`, not a per-domain pool.
  Workers grow lazily to the configured high-water mark; lowering the effective
  limit defers dispatch until occupancy falls below it. Threads are never
  replaced on timeout. The lifetime population is at most 64 provider workers
  plus four controllers. One additional application-owned terminal-audit worker
  is separate from provider capacity (see below); it is never replaced on timeout.
- At most two dispatched providers belong to one target storage identity.
  Provider selection prefers sessions without a slot, then rotates ready work.
  The existing process-wide DHT semaphore remains unchanged; this scheduler also
  admits at most two DHT tickets.
- Each unstarted queue is bounded by 16 descriptors. Provider cursors remain in
  controllers instead of expanding a whole scan into futures. Each dispatched
  ticket has one mailbox. Completed-but-unconsumed and overdue-running tickets
  still occupy physical capacity.
- Monotonic logical provider budgets are DNS 5 seconds, ENS 30 seconds, SNS 20
  seconds, RPC 35 seconds, and DHT's configured duration plus 5 seconds. Target eligibility ends
  75 seconds after ready-queue admission, including time waiting for capacity.
  Exact-boundary and later results are ineligible. Unstarted/deferred work is
  incomplete coverage, not a query error.
- The collector binds one worker-local cancellation/remaining-monotonic-budget
  context through native transport and decoding without changing the two-argument
  collector seam or no-owner helper defaults. DNS retains its two-second bound.
  ENS rebinds every HTTP RPC attempt (including Web3 nested calls/retries) to at
  most eight seconds or the original remaining budget, without rounding up;
  transport and RPC/application decode returns are checked before further work.
  Owned ENS refuses HTTP redirects and CCIP gateway fallback, whose separate
  Web3 transport would bypass this context. SNS keeps its original 20-second
  eligibility budget, clamps request and each live socket read to at most the
  existing 15-second timeout or remaining time, and explicitly streams in 8-KiB
  chunks. Its cap is 1 MiB of content-decoded bytes, inclusive; limit+1 is rejected
  before accumulation/text or record decoding. Gzip (including concatenated
  members), zlib-wrapped deflate and identity are decoded with bounded output;
  unsupported encodings and malformed/truncated streams fail closed. Owned SNS
  refuses redirects without Requests' implicit redirect-body prefetch and closes
  responses/sessions on success and failure. Live read-timeout rebinding uses
  urllib3's retained connection/buffered-response socket; an unavailable live
  socket interface fails closed. These checks do not interrupt blocked native
  calls or Web3 retry sleeps: late work retains its physical slot until return.

**Logical timeout is not physical termination.** A late callable retains its
physical slot and `(original target incarnation, provider)` single-flight key
until it actually returns and its mailbox/cleanup is retired. If every worker
wedges, no new provider can make progress: the runtime remains saturated rather
than creating replacement threads. `status()` exposes actual active, queued,
overdue, controller, and worker counts. At `max_workers=1`, a healthy target must
wait for the occupied physical slot to return. Four blocked local controllers
can likewise prevent new reductions. These are explicit cooperative-runtime
limits, not recoverable conditions disguised as successful cancellation.

## Incremental evidence and authority

An eligible provider result is reduced against a newly detached candidate from
the **original** lease, admitted through `accept_observation`, published, and
persisted before another same-target session can proceed. The gate is keyed by
storage identity and covers different generations and force/full sessions.
Worker registry contexts use the exact captured registry object. Configuration
changes revoke the old lease; the runtime never recaptures authority by name.

The same original eligibility predicate crosses store ownership, SQLite BEGIN,
and the final pre-COMMIT check. Cancellation rolls back receipt, cursor and
suppression changes together and returns stale without inventing a storage gap.
Real storage errors and unresolved COMMIT readback remain storage failures even
if eligibility expires concurrently. COMMIT begun on time may finish later;
this is not a hard fsync interruption contract. No-owner store calls retain
their optional-cancellation defaults and batching/recovery behavior.

The configured provider projection remains complete even for a forced subset.
Errors/timeouts retain last-good provider snapshots. A successful sibling is
admitted without waiting for another provider. Fresh-positive evidence merges
only admitted queried providers; cached values are never fresh force evidence.
Incomplete coverage cannot activate NXDOMAIN absence. A genuinely complete
empty/NXDOMAIN result can still follow the existing authoritative absence policy.
The legacy no-owner three-failure eviction semantics remain unchanged for DNS,
ENS and SNS. RPC, like DHT, retains last-authenticated evidence after failure.
RPC is one logical provider with fixed public-endpoint fallback. Its transport
uses per-attempt 8-second cooperative budgets, 1-KiB chunks, an 8-KiB identity-only
response cap, TLS verification, no proxy/redirect, and the original owner deadline.
See [RPC tracking](RPC_TRACKING.md) for authentication and role separation.

`CycleResult.complete` describes the selected scan's coverage. Its
`target_complete` mapping describes the targets visited by that scan, and
`positive` contains fresh admitted IP evidence. An omitted target has no completed
observation; it must not be inferred complete. Forced-subset completion is not
complete configured-generation coverage. For delivery recovery, the engine also
publishes a target-end boundary after every configured required provider succeeds,
including successful empty results. It does not wait for unrelated targets. Pending
addition cursors rebase silently at that boundary; ready targets continue accepting
incremental fresh positives even while another provider/target fails. Full-only
absence reconciliation preserves these accepted cursor operations. See the
resilience substep 3b section of `DELIVERY_CONTRACT.md` for durable epoch semantics.

DHT obtains a durable begin token only after physical dispatch capacity is
reserved and before fetch. Reverification, checkpoint finish, source admission,
and history publication remain in the parent process. An unacknowledged timeout
or late potentially acquired observation preserves its exact pending token.
Only an explicit empty/discarded-evidence cancellation acknowledgment, or a
positively known not-started attempt, permits exact-token abort. Cleanup failure
keeps the durable fence; it does not strand an already-returned physical worker
or reset anti-rollback state.

After producer quiescence, a committed-but-unpublished finalized DHT checkpoint
can be decoded and restored before the next begin. The original lease/version,
current compatibility and exact durable checkpoint/pending state are rechecked
before publication. Restoration does not certify fresh complete coverage or
enqueue alerts; unknown or unfinalized tickets cannot be cleared by delivery retry.

## Force scheduling and stop

During a full scan, the pump can own one dequeued force envelope. The HTTP queue
is not drained into an additional backlog. Dispatchable target sessions receive
full/full/full/force entitlement, skipping unavailable classes without consuming
their turn. Same-target force work waits through source/history publication, not
through unrelated targets. Each force has its own reconciliation and one terminal
audit attempt; it never advances the scheduler's full-completion timestamp.

An owned force reserves terminal-audit capacity **before dequeue**. There is one
fixed worker and at most 17 total active/queued/reserved duties (one active or
reserved execution slot plus 16 waiting slots). A blocked audit retains its slot;
capacity refusal leaves later envelopes in their original bounded queue. Audit
I/O executes neither on the source pump nor on main's cleanup thread. Actor,
request and job identity travel with the original envelope. `_terminal_outcome`
records the one selected terminal attempt, not successful durable audit; the
worker retains ownership until the callback returns, including exceptions.
Direct owned-force calls also reserve before execution; on refusal the caller
retains its envelope. Legacy calls without a lookup owner remain synchronous.

Stop publishes its permanent latch before lookup/state/config/storage locks,
then fences the original repository publication path,
cancels unstarted work, and settles logical scan outcomes. One shared monotonic
three-second drain allowance covers lookup controller/provider and audit joins;
main passes only the remaining allowance to delivery shutdown. Zero-drain stop
and status do not wait for the lookup condition behind blocked history replace.
If bookkeeping cannot be sampled under its lock, status reports incomplete with
`bookkeeping_pending`; those counts are a non-atomic observation, not release.
`stopped` means the actual threads have retired, not merely that logical results
expired. The owner stays attached and refuses replacement even after an
incomplete stop. Repeated stop can observe eventual retirement.

Delivery workers are stopped regardless of lookup quiescence. `DeliveryRuntime.stop`
accepts `producers_stopped` and independently checks the attached lookup owner;
it cannot close the ledger while lookup producers/cleanup remain alive. Main logs
incomplete shutdown and retains the owner/ledger. Embedded owners can retry stop
and close only after actual retirement. Worker threads are daemon threads to
avoid executor interpreter-exit waits; process exit is **not** a graceful drain
or proof of cooperative callback cancellation.

The scheduler's stop latch precedes config-lock acquisition. If an owned source
admission holds that lock, queued force envelopes remain owned in the original
queue; a subsequent stop retries their terminal audits. Arbitrary blocking local
storage, audit hooks, native code, and OS scheduling cannot be forcibly interrupted.
The audit worker incrementally retires retained original-queue duties after actual
capacity release. Stop fences new admission and terminalizes reserved unfinished
jobs once as failure. Audit start failure leaves the original queue intact and
reports incomplete rather than spawning replacements. Main cleans signal/HTTP/
housekeeping resources before bounded source/audit draining and does not close
the live owner's ledger. Repeated stop can report completion after actual return.

The lock-free signal handler delegates to `scheduler.stop_and_wake` on the normal
signal coordinator thread. After publishing the stop latch and fencing, that
thread retains the condition-wake obligation until a contending config holder
releases the lock; it does not retry until audit retirement completes. The owned
scheduler's ordinary `stop()` remains nonblocking on config contention for pump
and audit-retirement callers. Bridge close retains its bounded join and reports
incomplete while the coordinator is still waiting; a wake is not proof of drain.

## Acceptance coverage

The implementation review artifact contains the ten-row matrix from design §7,
RED/GREEN logs, canonical XML, and exact source/preimage/postimage manifests.
Relevant persistent tests are `tests/test_lookup_{liveness,partial,deadline,
resources,force,authority,dht,controls}.py`. They use actual main/engine/repository
and ledger paths with synthetic collectors, Events, and monotonic clocks; they do
not contact provider DNS/RPC/DHT/C2/alert endpoints. Existing no-owner and local
loopback/browser regression fixtures remain separate compatibility controls.

The promoted `test_s2_accept_runtime_boundaries.py` and
`test_s2_accept_dht_shutdown.py` retain all 41 independent schedules; only the
candidate-root binding and nonbehavioral lint comments differ from the external
originals. `test_stage2_correction_{store,audit}.py` covers rollback versus storage
failure/ambiguous COMMIT, audit saturation, start failure, exact finalization and
shutdown races. These tests are acceptance evidence, not stage closure.

Stage-1 batching, public health/API schemas and UI are unchanged. The stage-3b
recovery extension above has focused producer/store/DHT regression coverage;
public saturation/partial-coverage presentation remains a stage-4 task.
Independent acceptance, integration, and deployed validation are separate gates.
