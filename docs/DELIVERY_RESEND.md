# Resend one target's current managed IPs

An **admin** can choose **Settings → Domain settings → Resend current IPs** on a
saved A, TXT, ENS, SNS, DHT or RPC target card. This deliberately sends the
current managed IPs again to the selected saved Teams and/or MISP integrations.
It is not a force lookup, queue reset, history deletion, or retry of failed items.
For RPC, only decoded C2 IPs are eligible; ciphertext and auxiliary roles are not.

## Preview, then confirm

1. Save or reload edited settings first. New unsaved rows have no resend action.
   The action uses the saved card identity and loaded configuration revision,
   never the edited name, decoder, destination, credentials or a browser IP list.
2. Select one or both channels (both start selected), then choose **Preview**.
   Preview performs no provider calls. Disabled, unapplied, unavailable or
   authentication-blocked destinations are refused rather than bypassed.
3. Review the **entire** accepted IP list, selected channels, source type and
   observation timestamp. At most `min(256, store.unit_items)` IPs are accepted;
   an over-budget snapshot is refused, not truncated. The displayed timestamp
   is source evidence, not a live lookup or a promise of freshness/reachability.
   The warning **“Last-good/current saved observation; no live lookup”** always
   applies, including when `retained` is false. `retained` warns that last-good
   data may be retained or freshness/latest success is not established.
4. Choose **Confirm resend** only for a deliberate duplicate. Changing channels
   invalidates the displayed intent and requires another preview. Cancel before
   confirmation clears the local preview and queues nothing. Unused server
   intents expire; cancellation is not a server-side revoke operation.
5. **Queued** means durable queue admission, **not** provider ACK or human receipt.
   Use the existing **Delivery health** and **Delivery diagnostics** panels to
   inspect subsequent aggregate delivery state. They are not per-request status
   endpoints or proof that a human received the notification.

Only one modal and one request are active in the page. Buttons prevent ordinary
double submission. Each request has the shared 15-second authentication/network/
body-decoding lifetime. There is **no automatic POST retry**. Cancelling during
confirmation, timeout, malformed results or transport failure can leave the
admission outcome **unknown**: the server may already have committed work.
The page keeps an uncertainty warning and disables further resend actions.
Check diagnostics and destination state before deciding on another deliberate
send; a new preview is **not** a safe retry of an ambiguous confirmation.

## Closed HTTP API

Both legacy and versioned routes use the same authentication, current-account
RBAC, Host/Origin, CSRF and durable pre-action audit boundary:

- `POST /delivery-resend/preview`
- `POST /api/v1/delivery-resend/preview`
- `POST /delivery-resend`
- `POST /api/v1/delivery-resend`

Viewer/operator requests are forbidden. Session revocation and forced password
change still apply. No GET/PUT/PATCH/DELETE resend operation is mounted.
The initial security body reader enforces **4096 bytes** (or a smaller configured
limit). JSON objects must have unique keys and exactly the documented fields.
Framing/oversize/security errors retain the shared error contract, including
text/plain 400/413 and a possibly empty worker-capacity 503.

Preview request:

```json
{"target":"saved.example","channels":["teams","misp"],"revision":7}
```

`target` is the exact **canonical configuration identity** produced by
`config_manager.domain_identity` (the UI uses `domainConfigIdentity` on the saved
card). It is not a storage label or arbitrary hostname to resolve. Ordinary DNS
uses its normalized name; ENS includes text key/node/resolver, SNS its text key,
DHT its public key, and RPC its profile. For example the RPC identity is
`label|RPC|polygon_aes_gcm_v1`. Preserve the complete identity from the saved
configuration; do not guess a bracketed storage name from a display label.
`channels` is a unique nonempty array of `teams` and/or `misp`; `revision` is an
integer in `0..9007199254740991`, never Boolean.

Every preview response includes exactly:

```text
status: ready | not_ready
reason: null | fixed reason below
request_id: null | 32 lowercase hex characters
target: string | null                 (canonical configuration identity)
source_type: A | TXT | ENS | SNS | DHT | RPC | null
ips: array of IP strings              (0..256, complete accepted list)
observed_at: integer | null           (UTC epoch seconds)
retained: boolean
channels: array of teams/misp
expires_in_seconds: integer 0..300
retry_after: integer 0..30 | null
```

Confirmation request is exactly `{"request_id":"<32 lowercase hex characters>"}`.
The actor is always the authenticated principal's `id`, never a body field.
Every confirmation response includes exactly:

```text
status: queued | already_queued | not_queued | unknown
reason: null | fixed reason below
request_id: null | 32 lowercase hex characters
ip_count: integer 0..256
receipt_count: integer 0..512         (IP × selected destination obligations)
channels: array of teams/misp
retry_after: integer 0..30 | null
```

| HTTP | Outcome / reason |
|---|---|
| 200 | Preview `ready`, or confirmation `already_queued` with original counts and no new work |
| 202 | Confirmation `queued` after durable commit/readback, not delivered |
| 400 | `invalid_request`, or a common validation/framing error |
| 404 | `target_not_found` |
| 409 | `no_managed_ips`, `snapshot_changed`, `configuration_changed`, `preview_expired`, `delivery_pending`, `destination_unavailable` |
| 429 | `preview_capacity`, `resend_cooldown` |
| 503 | `delivery_capacity`, `delivery_storage`, `runtime_unavailable`, or `unknown/delivery_unknown`; common security/audit/capacity errors may instead use the normal error body |

`Retry-After` is emitted only for a validated `retry_after` in `0..30`.
No provider prose, URL, credential or exception text is returned. Unknown internal
fields are projected away. Malformed confirmation results or exceptions after
invocation become `unknown/delivery_unknown`, not a claim that admission failed.
The feature's closed DTO bypasses generic secret substitution so coincidental
secret/enum collisions cannot corrupt status fields. The shared frontend wrapper
preserves bodies **only** on these resend POST paths for 400/404/409/429/503;
ordinary fetch errors and authentication/CSRF denials are unchanged.

## Runtime ownership and limits

The HTTP facade calls:

```python
runtime.preview_resend(target, channels, expected_revision, actor_id=principal['id'])
runtime.resend_target(request_id, actor_id=principal['id'])
```

The runtime, not HTTP or JavaScript, selects the source under configuration →
repository → state ownership and binds the intent to the actor, target incarnation,
revision, exact source evidence and destination bindings. In-memory previews have
300-second monotonic TTL and capacity 128; restart loses unused previews. Confirm
revalidates immediately before admission. A changed or expired intent is refused,
not silently rebuilt from unseen data.

All selected destination receipts and the request marker are admitted atomically
or none are admitted. Existing pending/blocked work is refused; attempts, retries
and provider-auth blocks are not reset. Same actor/token confirmation can return
`already_queued` across restart and terminal receipt cleanup while its durable
marker is retained. Markers are bounded to 256 with 24-hour retention; capacity
exhaustion is a refusal, not live-marker eviction. An old token without its marker
and original preview is not new admission authority. A durable 30-second per-target
cooldown covers both channels and survives restart.

The existing worker uses Added semantics with immutable saved bindings. Teams can
produce a deliberate duplicate; MISP uses the existing idempotent add/existing
observation behavior. Admission does not change current observations, history,
cursor, recent/reappearance state, failed-addition exceptions, full baselines or
removal grace. Automatic dedupe/grace is not deleted to authorize this action.

## Audit and evidence

Actions remain `post:/delivery-resend/preview` and `post:/delivery-resend` for both
route families. A durable `started` event precedes runtime invocation; terminal
outcomes are `ready`, `not_ready`, `queued`, `already_queued`, `not_queued` or
`unknown`, not “delivered”. The preview event target is the canonical target;
confirmation targets the resend token. The strictly validated `details.resend_id`
links both events, alongside server-derived actor and independent HTTP request ID.
These are ledger requests, **not** fabricated security asynchronous jobs.
A terminal audit write failure returns 503 rather than exposing successful
admission without that audit; already-committed queue work cannot be rolled back
by the HTTP response, so clients must treat that response as ambiguous.

`http_api.delivery_resend` owns request/result schemas; `http_api.openapi` and
`docs/openapi.json` are generated-equivalent. Focused real loopback HTTP tests use
an injected runtime protocol seam and verify security, audit and DTO handling;
they do not prove backend admission. Node tests execute the shipped widget and
actual auth wrapper with synthetic HTTP responses. Real runtime/ledger/worker and
browser integration are separate gates. None of these tests require live Teams,
MISP, RPC, C2 contact or production configuration.
