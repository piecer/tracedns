# Delivery diagnostics (read-only, version 1)

`GET /delivery-diagnostics` and `GET /api/v1/delivery-diagnostics` require an
**operator or admin** session. Viewer/anonymous access is denied; no write method
is supported. The endpoint reads `DeliveryStore.diagnostics_snapshot()` only:
no delivery-ledger SQL, disk read, provider request, probe, replay, configuration
change or queue mutation is initiated by this read. Normal authentication and
audit processing still apply. Existing `/delivery-health` fields and behavior are
unchanged. The separate admin-only **Send real Teams test** button in Alert
integrations does perform an explicit outbound send; see `TEAMS_TEST.md`.
Its result does not change this cached diagnostic history or normal delivery
counters, and does not replay failed alerts.

## Reading the evidence

- Health `last_error` prioritizes the **oldest blocked** item. It is not a latest
  attempt log. Compare each channel's `latest_result` and `latest_failure`;
  a successful later result does not erase the latest retained terminal failure.
- `recent_failures` contains at most **10 retained terminal failure groups**,
  latest first, **not cumulative failure counts**. `items` gives each group's
  number of affected destination-items. Do not sum this list as total failures
  or total loss. Use health accounting and its completeness flags separately.
- `blocked_by_reason` contains cached current blocked-item counts, at most 64
  entries per channel. This is not a list of provider error messages.
- Null result/detail fields mean **unknown/not recorded**, including older
  records without new provider evidence. They do not prove zero or success.
- `response_bytes` is the observed decoded byte count; `attribute_count` is the
  observed attribute count. On rejected/truncated reads they are **lower bounds**,
  not promised complete response sizes. Corresponding limits remain enforced.
- `storage_error` is the **latest observed incident in this process**, volatile,
  not persisted and **not necessarily still active**. It has an incident time,
  fixed stage and fixed code. A null incident cannot rule out an earlier process
  failure. Read `storage_ok`, `worker_running`, `coverage`, `counts_stale`, and
  `observed_at` together. Degraded valid cache remains HTTP 200; absent, malformed
  or over-budget cache returns 503, not fabricated empty success.
- Failed items are **not automatically replayed**. Refresh and download do not
  retry, restart, rebind or acknowledge anything. Existing scheduled worker
  retries of admitted retryable work are a separate mechanism.

## Console

The separate **Delivery diagnostics** section loads nothing until **Read
diagnostics** is clicked. **Refresh diagnostics** performs another bounded read;
there is no polling. **Cancel read**, leaving the page or hiding the tab cancels
an active read. A ten-second deadline covers auth wait, transport and body.
Failures keep a clearly stale last successful snapshot; permission denial or
session expiration clears it. Explicit refresh can recover from transient auth
or transport failures. The evidence panel separates latest result, latest terminal
failure, blocked reasons, recent groups, process incident and worker state.

**Download sanitized JSON** exports only the validated closed snapshot, never a
raw provider response or HTTP error body. Its fixed filename contains no target
identifier. Integer values outside JavaScript's safe range display **precision
unavailable**, not a rounded count or date; the JSON export preserves their exact
wire integers. A stale download is still the prior successful snapshot, with its
original observation time, not a fresh observation.

## Next checks (no automatic remediation)

| Evidence | Check |
|---|---|
| TLS / certificate verification | CA trust chain, hostname, expiry and configured CA file readability. Keep verification enabled. |
| HTTP 302 | Direct provider endpoint and reverse-proxy routing. Redirects are not followed. |
| Response / attribute / work cap | Provider response/event scope and configured limits. Do not bypass caps. |
| Provider auth | Credentials and least-privilege authorization; never paste credentials into diagnostic reports. |
| Timeout / transport / rate limit / unavailable | Provider connectivity and availability. This panel performs no network probe. |
| Old binding / configuration | Destination change and applied settings; do not assume automatic rerouting. |
| Storage incident | Local free space, permissions, exclusive ownership, integrity and operator logs. Do not delete the ledger. |
| Worker stopped / exception | Process lifecycle and local logs. The diagnostics UI cannot restart the worker. |

## Closed wire schema

The exact schema is generated from `http_api.delivery_diagnostics.DIAGNOSTICS_SCHEMA`
in `docs/openapi.json`. Every object is closed; extra internal cache fields are
projected out without traversal. Invalid required values fail closed. Arbitrary
exception/provider text, URLs, paths, IDs, headers, response bodies and credentials
are never public fields. Success output contains only fixed grammar, booleans,
nulls and bounded integers. It deliberately bypasses generic credential string
substitution after projection so coincidental secret/enum matches cannot rename
the schema; other endpoints retain their existing response handling.

Root fields: `version` (1), `observed_at`, `counts_stale`, `storage_ok`,
`worker_running`, `coverage`, `storage_error`, `channels` (`teams`, `misp`),
`recent_failures`. Every count is an integer in `0..2^63-1`, never a Boolean.
A record contains `at`, `channel`, `state`, `reason`, `attempt`, `items`,
`diagnostic`. Its diagnostic contains `operation`, `http_status` (null or 100–599),
`response_bytes`, `response_limit`, `attribute_count`, `attribute_limit`,
`tls_kind` and `tls_verify`. Process incident fields are `at`, `stage`, `code`.
Successful serialized output is bounded to **32768 UTF-8 bytes**, including the
nonempty nested arrays. No delivery policy or provider limit changes are implied.
