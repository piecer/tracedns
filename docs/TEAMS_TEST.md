# Manual Teams test (actual send)

An **admin** can use **Settings → Alert integrations → Send real Teams test**
next to the Teams webhook field. This is a real outbound request, not a simulation
or a retry of queued alerts. The confirmation explicitly warns that only saved,
applied settings are used. Unsaved webhook/message fields are never submitted.
Save and then load settings before testing changes. The button is unavailable
until a valid settings revision has loaded; a failed reload disables it.

The button permits one outstanding action, shows a sending state, and waits at
most 15 seconds across authentication, transport and response-body decoding.
There is **no automatic retry**. A browser timeout or network failure does not
cancel a send already admitted on the server. Check Teams before sending again.
The server independently allows one in-flight test and enforces a 30-second
monotonic cooldown after an admitted send completes, including a failed send.
Other administrators share this process-local gate.

## API

`POST /teams/test` and `POST /api/v1/teams/test` use the same handler and require
an admin session, the existing CSRF token and exact Origin. Viewer/operator
requests are denied. No GET, PUT, PATCH or DELETE send operation is supported.
The body must be exactly `{"revision": 7}` where `7` is the saved settings snapshot
revision, an integer in `0..9007199254740991`, never a Boolean. Missing, extra or
duplicate fields, invalid JSON, strings and fractional revisions are rejected
with 400 before any runtime/provider call. Existing framing/body limits apply.
No webhook, credential, message, destination or draft config is accepted.

The handler calls `ctx.config_service.delivery_runtime.test_teams(revision)`.
Missing runtime yields `not_sent/runtime_unavailable`, never synthetic success.
The exact result fields are:

- `status`: `accepted`, `failed` or `not_sent`.
- `reason`: null, a fixed delivery reason, `test_in_progress`, `test_cooldown`,
  `configuration_changed` or `runtime_unavailable`.
- `retry_after`: null or an integer in `0..30` seconds.
- `diagnostic`: the existing closed provider diagnostic with `operation`,
  `http_status`, `response_bytes`, `response_limit`, `attribute_count`,
  `attribute_limit`, `tls_kind`, and `tls_verify` (see `DELIVERY_DIAGNOSTICS.md`).

| HTTP | Result | Operator guidance |
|---|---|---|
| 200 | `accepted` | Provider accepted the test; not proof of human receipt/read. |
| 502 | `failed` | Read the fixed reason and HTTP/TLS evidence. Timeout, transport error, `delivery_unknown`, or inability to validate a 2xx response mean delivery may have happened. The UI preserves the fixed failure reason and warns to check Teams before repeating the send. |
| 429 | `not_sent`, `test_in_progress` or `test_cooldown` | Wait for the existing send/cooldown; click manually only if another test is needed. `Retry-After` is sent only when `retry_after` is present. |
| 409 | `not_sent`, `configuration_changed`, `destination_disabled`, `destination_invalid`, `adapter_unapplied` or `configuration_unavailable` | Review saved/applied settings and use **Load Alert Settings** before testing again. |
| 503 | `not_sent`, `runtime_unavailable` | Runtime unavailable; contact the administrator. |
| 400 | Fixed request error | Supply only a valid revision; no send occurred. |

Authentication, origin, CSRF, audit, framing and worker-capacity failures retain
the existing server error contract (including a possible empty saturation 503),
not a fabricated test result. If a runtime call throws or returns malformed
required data, HTTP reports `failed/delivery_unknown`: it cannot prove no send.
Extra internal result fields are projected away. Output contains only validated
fixed grammar and bounded primitive evidence; no endpoint, provider body,
credential, path or raw exception. This narrow boundary bypasses generic secret
substitution so a credential coincidentally matching an enum cannot corrupt the
wire schema. All other response handling stays unchanged.

The frontend uses the normal authenticated fetch wrapper and CSRF handling.
Only manual-test POST responses with 409/429/502/503 preserve their bodies for
closed-result rendering; ordinary requests retain their existing error behavior.
Unrecognized/error bodies display unknown outcome without reflecting their text.

## Delivery isolation

The runtime captures the ready immutable Teams adapter from the saved applied
configuration, including INI provenance, while checking the expected revision.
Disabled, invalid or unapplied configurations make no provider request. The
config lock is released before network I/O. The adapter sends a fixed benign
TraceDNS manual-test message, with no monitored IOC/IP/host data, through the
existing verified TLS, no-redirect and response-limited transport.

Tests do not append delivery ledger items, change normal ACK/failure counters,
or add diagnostic-history records. Existing alert delivery/retry behavior is
unchanged; a successful manual test does not replay failed queued alerts.

The generated schema is in `docs/openapi.json` (`http_api.teams_test` owns the
request/result schemas). Loopback HTTP tests with an injected runtime and Node
UI/auth harness tests are separate from trusted local HTTPS plus real-browser
integration. Neither test setup claims delivery to a live Teams channel.
