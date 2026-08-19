# Code Review

Current-code review against `master` at `793757c`. Findings are ordered by priority and intended fix order. No P0 issue was confirmed. Existing untracked user files are outside this review.

## P1 — High

### 1. HTTP administration API listens on every interface by default

- Evidence: `dns_monitor.py:198` starts the HTTP server with `0.0.0.0`; the server exposes configuration and state-changing routes without authentication.
- Impact: a default deployment reachable from another host permits remote configuration changes and can expose configured integration data.
- Fix/test: default to `127.0.0.1`, provide an explicit `--http-host` override, and cover both parser behaviours.

### 2. History filenames accept path separators from domain-derived keys

- Evidence: `history_manager.py:34-37`, `history_manager.py:67-69`, and `history_manager.py:87-90` construct paths directly from `domain`; callers can use user-controlled configuration names.
- Impact: a crafted domain such as `../target` can read, write, or delete JSON outside `history_dir`.
- Fix/test: centralize a safe filename transformation that cannot escape the directory; test traversal and normal domain names.

### 3. Regex safety module fails to import on supported Python versions

- Evidence: `regex_safety.py:23-25` imports private `re._parser`, which is absent on the current Python 3.10 runtime; `make test` fails while importing `tests/test_regex_safety.py`.
- Impact: startup/import of decoder modules fails, and the complete test suite cannot run.
- Fix/test: use the public compatibility surface available across supported Python versions (with a guarded fallback) and retain the existing ReDoS regression suite.

### 4. Configuration persistence failures are hidden and runtime state is mutated first

- Evidence: `config_manager.py:77-83` catches write exceptions and returns no status; `http_api/config_post.py:57-104` mutates shared state before attempting persistence, so its `try/except` cannot detect the real writer failure or roll back. `http_api/settings_handlers.py:105-131` likewise returns success after logged save failure.
- Impact: clients receive success while changes disappear after restart; memory and disk can silently diverge.
- Fix/test: make writes atomic and exception-transparent, persist a candidate before publishing it to shared state, and return HTTP 500 without changing runtime state on failure.

### 5. Domain removal can race with an active monitor cycle

- Evidence: `monitor/engine.py:202-205` reads domain maps outside `_STATE_LOCK`; later `monitor/engine.py:248-255` writes `current_results[name][srv]` after an API removal can delete `name`.
- Impact: concurrent configuration updates can raise `KeyError`, abort a cycle, or recreate partial stale state.
- Fix/test: keep lookup/update under the state lock and tolerate removal; reproduce deletion between collection and commit.

### 6. MISP TLS verification is disabled

- Evidence: `alerts.py:109` initializes `PyMISP(..., False)` and `http_api_handlers.py:1861-1866` sends API credentials with `verify=False`.
- Impact: MISP API keys and responses are exposed to man-in-the-middle attacks.
- Fix/test: verify TLS by default, add an explicit opt-out setting only if required, and test constructor/request arguments.

## P2 — Medium

### 7. Teams webhook reports HTTP failures as success

- Evidence: `alerts.py:185-187` ignores the response status and returns `True` for 4xx/5xx responses.
- Impact: alert delivery failures are silent.
- Fix/test: call `raise_for_status()` (or inspect status) and return false on HTTP errors.

### 8. UI advertises DNS record types the backend queries as A records

- Evidence: `dns_frontend.js:2460-2461` offers `AAAA`, `CNAME`, `MX`, `NS`, `SRV`, and `CAA`; `dns_query.py:44-76` performs TXT only for `TXT` and A for every other type; `monitor/collect.py:127-137` labels all non-TXT DNS snapshots as A.
- Impact: displayed type and queried data disagree, producing incorrect monitoring results.
- Fix/test: either implement generic record querying/typing or restrict the UI; add contract tests for each supported type.

### 9. Extracted settings POST bypasses the shared request-size limit

- Evidence: `http_api/settings_handlers.py:52-54` reads attacker-controlled `Content-Length` directly instead of `http_api.request_limits.get_request_body`.
- Impact: this route can still allocate/read an oversized request even though other extracted routes are bounded.
- Fix/test: use the shared limiter and verify an oversized settings request returns 413 without reading the payload.

### 10. JSON string `"false"` enables VirusTotal enrichment

- Evidence: `http_api/relationship_handlers.py:787-798` defines a strict boolean parser but line 804 uses `bool(data.get(...))` for `include_vt`.
- Impact: clients intending to disable paid/remote enrichment can unexpectedly trigger up to thousands of external lookups.
- Fix/test: parse `include_vt` with the existing helper and cover boolean and string forms.

### 11. Thread-per-request server has no concurrency bound

- Evidence: `http_server.py:71` subclasses `ThreadingHTTPServer` without limiting active handlers.
- Impact: many slow connections can exhaust threads/file descriptors even with bounded bodies.
- Fix/test: add a bounded request semaphore or worker pool and test that excess concurrent requests are rejected or queued safely.

## P3 — Low / test quality

### 12. ENS corpus regression test silently skips when its fixture is absent

- Evidence: `tests/test_ens_decoder.py:54-59` skips if `docs/ens/betavpn-network-full-decoder.json` is missing; the fixture is absent from current HEAD.
- Impact: a high-value decoder compatibility test does not run in normal CI.
- Fix/test: restore a licensed compact fixture or make the corpus an explicit CI artifact; avoid a silent permanent skip.

## Additional findings received from the asynchronous clean-tree audit

The following findings were reproduced against `793757c` by the delayed
read-only audit and remain reachable after the fixes above. They are ordered
by impact and will be remediated in this order.

### P1 — Asynchronous relationship jobs have no admission bound

- `http_api/relationship_handlers.py` accepts every submission into a global
  job map and `ProcessPoolExecutor` queue. Pending payloads and metadata can
  therefore grow without limit.
- Add a fixed running-plus-pending limit, reject excess submissions, and test
  with a non-completing executor.

### P1 — ENS and SNS targets with the same name/key collide

- `config_manager.domain_identity()` and `domain_storage_name()` label both
  target types as ENS. Normalization drops one target and runtime state can
  overwrite the other.
- Include the actual target type in both identities and storage keys.

### P1 — SNS collection ignores the configured record key

- `monitor/collect.py` always calls a TXT-only SNS helper and `sns_query.py`
  always builds a `/TXT` endpoint although configuration preserves
  `ens_text_key` for SNS targets.
- Pass a validated/URL-encoded configured record key through collection.

### P2 — Implemented settings and decoder update/delete routes are unwired

- `POST /settings` returns 404, while `PUT` and `DELETE /decoders/custom`
  fall through to the base handler's 501 response.
- Wire the delegated handlers with the common request limit and verify the
  real handler method contract.

### P2 — No-op ENS/SNS config saves purge live state

- `http_api/config_post.py` compares raw configured names with decorated
  runtime storage keys, classifying retained ENS/SNS state as orphaned.
- Compare canonical `domain_storage_name()` values and test no-op saves.

### P2 — Force-resolve requests overwrite one shared slot

- Each `/resolve` request replaces `_force_resolve`; multiple accepted
  requests before the next monitor cycle silently lose all but the last.
- Use a bounded FIFO and return an explicit overload response when full.

### P2 — Transient VirusTotal failures are cached as authoritative negatives

- `vt_lookup.get_ip_report()` stores `None` after timeouts and HTTP failures,
  suppressing retries for the full normal cache TTL.
- Do not cache transient failures; test first-failure/second-success behavior.

### P2 — Domain settings payload fields are ignored

- `/config` ignores `ens_rpc_url` and `DEFAULT_SNS_PROXY_HOSTS` sent by the
  frontend while still returning success.
- Persist validated values and cover the frontend payload round trip.

### P3 — Canonical unittest discovery skips function-style decoder tests

- `tests/test_a_decoder.py` contains pytest-style top-level tests that
  `unittest discover` does not collect.
- Convert them to `unittest.TestCase` so `make test` executes them.
