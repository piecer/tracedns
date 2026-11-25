# Optional AI assistance / 선택적 AI 보조

> Experimental, disabled by default. Controlled-protocol tests do not replace
> actual model, full-page and final canonical acceptance. Require the verification
> report for the exact revision and qualify your runtime before deployment;
> this operating guide is not itself an acceptance certificate. Provider/UI
> support has **not verified actual-model latency or usefulness**.
>
> 실험적 기능이며 기본값은 비활성화입니다. 통제된 응답의 테스트를 실제 모델·전체
> 화면·최종 검증으로 간주하지 마세요. 배포 전 정확한 리비전의 검증 보고서와
> 사용할 런타임의 적합성을 확인하세요. 이 운영 안내 자체가 수용 증명은 아닙니다.
> 제공자·UI 지원으로 실제 모델의 지연 시간이나 유용성을 검증한 것은 아닙니다.

TraceDNS keeps its deterministic analysis. AI proposes constrained decoder steps
or explains one selected, authorized snapshot; it cannot change verdicts, scores,
coverage, configuration or delivery state. This is not a new malware detector,
autonomous investigator, arbitrary chat endpoint or replacement for source evidence.

## Operations and permissions

| Kind | Input and result | Required role |
|---|---|---|
| `decoder_suggest` | One TXT/A kind, explicitly supplied data/expected IP samples; catalog recommendation and optionally one generated proposal | `admin` |
| `relationship_pair` | Exactly one pair in a completed successful, originally stamped relationship job | `operator` or `admin` |
| `delivery` | Separately captured cached diagnostics and progress; no new provider lookup | `operator` or `admin` |

An AI job belongs to both its originating user and its originating session.
Administrators cannot bypass this boundary. Another login of the same account
cannot recover an old session's result. At most one unfinished job per user is
admitted. Status/polling and background authorization do not extend session idle
lifetime. Explicit create/cancel requests retain ordinary authentication and CSRF.

Permissions, configuration/projection authority and source ownership are checked
before capture, at dispatch, before publication and on retrieval. Background
sweeps retire revoked or expired references without requiring another browser
poll. Already transmitted input and already displayed text cannot be recalled.

## Provider configuration and live settings

Two explicit profiles are available: native `ollama` and
`openai_compatible` Chat Completions. Existing Ollama behavior is retained;
compatible providers do not inherit its local-model/digest/CPU claims.

An administrator can open **Settings → AI provider** (`#settings-ai`) to Load,
edit and Save the provider, Base URL, model and server-outbound Bearer key.
The persistent service owner exists even when startup settings are absent or
disabled, so ordinary configuration changes need no TraceDNS restart. Save
performs no connectivity test, discovery or inference. Local runtime `ready`
is not evidence of provider reachability or model quality. Explicit AI actions
may transmit selected, secret-checked evidence to the configured destination;
holdouts remain excluded. Review the destination's retention policy yourself.

Omitting `local_ai`, or the following configuration, keeps inference disabled:

```json
{"local_ai":{"enabled":false}}
```

For an explicitly qualified local installation, the startup object is:

```json
{
  "local_ai": {
    "enabled": true,
    "origin": "http://127.0.0.1:11434",
    "model": "qwen3.5:9b",
    "model_digest": "REPLACE_WITH_THE_EXACT_64_LOWERCASE_HEX_MANIFEST_DIGEST"
  }
}
```

The placeholder intentionally fails validation. Obtain the exact full digest from
the runtime owner and its local model catalog; do not copy a digest from this
repository or use only a short prefix. Model name and digest must identify the
same installed model. The legacy startup `origin` spelling remains supported;
the UI and settings API use `provider=ollama` and `base_url`. Do not combine
`origin` with `base_url` or send `origin` in the settings API. The job request
cannot override its provider. Coordinate any operational restart with the
deployment owner; this guide does not authorize interrupting an existing service.

### Native Ollama profile

The native adapter accepts the Ollama chat/catalog protocol, local GGUF
format and the `qwen35` family/profile. It rejects cloud markers and digest drift.
It performs no downloads, model pulls, fallback, runtime stop/unload or model
replacement. Other native model families and custom templates are not
qualified by this adapter. Use the separate compatible profile for its protocol;
selecting it does not qualify a model's semantic behavior.

The origin must be an explicit loopback HTTP origin with a port: a numeric
loopback address, or the literal `localhost` mapped directly to `127.0.0.1`
without DNS. Credentials, query, fragment and paths (including a trailing slash)
are refused. There is no DNS resolution,
redirect following or environment-proxy routing. Configuring a loopback origin
alone does **not** prove that the runtime performs local-only inference: the
runtime owner must disable cloud operation, enforce its egress policy and keep
the model/template immutable while serving. Catalog identity is observed
configuration provenance, not cryptographic attestation of opaque execution.

Fixed generation policy: CPU only (`num_gpu=0`), four threads, `num_ctx=32768`,
`num_predict=512`, temperature zero, `think=false`, `stream=false`. A larger
configured context is not a measured throughput guarantee. The original
120-second job deadline includes queue wait, source preparation, inference and
verification. A slow runtime is refused; deadlines are not automatically raised.

`provider_state=ready` means the scheduler/interlock permits admission. It is not
a model-availability, semantic-quality or connectivity probe. Startup, panel
opening and status reads do not perform inference; the native catalog is checked
when an explicit generation is dispatched.

### OpenAI-compatible profile

This bounded profile requires nonstreaming Chat Completions and
`response_format={"type":"json_object"}`. It appends output-schema guidance to
the existing system message **before** privacy checking, byte admission and
the canonical commitment; the two-message structure and original verifier stay
authoritative. It does not assume portable strict JSON-Schema support. A service
calling itself compatible may still refuse the selected model/options or return
an unsupported response; failures are not converted into successful summaries.

The Base URL is an exact base prefix, such as `https://gateway.example.test/v1`,
not an already-appended `/chat/completions` URL. `public_https` requires HTTPS,
verified certificates/hostname and only globally routable DNS answers or numeric
addresses. `loopback` explicitly permits HTTP/HTTPS loopback literals or
`localhost`; self-signed TLS is not accepted. Private LAN destinations, embedded
credentials, query/fragment, ambiguous/encoded path components, redirects and
environment proxies are refused. Every DNS answer is vetted before one numeric
address is dialed. A timed-out lookup retains its one shared physical slot until
the worker actually exits; changing settings does not create a replacement slot.

There is one POST, with server-only `Authorization: Bearer …` when a key is
configured, `stream=false`, `n=1`, `store=false` and a 512-token output limit.
Select `max_completion_tokens` or `max_tokens` explicitly for your provider.
There is no automatic token-field fallback, temperature setting, model listing,
retry or model download. `store=false` is a request flag, **not** a guarantee of
the remote service's retention behavior. CPU/thread/context settings above are
native-only. The original job deadline and all validation/privacy limits remain.

### Settings API, keys and revisions

Admin-only `GET/POST /ai/settings` and `/api/v1/ai/settings` share the existing
web session, Origin, CSRF and audit controls. Outbound Bearer is **not** a new
TraceDNS login mechanism. `/settings` remains the alert-integrations route.
GET returns `revision`, public `settings` and `runtime`; it never returns the
key, only `configured.api_key`. POST uses a closed, nonempty `settings` patch
and the exact global revision loaded from GET. For example (replace all
placeholders and use your freshly read revision; this does not qualify a provider):

```json
{
  "revision": 0,
  "settings": {
    "enabled": true,
    "provider": "openai_compatible",
    "base_url": "https://gateway.example.test/v1",
    "model": "REPLACE_WITH_MODEL_ID",
    "endpoint_policy": "public_https",
    "token_limit_field": "max_completion_tokens",
    "api_key": "REPLACE_WITH_PROVIDER_KEY"
  }
}
```

- Omitted or blank key keeps the existing key only for the same provider, exact
  Base URL and endpoint policy. Changing that destination requires explicit
  replacement or top-level `clear_fields:["api_key"]`; equivalent-looking URL
  spellings are not silently normalized. A model/token-option change alone does
  not change the destination binding. Enabled public HTTPS requires a key;
  explicit loopback may be anonymous. Ollama does not accept a Bearer key.
- Missing/malformed revisions fail with 400; stale revisions return
  `config_revision_conflict` (409) and the current revision. Never silently rebase
  a draft or retry a mutation. AI and unrelated settings editors retain separate
  loaded revisions. Explicit Load discards/reconciles the old AI draft.
- Success includes `status=ok`, the new revision, public settings, runtime and
  closed warnings: `ai_runtime_apply_failed`, `ai_previous_call_draining`,
  `ai_provider_unsettled`. `runtime.applied=false` distinguishes a committed
  configuration from failed local application. Runtime states are `disabled`,
  `ready`, `draining`, `unsettled`, `unavailable`, `stopped`; none prove connectivity.
  A failed or lost acknowledgement is not proof of rollback: read back with GET.
- A writer exception is reconciled once, under the same serialized owner, without
  repeating the write. Exact candidate bytes establish the committed revision;
  unchanged pre-write bytes (including known absence) preserve the old revision
  and `config_save_failed`. An unprovable outcome returns
  `config_storage_unavailable` (503): settings GET and later configuration writes
  are refused, and old AI admission/publication is fenced. Readback is limited to
  regular non-symlink files of at most 8 MiB; unsupported shapes or read errors
  are not rollback proof. This is local file visibility, not crash durability or
  coordination with arbitrary external writers. Investigate the file offline
  before reconstructing the owner; no automatic retry or in-process fence reset
  is provided. Restart never clears the durable provider interlock.
- Retired jobs keep their original queued-finalization and task/lease ownership
  until cleanup acknowledges. One failing callback does not skip siblings.
  Cleanup/finalizer attempts are bounded to two per job, not renewed by Save;
  persistent failure keeps runtime unavailable and shutdown incomplete even
  when no worker remains. Terminal-audit failure retains the existing sticky
  audit failure policy, with no duplicate audit retry. A successful later Save
  can apply settings after one-shot cleanup recovery, but cannot release a
  still-running provider/DNS owner or clear durable quarantine.
- The success receipt is secret-checked against its own committed configuration
  and waits for completion audit. Audit unavailability fails closed. The owner
  fences new admission before releasing the configuration lock even if its
  post-replace publication callback fails. No old generation may publish through
  a configuration change, and physical work/quarantine is not reset by Save.
- The inert credential form has no native key field name. Every actual POST
  outcome clears only the submitted key-edit generation; later key edits survive.
  Logout/role loss/page retirement clear all secret edits and invalidate owners.
  Keys never enter generic draft signatures or local/session storage.
- Keys are stored server-side in the existing configuration file. Atomic replace
  uses an owner-only file and file fsync; this is **not encryption** or a claim of
  complete power-loss durability. Protect the config and backups. Public receipts,
  job results and audit records must not contain credential values.

## Decoder workflow

1. Select TXT or A and enter raw data with canonical expected IPv4 addresses.
2. Mark each row `example` or `validation`, and say whether its expected set is
   complete. Raw data is preserved, not trimmed or repaired.
3. Run catalog recommendation. `generate=false` never calls the model.
4. Explicitly request generation with `generate=true` when desired. This performs
   complete catalog verification first, then at most one proposal call—even if
   the catalog already contains a match. Incomplete verification prevents generation.
5. Inspect example and validation results separately, including missing,
   unexpected and unverified extra IPs. Candidates are ranked only by examples;
   generated candidates retain their fixed generation order.
6. Apply a qualifying candidate to the editor draft explicitly. This is not Save,
   registration, automatic Preview or a catalog/revision refresh. Review the
   draft and use the existing Preview and revision-checked Save separately.
   Conflicts require explicit review; never silently rebase or retry a mutation.

Validation rows, answers and evaluation feedback never enter the model prompt.
A candidate is frozen before holdout evaluation; there is no regeneration based
on holdouts. Distinct strings are not proof of independent observations. A sample
match is not generalization or proof of maliciousness. Without validation rows,
the absence of independent validation remains visible.

### Model-only decoder view

Generation retains the original example `snapshot` and its `snapshot_digest`.
Only the model prompt uses the deterministic `decoder_examples_utf8_v1` view:
at most **1024 raw UTF-8 bytes across all examples**, allocated in original row
order by repeated one-byte rounds to rows with data remaining. A row that fits
is unchanged. Otherwise it has `excerpt` instead of `data`:
`{original_utf8_bytes, prefix, suffix, omitted_utf8_bytes}`. The byte quota gives
roughly three quarters to the prefix and one quarter to the suffix, dropping
partial UTF-8 code points at each cut. The two segments stay separate; neither
joining them nor treating them as a complete sample is valid. Example order,
expected IP labels and `complete_expected` are preserved.

The required result sidecar `model_input` is **null for catalog-only** results
and populated for generation, including a proposal with no candidates. Its exact
fields are:

| Field | Meaning |
|---|---|
| `version`, `policy` | `1`, `decoder_examples_utf8_v1` |
| `source_snapshot_digest` | SHA-256 of the unchanged original example snapshot, not the view |
| `view` | `{version, kind, decoder_type, examples}` with complete or excerpted rows |
| `coverage` | `{original_utf8_bytes, shown_utf8_bytes, omitted_utf8_bytes, complete_examples, excerpted_examples}` |
| `messages_schema_bytes`, `messages_schema_digest` | Byte length and SHA-256 of the exact privacy-checked canonical `{messages, schema}` bundle |

Canonical commitments use sorted keys, compact JSON separators,
`ensure_ascii=False`, `allow_nan=False` and UTF-8. They cover the actual messages
and unchanged model-output schema, **not** the HTTP/native envelope, provider
options, model attention or runtime custody. Browser consistency checking is not
cryptographic attestation of inference. Byte limits are not token-count or
latency guarantees.

Inspect coverage and the omission warning before relying on a suggestion. The
exact model view and checked-bundle byte count/digest are available for explicit
disclosure; full sample bodies need not be expanded initially. Omitted content
may reduce inference quality or make a transformation impossible to infer.
There is no second generation, fallback or deadline increase to compensate.
Full original examples, expected sets and holdouts remain the verifier inputs;
holdout data, answers and feedback are never sent to the model. The original
input must pass privacy checks **before** projection, and the complete outgoing
messages/schema must pass again before dispatch. Excerpting cannot hide a
configured secret or make an oversized original admissible.

Only the generated DSL is newly restricted. Parameterless operations have exactly
`op`; `xor_hex` has `op,key` with nonempty even-length hex of at most 128 characters;
A `xor32_ipv4` has `op,key` with `0x` followed by eight hex digits. Generated regex,
arbitrary code, unknown operations and extra fields are rejected, never stripped
to manufacture success. Existing stored DSL/factory semantics are preserved.
Built-ins use their real defaults and `domain=None`; alternative keys,
domain-dependent branches and external key-extension datasets are not searched.
`ipv4_1423` remains a built-in only, not a new generated DSL operation.
Verification executes actual factories in a fresh owned subprocess, not a fork of
the threaded HTTP server or a pickled closure.

## Explanations and evidence

Relationship explanations use only the selected pair, not a whole cluster,
whole history or new enrichment request. Source identity was captured before the
original context preparation and checked again before original admission. Legacy,
unstamped, replaced, expired or hard-invalidated jobs cannot be backfilled with
current authority. All MISP-backed source jobs are excluded in v1; the ordinary
MISP/relationship workflows remain available unchanged. If auxiliary stamping
fails, ordinary analysis remains available but that result is AI-ineligible.

The browser must retain the completed job ID with its accepted result owner;
a transient active job ID is not provenance. Input changes, replacement,
authentication invalidation or navigation cannot attach an old callback to a
new selection. Opening a different source does not resume `status.active_job`.

Server facts, verdict, coverage warnings, analysis time and snapshot digest stay
separate from model interpretation. A source-category count is not an independent
origin count. Shared infrastructure is not attribution or proof of compromise.
Citations must identify existing evidence IDs in the exact snapshot; valid IDs
and JSON syntax do not prove that the cited facts support a model claim.

Delivery diagnostics and progress are separate cached reads with their own
capture times. Historical failure may coexist with later success. Unknown,
incomplete, stale or unavailable telemetry is not zero backlog or healthy
collection. Manual next checks can open corresponding retained evidence only;
models cannot provide executable commands, URLs or arbitrary action parameters.

### Deterministic facts versus AI interpretation

Every pair/delivery result requires `facts_summary`, derived once from the exact
original snapshot. Its closed fields are `{version, kind, language,
snapshot_digest, summary, counterpoints, limitations}`. Version is `1`; kind,
language and digest bind it to this job and its retained snapshot. Each claim is
exactly `{code, text, evidence_ids}`, with nonempty text of at most 512 UTF-8
bytes and specific snapshot fact citations. The whole sidecar is at most 6144
encoded bytes. These are server-owned statements, not model-selected IDs or an
extra copy of the summary sent to the model.

Mandatory codes occur **once, in this order**, even when telemetry is unknown:

| Kind | `summary` | `counterpoints` | `limitations` |
|---|---|---|---|
| `relationship_pair` | `pair_assessment`, `pair_signals` | empty array | `pair_scope`, `pair_coverage`, `pair_attribution` |
| `delivery` | `delivery_overview`, `delivery_teams`, `delivery_misp` | `delivery_recovery` | `delivery_snapshot_scope`, `delivery_capture_times`, `delivery_coverage`, `delivery_lookup` |

Read the deterministic facts and warnings before the separately labeled
**unverified AI interpretation**. `interpretation.version=1` remains the original
free-prose contract, including its existing manual `next_checks`; the new codes
are not added to that model-output schema. Valid JSON and citations cannot rule
out misleading prose, invented causal explanations or other semantic errors.
Fixed prompt guidance does not make free AI interpretation verified.

For pairs, preserve producer scores/verdict, observed signals, cached scope,
quality and attribution limitations; pipeline completeness does not establish
observation coverage. For delivery, preserve current captured state separately
from historical failures and later ACKs, recovery separately from absence state,
and event times separately from capture times. A later ACK does not prove a
failed receipt was repaired or overall health restored. Cached coverage and
freshness qualifiers remain visible; unknown is never silently converted to zero.

Retained prose keeps its capture language; switching the UI language must not
silently translate saved server text or model interpretation. A summary is not
independent publication authority: provider, output validation, source/owner,
deadline and terminal-audit failures still suppress the entire result.

Configured-credential redaction is used as a validation boundary before digest
and transmission: if it would change a key or value, the request is refused.
Samples and citation commitments are not silently sanitized. This is the existing
configured-secret policy, **not** a generic PII detector. Do not submit passwords,
tokens, sensitive personal data or unapproved operational evidence. Prompt/result
content is not written to the security audit stream. Active worker-local copies
cannot be securely recalled merely by dropping stored references.

## HTTP contract

Use the same authenticated session and Origin/CSRF handling as [API.md](API.md).
Keep one persistent client session through submission and polling. The one-shot
API CLI logs out after its request and therefore cannot own a later AI poll;
use a persistent `TraceDNSClient` instance instead of separate CLI invocations.
Both legacy and `/api/v1` routes reach the same service:

| Method | Path | Meaning |
|---|---|---|
| GET / POST | `/ai/settings` | Admin-only secret-free reads / revision-checked live configuration |
| GET | `/ai/status` | Local availability and only this session's active handle; no inference |
| POST | `/ai/jobs` | Explicit bounded request; HTTP 202 is admission, not success |
| GET | `/ai/jobs/{job_id}` | Owned state/result; polling does not refresh the session |
| POST | `/ai/jobs/{job_id}/cancel` | Empty JSON object; explicit best-effort cancellation |

Example requests:

```json
{"kind":"decoder_suggest","language":"en","decoder_type":"TXT","generate":true,"samples":[{"data":"MTkyLjAuMi4x","expected_ips":["192.0.2.1"],"usage":"example","complete_expected":true},{"data":"MTk4LjUxLjEwMC4xNw==","expected_ips":["198.51.100.17"],"usage":"validation","complete_expected":true}]}
```

```json
{"kind":"relationship_pair","language":"ko","source":{"job_id":"0123456789abcdef0123456789abcdef","a":"192.0.2.1","b":"192.0.2.2"}}
```

```json
{"kind":"delivery","language":"ko"}
```

The relationship ID above is illustrative, not an existing job. Supply an actual
completed eligible job and its exact selected pair. Job requests do not accept
client-supplied facts, model selection, endpoint or prompt overrides; provider
configuration belongs to the separate admin-only settings route.

A job includes `job_id`, `kind`, `language`, `status`, `created_at`, `deadline_at`,
`audit_status`, `error`, `result` and `cancel_requested`. Times are Unix integer
milliseconds. States are `queued`, `running`, `cancel_pending`, `completed`,
`failed`, `cancelled`. `audit_status` is `pending`, `success` or `failed`.
Do not use a result until `status=completed` **and** `audit_status=success`.
Terminal execution may still await audit; `result` stays null and the active
handle remains discoverable in that interval. A terminal HTTP 200 job can still
contain `error=audit_unavailable`; this is not successful assistance.

### Result compatibility and schema limits

All non-null results retain `snapshot`, `snapshot_digest`, `source_revision` and
`model`. Decoder results additionally require `catalog`, `generated`, `proposal`
and `model_input`; catalog-only `model`, `generated`, `proposal` and `model_input`
are all null. Explanation results instead require `interpretation` and
`facts_summary`. These alternative result envelopes and sidecars are closed:
missing, extra, malformed or foreign-kind fields are not a legacy fallback.
The same schema applies to create, read and cancel job responses.

`model` has separate closed native and compatible alternatives. Native retains
its observed model/digest and native counters. Compatible metadata requires
`provider=openai_compatible`, `requested_model`, `reported_model`, `finish_reason`
and `response_format=json_object`. Optional observed `prompt_tokens`,
`completion_tokens`, `total_tokens` are decimal int64 strings; missing counters
are omitted, not fabricated as zero. No native digest or timing is synthesized.
Requested/reported identity and counters are provenance, not execution attestation.

OpenAPI 3.1 / JSON Schema 2020-12 represents closed keys, scalar limits,
null/populated alternatives and mandatory ordered summary codes. It does **not**
replace the existing closed task/browser validators for retained catalog,
proposal, interpretation, metadata and fact contents. UTF-8/encoded byte caps
(`x-max-*` annotations), source/digest equality, canonical excerpt allocation,
coverage arithmetic, and code-specific fact citations require runtime checks.
`maxLength` alone counts characters, not UTF-8 bytes; an ID pattern alone cannot
prove that a fact exists or supports a claim. This change leaves the model v1
output schemas and generated operation set unchanged.

Unsupported or stale browser code must fail closed and require an explicit
reload to obtain matching assets; do not strip sidecars, accept an older shape,
silently widen a closed consumer or automatically resubmit generation. Retained
source ownership, authorization, generation/callback retirement and manual-only
draft/Save checks still apply.

The schema sources are `http_api/local_ai_schema.py` and
`http_api/ai_settings_schema.py`. Regenerate the checked-in
reference using the project procedure (from the repository root):

```bash
.venv/bin/python -m http_api.openapi > docs/openapi.json
```

`tests/test_local_ai_usability_schema.py` checks exact current pure-producer
sidecars, real decoder verification reports, malformed variants and byte-fresh
OpenAPI output. Its composed job envelopes are schema fixtures, not a claim of
HTTP publication, browser acceptance or actual-model performance. Those gates
require separate integration verification.

Errors use fixed `error`, `code` and `request_id` fields. Consult
[openapi.json](openapi.json) for the closed schemas and status codes. Distinguish
invalid input, source revocation, capacity, verification failure, invalid model
output, privacy failure, audit failure and unsettled execution. Do not reflect
provider/parser exception prose or automatically replay a failed POST.

## Budgets and retained state

| Boundary | Hard limit |
|---|---|
| HTTP input | 16 KiB; duplicate/unsupported framing refused before body read |
| AI settings receipt / Base URL / model / replacement key | 16 KiB / 1024 ASCII characters / 256 ASCII characters / 4096 visible ASCII characters |
| Samples | 6 rows; each raw value 2 KiB UTF-8; 1–8 canonical IPv4 addresses per row; at least one example; no duplicate raw input |
| Selected catalog | 32 total names; 32 KiB encoded definitions; no arbitrary prefix search |
| Original generation snapshot / model view | 8 KiB encoded each; oversized originals refused before excerpting |
| Decoder model raw-data view | 1024 UTF-8 bytes total; only long rows excerpted, no label truncation |
| Model-view labels / metadata | 1024 encoded bytes each; labels are the whole array of expected-IP arrays; metadata blanks raw data/segments and labels |
| `model_input` sidecar / metadata | 10240 / 2048 encoded bytes; metadata uses that blanked view |
| Checked canonical messages and schema | 16384 bytes (16 KiB); excludes HTTP/options |
| `facts_summary` / claim text | 6144 encoded bytes per summary; 1–512 UTF-8 bytes per claim |
| Provider request/response | 64 KiB each; framing separately bounded to 16 KiB |
| Model content | 16 KiB; generated JSON/schema validated separately |
| Verifier | 64 KiB stdin/stdout, 4 KiB observed stderr; catalog/generated phases each at most 5 seconds within original deadline |
| Provider work | One physical worker, two queued jobs, at most three concurrent preparations, one unfinished job per user |
| Job deadline | Original 120 seconds; queue/polls do not renew it |
| Public job | 32 KiB including envelope, facts, model metadata and result |
| Terminal retention | At most 32 records, 600 seconds and 1 MiB complete encoded records |
| Panel | Five candidates/facts per page, one mounted detail, six sample editors; bounded component DOM |

Six maximal samples can fit the HTTP limit but exceed the generation projection
limit. This is an explicit refusal, not a promise that every combination at the
individual field limits can run. Model metadata int64 counters are decimal strings
in browser JSON. Raw observations remain in their original authoritative stores;
AI retention is not an additional persistent history or prompt database.

## Cancellation, quarantine and recovery

A queued cancellation can be confirmed before inference. For running work,
cancellation suppresses publication but drains the original provider request; it
does not promise that the model stopped. Browser detachment is not authority to
kill a provider or to resume the job under another source.

Physical settlement and product-output acceptance are separate. A complete valid
native `done=true` envelope can settle capacity even when inner model JSON,
schema or content size is rejected. Timeout, partial/malformed/oversized native
envelopes and failed settlement auditing leave durable uncertainty. There is no
automatic replacement inference. Closing the local service can truthfully report
retained workers instead of pretending they disappeared.

For compatible responses, only a complete bounded supported completion or a
typed complete rejection can settle the exact job. Rejections 400/404/422 map to
`provider_request_rejected`, 401/403 to `provider_auth_failed`, and 429 to
`provider_rate_limited`, with audited `http_rejected` settlement. A job GET may
still be HTTP 200 with `status=failed`, a fixed `error` and `result=null`.
Provider authentication failure is not TraceDNS logout. Incomplete/late/timeout,
5xx and unsupported/uncertain responses do not authorize replacement inference.
No provider response body or exception prose is reflected to the user.

The security database keeps the `llm.provider` interlock through audit pruning
and restart. `llm.lifecycle` is a separate intent/terminal stream with fixed
metadata, not prompt/result text. Elapsed time, a model residency list, health
success or an application restart is not evidence that the earlier inference
stopped. The interlock covers this security-store deployment, not unrelated
clients of the same runtime.

Only after TraceDNS is stopped **and** the runtime owner has stopped the prior
inference may an authorized operator record the exact outstanding job's recovery:

```bash
python -m local_ai.recover \
  --security-db /path/to/existing/auth.sqlite \
  --job-id 0123456789abcdef0123456789abcdef \
  --confirm-tracedns-stopped \
  --confirm-provider-stopped
```

Replace the illustrative job ID with the actual outstanding ID from the provider
audit records. These flags are human attestations, not machine proof. The command
does not stop, unload or inspect a runtime and does not authorize killing borrowed
processes. There is no HTTP recovery endpoint. Never clear the interlock merely
to retry an uncertain request.

For a hosted compatible service, closing the client socket, clearing its key or
changing the endpoint is not proof that remote execution stopped. If the provider
owner cannot authoritatively establish termination, keep the interlock blocked;
do not assert `--confirm-provider-stopped` merely to resume work.

## 한국어 요약

- 기본 비활성화입니다. 관리자는 Settings의 AI provider(`#settings-ai`)에서 네이티브
  Ollama 또는 OpenAI-compatible을 선택하고 URL·모델·서버 발신 Bearer 키를 저장할 수
  있습니다. 정상 적용은 TraceDNS 재시작이 필요 없으며 저장 자체는 연결 검사·추론을
  하지 않습니다. Ollama는 기존 정확한 digest와 로컬 프로필을 유지합니다.
  루프백 주소만으로 클라우드 미사용이 증명되지는 않습니다.
- `/ai/settings` 및 `/api/v1/ai/settings`는 admin 전용 GET/POST입니다. Bearer는 제공자
  발신 인증이며 웹 로그인·세션·CSRF를 대체하지 않습니다. 공개 HTTPS는 검증된 TLS와
  전역 라우팅 주소만, 명시적 loopback은 루프백만 허용합니다. 사설 LAN·프록시·리다이렉트·
  자동 토큰 옵션 fallback은 없습니다. `store=false`도 외부 서비스의 무보존 보장은 아닙니다.
- 빈 키는 동일한 제공자·정확한 URL·정책에서만 유지됩니다. 대상 변경은 새 키 또는
  `clear_fields`가 필요합니다. 저장된 키는 화면에 반환하지 않고 서버 설정 파일에
  보관하므로 파일·백업을 보호하세요. 암호화 저장을 보장하지 않습니다. 리비전 충돌·
  저장 결과 미확인은 명시적 Load로 확인하고 자동 재시도하지 마세요. 저장 후에도
  `runtime.applied=false`일 수 있으며, 설정 변경으로 이전 추론의 격리를 해제하지 않습니다.
- 디코더는 `admin`, 관계 pair·전달 진단 설명은 `operator`/`admin` 권한이 필요합니다.
  관리자도 다른 사용자나 다른 로그인 세션의 AI 작업을 가져올 수 없습니다.
- 예제와 검증용 입력은 분리합니다. 검증 데이터와 정답·평가 결과는 모델에 보내지
  않으며, 결과를 보고 다시 생성하지 않습니다. 생성은 명시적 선택입니다.
- `model_input`은 카탈로그 전용 결과에서 필수 `null`, 생성 결과에서는 필수 객체입니다.
  모델용 예제 원시 데이터는 합계 1024 UTF-8 바이트 이내이며 긴 행은 앞·뒤 발췌를
  분리합니다. 생략으로 추론 품질이 낮아질 수 있습니다. 원본 예제·정답·holdout은
  그대로 검증하며 원본 스냅샷과 digest도 유지합니다. 발췌 전에 원본의 비밀 검사를 합니다.
  메시지·스키마 digest는 HTTP·옵션·실제 모델 실행의 증명이나 토큰·속도 보장이 아닙니다.
- 후보 적용은 초안만 변경합니다. Preview·저장·리비전 충돌 검토는 별도이며 자동
  등록이나 재시도는 없습니다. 샘플 성공을 일반화나 감염 증거로 해석하지 마세요.
- 관계는 원래 제출 시점의 권한을 기록한 완료 job의 선택 pair만 설명합니다.
  MISP 기반 결과, 기존 무표식 결과, 만료·권한 변경된 결과는 설명 대상이 아닙니다.
- 원래 판정·점수·관찰 범위는 유지합니다. 필수 `facts_summary`의 서버 사실·경고를
  먼저 읽고, 기존 `interpretation.version=1`의 검증되지 않은 자유 형식 AI 해석과
  구분하세요. 인용 ID가 유효해도 의미적 정확성이 보장되지는 않습니다. 저장된 문구의
  언어는 유지하며 UI 언어 변경으로 자동 번역하지 않습니다. 구형·비지원 브라우저는
  필드를 버리거나 재생성하지 말고 명시적으로 새로고침해야 합니다.
- 전달 진단은 캐시를 읽습니다. 과거 실패와 이후 성공, 수집·전달의 서로 다른
  관측 시각과 누락을 구분하며 설정이나 전송을 자동 실행하지 않습니다.
- HTTP 202는 접수이고 완료가 아닙니다. `completed`라도 `audit_status=success`
  전에는 결과를 사용하면 안 됩니다. 취소 요청도 실제 추론 중지를 보장하지 않습니다.
- 실행 종료가 확인되지 않으면 재시작 후에도 새 추론을 막습니다. 복구 CLI는
  운영자의 정지 확인을 기록할 뿐 실제 종료를 자동 증명하거나 런타임을 죽이지 않습니다.
- 120초 원래 기한, 입력·출력·대기열·보관 한도는 자동으로 늘어나지 않습니다.
  실제 모델과 현재 환경을 검증한 뒤 사용하세요.
