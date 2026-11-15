# Optional local AI assistance / 선택적 로컬 AI 보조

> Experimental, disabled by default. Controlled-protocol tests do not replace
> actual model, full-page and final canonical acceptance. Require the verification
> report for the exact revision and qualify your runtime before deployment;
> this operating guide is not itself an acceptance certificate.
>
> 실험적 기능이며 기본값은 비활성화입니다. 통제된 응답의 테스트를 실제 모델·전체
> 화면·최종 검증으로 간주하지 마세요. 배포 전 정확한 리비전의 검증 보고서와
> 사용할 런타임의 적합성을 확인하세요. 이 운영 안내 자체가 수용 증명은 아닙니다.

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

## Startup configuration

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
same installed model. These settings are startup-only, not browser-supplied
options or a live Settings update. Coordinate any restart with the deployment
owner; this guide does not authorize interrupting an existing service.

The initial adapter accepts the native Ollama chat/catalog protocol, local GGUF
format and the `qwen35` family/profile. It rejects cloud markers and digest drift.
It performs no downloads, model pulls, fallback, runtime stop/unload or model
replacement. Other providers, model families and custom templates are not
qualified by this implementation.

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

Only the generated DSL is newly restricted. Parameterless operations have exactly
`op`; `xor_hex` has `op,key` with nonempty even-length hex of at most 128 characters;
A `xor32_ipv4` has `op,key` with `0x` followed by eight hex digits. Generated regex,
arbitrary code, unknown operations and extra fields are rejected, never stripped
to manufacture success. Existing stored DSL/factory semantics are preserved.
Built-ins use their real defaults and `domain=None`; alternative keys,
domain-dependent branches and external key-extension datasets are not searched.
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
completed eligible job and its exact selected pair. Client-supplied facts, model
selection, endpoint and prompt overrides are not accepted.

A job includes `job_id`, `kind`, `language`, `status`, `created_at`, `deadline_at`,
`audit_status`, `error`, `result` and `cancel_requested`. Times are Unix integer
milliseconds. States are `queued`, `running`, `cancel_pending`, `completed`,
`failed`, `cancelled`. `audit_status` is `pending`, `success` or `failed`.
Do not use a result until `status=completed` **and** `audit_status=success`.
Terminal execution may still await audit; `result` stays null and the active
handle remains discoverable in that interval. A terminal HTTP 200 job can still
contain `error=audit_unavailable`; this is not successful assistance.

Errors use fixed `error`, `code` and `request_id` fields. Consult
[openapi.json](openapi.json) for the closed schemas and status codes. Distinguish
invalid input, source revocation, capacity, verification failure, invalid model
output, privacy failure, audit failure and unsettled execution. Do not reflect
provider/parser exception prose or automatically replay a failed POST.

## Budgets and retained state

| Boundary | Hard limit |
|---|---|
| HTTP input | 16 KiB; duplicate/unsupported framing refused before body read |
| Samples | 6 rows; each raw value 2 KiB UTF-8; 1–8 canonical IPv4 addresses per row; at least one example; no duplicate raw input |
| Selected catalog | 32 total names; 32 KiB encoded definitions; no arbitrary prefix search |
| Generation projection | 8 KiB; excess combinations rejected, not truncated |
| Encoded prompt and schema | 16 KiB |
| Provider request/native response | 64 KiB each; framing separately bounded to 16 KiB |
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
cancellation suppresses publication but drains the original native request; it
does not promise that the model stopped. Browser detachment is not authority to
kill a provider or to resume the job under another source.

Physical settlement and product-output acceptance are separate. A complete valid
native `done=true` envelope can settle capacity even when inner model JSON,
schema or content size is rejected. Timeout, partial/malformed/oversized native
envelopes and failed settlement auditing leave durable uncertainty. There is no
automatic replacement inference. Closing the local service can truthfully report
retained workers instead of pretending they disappeared.

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

## 한국어 요약

- 기본 비활성화이며 관리자가 시작 설정으로 로컬 런타임과 정확한 모델 digest를
  지정합니다. 루프백 주소만으로 클라우드 미사용이 증명되지는 않습니다.
- 디코더는 `admin`, 관계 pair·전달 진단 설명은 `operator`/`admin` 권한이 필요합니다.
  관리자도 다른 사용자나 다른 로그인 세션의 AI 작업을 가져올 수 없습니다.
- 예제와 검증용 입력은 분리합니다. 검증 데이터와 정답·평가 결과는 모델에 보내지
  않으며, 결과를 보고 다시 생성하지 않습니다. 생성은 명시적 선택입니다.
- 후보 적용은 초안만 변경합니다. Preview·저장·리비전 충돌 검토는 별도이며 자동
  등록이나 재시도는 없습니다. 샘플 성공을 일반화나 감염 증거로 해석하지 마세요.
- 관계는 원래 제출 시점의 권한을 기록한 완료 job의 선택 pair만 설명합니다.
  MISP 기반 결과, 기존 무표식 결과, 만료·권한 변경된 결과는 설명 대상이 아닙니다.
- 원래 판정·점수·관찰 범위는 유지하고 AI 해석은 따로 표시합니다. 인용 ID가
  유효하다고 주장의 의미적 정확성이 보장되지는 않습니다.
- 전달 진단은 캐시를 읽습니다. 과거 실패와 이후 성공, 수집·전달의 서로 다른
  관측 시각과 누락을 구분하며 설정이나 전송을 자동 실행하지 않습니다.
- HTTP 202는 접수이고 완료가 아닙니다. `completed`라도 `audit_status=success`
  전에는 결과를 사용하면 안 됩니다. 취소 요청도 실제 추론 중지를 보장하지 않습니다.
- 실행 종료가 확인되지 않으면 재시작 후에도 새 추론을 막습니다. 복구 CLI는
  운영자의 정지 확인을 기록할 뿐 실제 종료를 자동 증명하거나 런타임을 죽이지 않습니다.
- 120초 원래 기한, 입력·출력·대기열·보관 한도는 자동으로 늘어나지 않습니다.
  실제 모델과 현재 환경을 검증한 뒤 사용하세요.
