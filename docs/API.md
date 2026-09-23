# TraceDNS REST API v1

외부 프로그램과 AI는 `https://<public-origin>/api/v1`을 사용한다.
기존 UI의 `/config`, `/results` 등 비버전 경로는 그대로 동작하며 같은 설정,
관측 상태, 세션, RBAC, 감사 저장소를 공유한다. 별도 서버나 DB를 만들지 않는다.
외부 제어 범위는 관제 대상/설정/디코더/분석/계정이다. OS 명령 실행이나
모니터 프로세스 시작·중지 API는 제공하지 않는다.

- AI 작업 지침: 저장소 루트 `SKILL.md`
- Python 표준 라이브러리 클라이언트: `scripts/tracedns_api.py`
- 인증 후 API 탐색: `GET /api/v1` 또는 `GET /api/v1/`
- 인증 후 OpenAPI 3.1: `GET /api/v1/openapi.json`
- 오프라인 명세: `docs/openapi.json`
- 명세 재생성: `.venv/bin/python -m http_api.openapi > docs/openapi.json`

라우팅의 단일 기준은 `http_api/rest.py`이다. 명세는 이 allowlist에서 생성하며,
알 수 없는 v1 경로는 404, 지원하지 않는 메서드는 405로 거절한다.
기존 `/verify`는 501 미구현이므로 v1에 노출하지 않는다.
변경은 설정/관측의 기존 서비스로 전달하며 v1 전용 복제 상태를 만들지 않는다.
`PATCH /config`, `PATCH /settings`는 해당 POST와 같은 부분 객체 병합이다.
JSON Patch(RFC 6902) 문서가 아니며 `domains` 배열 자체는 전체 교체다.

## 배포와 인증

`docs/security/deployment.md`의 계정 bootstrap 및 HTTPS reverse proxy 절차를 따른다.
프록시는 공개 Host를 유지하고 `/api/v1` 접두사를 제거하지 않아야 한다.
TLS는 프록시에서 종료한다. 내장 HTTP 서버 포트만 인터넷에 공개하지 않는다.
CORS/익명 접근/장기 API 키/Bearer 인증을 추가하지 않았다. 브라우저 외부 프로그램도
기존의 세션 쿠키와 CSRF를 사용하며 클라이언트가 절차를 자동화한다.

직접 구현할 때의 순서(아래 경로는 모두 `/api/v1` 기준):

1. `GET /auth/csrf`: `Set-Cookie: td_pre=…`를 보관하고 JSON `csrf_token`을 읽는다.
2. `POST /auth/login`: `{"username":"…","password":"…"}` JSON 객체와
   `Cookie: td_pre=…`, `X-CSRF-Token`, `Origin: https://<public-origin>`을 전송한다.
3. 반환된 `td_session` 쿠키와 새 `csrf_token`을 보관한다. 요청 URL/로그/채팅에 넣지 않는다.
4. 이후 요청에 세션 쿠키를 전송한다. POST/PATCH/PUT/DELETE에는 같은 Origin과
   X-CSRF-Token을 보낸다. VT 조회가 켜진 GET 및 MISP GET도 CSRF가 필요하다.
5. `GET /auth/me`로 role, must_change_password, audit_available을 확인한다.
   비밀번호 변경이 필요하면 `/auth/password` 후 다시 로그인한다(기존 세션은 철회됨).
6. 끝나면 `POST /auth/logout`으로 현재 세션을 철회한다.

viewer는 저장된 정보만, operator는 대상 수정·강제 조회·분석을,
admin은 전체 설정·디코더·계정·전체 감사 작업을 수행한다. operator의 config 쓰기에는
`domains`, `revision`만 허용된다. admin이 아닌 사용자는 다른 사람의 job을 조회/취소할 수 없다.
세션 만료·사용자 비활성화·권한 변경·감사 장애 차단은 기존 UI와 동일하다.
감사 action/target은 호환성을 위해 `post:/config` 같은 기존 정규화 경로를 사용한다.
PATCH도 이에 대응하는 POST로 기록된다. 응답 `X-Request-ID`로 요청을 추적한다.

## 클라이언트 사용

외부 AI에는 필요한 권한만 있는 전용 계정을 준비한다. 다음은 실행 예시이며 실제 URL과
사용자명은 운영자가 제공한다. 비밀번호는 secret manager로 `TRACEDNS_PASSWORD`에
주입하거나 사람이 실행할 때 숨김 프롬프트를 사용한다. 인수로 전달하지 않는다.

```bash
export TRACEDNS_BASE_URL=https://tracedns.example
export TRACEDNS_USERNAME=automation
python3 scripts/tracedns_api.py GET /
python3 scripts/tracedns_api.py GET '/results?aggregate=1'
python3 scripts/tracedns_api.py GET '/ips?include_vt=0&limit=100&offset=0'
python3 scripts/tracedns_api.py --json-file request.json PATCH /config
```

CLI는 한 번 로그인해 한 요청을 수행하고 로그아웃한다. 빈번한 polling/다단계 수정은
아래처럼 같은 Python 세션을 재사용한다. 변경 후 GET 확인은 호출자의 책임이다.

```python
import os
from scripts.tracedns_api import TraceDNSClient

with TraceDNSClient(os.environ['TRACEDNS_BASE_URL']) as api:
    user = api.login(os.environ['TRACEDNS_USERNAME'], os.environ['TRACEDNS_PASSWORD'])
    cfg = api.request('GET', '/config')
    # 실제 변경은 사용자 요청에 따라 cfg['domains'] 전체를 보존·편집한 뒤 수행한다.
    results = api.request('GET', '/results', params={'aggregate': '1'})
    history = api.request('GET', '/history', params={'domain': 'example.org'})
```

라이브러리는 JSON 응답 또는 JSONL 문자열을 반환한다. HTTP 실패는 `APIError`의
`status`, `request_id`로 구별한다. 성공 JSON의 `error`, job `status`, coverage도 확인한다.
응답이 성공한 뒤 로그아웃만 실패해도 CLI는 성공으로 표시하지 않으므로, 실패 시 쓰기를
무조건 재전송하지 않는다. 보호된 요청과 로그아웃은 각각 서버 감사를 남긴다.

클라이언트는 TLS 검증을 끄지 않으며 리다이렉트, 환경변수 HTTP proxy, 자동 재시도를
사용하지 않는다. 사설 CA는 `TRACEDNS_CA_FILE`/`ca_file`로 지정한다.
기본 요청 제한은 30초/응답 16 MiB, 라이브러리 `max_response_bytes` 상한은 64 MiB다.
로그인 응답 본문 처리에 실패해도 수신된 세션 쿠키가 있으면 CSRF 재조회와 로그아웃으로
철회를 시도한다. 이 정리 요청의 응답은 별도 16 KiB로 제한한다. 철회를 확인할 수 없으면
원래 오류를 유지하면서 stderr에 경고하므로 필요 시 계정의 세션 목록에서 철회한다.
로컬 개발만 `--allow-loopback-http` 또는 `allow_loopback_http=True`로 HTTP를 허용한다.
서버가 LAN plaintext 모드여도 이 클라이언트는 원격 HTTP를 허용하지 않는다.

## 엔드포인트

모두 `/api/v1` 상대 경로. 세부 요청/응답/권한 조건은 OpenAPI의 description과 schema 참고.

| 목적 | 메서드·경로 | 주요 입력 / 주의 |
|---|---|---|
| API 탐색 | GET `/`, `/openapi.json` | 인증 필요 |
| 설정 조회/수정 | GET/POST/PATCH `/config` | 쓰기 revision 필수, domains 전체 교체 |
| 연동 설정 | GET/POST/PATCH `/settings` | admin, alerts + revision |
| 관측 결과 | GET `/results` | aggregate=1, include_raw=0/1 |
| 대상 상태 | GET `/domains` | domains 배열, resolving은 과거 관측 기반 힌트 |
| 도메인 이력 | GET `/history` | domain: 정확한 storage name, URL 인코딩 |
| IP 목록 | GET `/ips` | limit 1–5000(기본 500), offset, since, include_vt, vt_budget, vt_workers |
| IP 역조회 | GET `/ip`, POST `/ip` | GET ip query: 현재+이력, POST ip body: 현재만 |
| 도메인 그룹 분석 | GET `/domain-analysis` | include_vt 기본 1, 저장정보만 보려면 0 |
| 강제 조회 | POST `/resolve` | domains 목록 또는 domain(A 단축), 설정된 서버/대상만 |
| TXT 샘플 분석 | POST `/analyze` | domain + txt 또는 sample; 로컬 디코딩 |
| 등록 전 조회 | POST `/domain-precheck` | domain, type, 디코더 옵션, include_vt |
| IP 목록 분석 | POST `/ip-list-analysis` | ips 문자열/배열 또는 attributes; include_vt |
| IP 관계 분석 | POST `/ip-relationship-jobs` | ips, include_vt, vt_budget, top_pairs, min_score 등 |
| 분석 상태/결과 | GET `/ip-relationship-jobs/{job_id}` | result=1로 결과 포함 |
| 분석 취소 | POST `/ip-relationship-jobs/{job_id}/cancel` | 빈 객체; running이면 보통 409 |
| 동기 분석 호환 | POST `/ip-relationship-analysis` | 긴 요청 대신 비동기 권장; misp_event_id 연동은 jobs에서 사용 |
| 디코더 카탈로그 | GET `/decoders` | 내장 이름 및 custom/custom_a/custom_all 정의 |
| DSL 허용 연산 | GET `/decoders/custom` | allowed_ops, decoder_types |
| 디코더 변경 | POST/PUT/DELETE `/decoders/custom` | admin, name/decoder_type/steps; DELETE는 steps 불필요 |
| 디코더 미리보기 | POST `/decoders/custom/preview` | admin, steps/sample/decoder_type |
| MISP 검색 | GET/POST `/misp/search` | value, 외부 조회 |
| MISP 이벤트 IP | POST `/misp/event-ips` | event_id, 외부 조회 |
| 내 정보 | GET `/auth/me`, `/auth/activity`, `/auth/sessions` | 감사 결과는 events,total,limit,offset |
| 내 계정 작업 | POST `/auth/password`, `/auth/logout`, `/auth/sessions/revoke` | revoke에서 session_id 생략 시 자신의 모든 세션 철회 |
| 계정 관리 | GET/POST `/admin/users` | admin, 생성 시 username/password/role |
| 사용자 변경 | POST `/admin/users/{user_id}/update`, `/reset`, `/revoke` | role/active 변경, 비밀번호 재설정, 전체 세션 철회 |
| 감사 조회/출력 | GET `/admin/audit`, POST `/admin/audit/export` | admin; export는 한 페이지의 JSONL |

## 안전한 대상 수정

`GET /config`의 최신 revision과 전체 domains를 읽고 원하는 항목만 편집한다.
ENS의 name/text-key/node/resolver, SNS의 record key 등 식별자를 보존한다.
`PATCH /config` 응답의 revision/config 및 후속 GET 결과를 확인한다.

```json
{"revision": 3, "domains": [{"name": "example.org", "type": "A"}]}
```

위 예시는 실제 서버의 revision/list가 아니다. 그대로 전송하면 다른 항목을 삭제할 수 있다.
목록에서 빠진 대상은 이력도 purge되므로 반드시 사용자 승인된 전체 목록으로 구성한다.
409이면 다시 읽고 변경 의도를 병합한다. 무조건 재시도하는 last-write-wins 로직은 금지한다.
Secret 응답은 빈 문자열 + configured 플래그다. 빈 쓰기는 기존 값을 보존하며,
명시적 `clear_fields`만 비운다. 등록/변경 메타데이터는 서버가 관리한다.

## 비동기 완료 판단

관계 분석 생성은 202와 `{"status":"queued","job_id":"…"}`를 반환한다.
상태 GET은 200이어도 실패/진행 중일 수 있다. 1–2초 간격, 제한된 총 시간으로 polling하고
completed에서 result=1로 결과를 가져온다. failed/cancelled/error/audit_status도 확인한다.
작업 결과는 메모리 기반이며 재시작/만료/용량 정책으로 사라진다. 404는 완료의 증거가 아니다.
취소는 future.cancel 기반이다. 실행 중이거나 이미 끝났으면 cancelled=false와 409다.

강제 DNS 조회는 HTTP 200 `requested=true`와 job_id를 반환하지만 완료된 것이 아니다.
`GET /auth/activity?action=force.resolve&target=<job_id>`에서 started → completed/failure를
확인하고 관측 결과의 값/시간을 함께 읽는다. completed는 처리 루프가 끝났다는 의미이며
모든 DNS 서버가 성공했다는 뜻은 아니다. 서버 재시작 후 미완료 intent는 unknown일 수 있다.
관계 job 조회 URL에 force-resolve job_id를 넣지 않는다.

VT 기본값은 `/ips`만 off, `/domain-analysis`·precheck·IP 분석은 on이다.
외부 전송을 허용하지 않았으면 `include_vt=false`(JSON) 또는 `0`(query)를 명시한다.
`misp_event_id`는 별도 외부 조회다. 강제 조회와 정상 모니터링은 설정된 Teams/MISP
알림/갱신을 실행할 수 있다. 원시 관측과 AI 추론은 분리해 보고한다.

## 페이지·제한·오류

- `/ips`: `ips_total_count`, `ips_displayed_count`, `ips_offset`, `ips_limit`, `ips_truncated`.
  offset을 반환된 행 수만큼 증가시키며 수집한다. 일관된 snapshot cursor는 아니므로
  수집 중 변화를 감안해 IP를 중복 제거하고 누락 가능성을 보고한다. `since`는 상대 초다.
- 감사: `limit` 1–1000(기본 50), `offset` 0–10000000. since/until은 UTC epoch 초.
  export는 application/x-ndjson이며 X-Total-Count/X-Next-Offset으로 다음 페이지를 요청한다.
  Python 클라이언트에서는 각 요청 직후 `api.response_headers`에서 이 헤더를 읽는다.
  다음 요청/로그아웃 전에 값을 복사한다. 이 속성은 쿠키 헤더를 노출하지 않는다.
  CLI는 JSONL 본문만 출력하므로 여러 export 페이지에는 Python 세션을 사용한다.
- 관계 분석: IP 토큰 20000개, 유효한 고유 IP 10000개 상한. worker/queue/result 예산 및
  축약 메타데이터는 실제 응답을 확인한다. 큰 결과는 자동 축약을 완전 분석으로 해석하지 않는다.
- body: 일반 기본 5 MiB(`TRACEDNS_MAX_BODY_BYTES`, 최대 64 MiB), auth/admin은 16 KiB.
- 400 잘못된 입력, 401 세션 없음/만료, 403 RBAC/Host/Origin/CSRF/비밀번호 변경 필요,
  404 경로/작업 없음, 405 메서드 불가, 409 revision 충돌 또는 취소 불가,
  413 body 초과, 429 로그인/큐 제한, 5xx 서비스/감사 장애.
- 일반 오류는 JSON error, 경계 오류에는 request_id가 포함된다. body 크기/프레이밍 오류는
  text/plain, HTTP worker 포화 503은 빈 body일 수 있다. 모두 JSON이라고 가정하지 않는다.
- idempotency-key 지원 없음. timeout/5xx 후 변경 또는 enqueue가 되었을 수 있으므로
  설정/감사를 먼저 조회한다. 무조건 재전송하지 않는다.

## 기존 구현의 한계

- 디코더 CRUD는 revision 충돌 검사가 없고 파일 저장 실패가 성공 응답에 드러나지 않을 수 있다.
  PUT은 upsert이며 새 등록 실패 전에 기존 런타임 정의를 제거할 수 있다. 미리보기와 원본 보관,
  성공/실패 후 `/decoders` 재조회를 수행하되 런타임 조회만으로 재시작 후 영속성을 주장하지 않는다.
  이 REST 정리는 디코더 저장 엔진의 트랜잭션 동작을 변경하지 않는다.
- domain-precheck의 `vt_lookup_budget`는 디코더 후보 분석만 제한한다. 초기 선택 IP의 VT
  조회까지 제한하는 전역 quota가 아니다. SNS precheck는 기존 `DEFAULT_SOLAR_PROXY_HOSTS`
  경로를 사용하므로 config의 `DEFAULT_SNS_PROXY_HOSTS` 변경 반영을 가정하지 않는다.
- 관계 분석의 기존 `pairs[].score`와 `relationship_strength`는 의미가 다르다.
  순위/임계치와 assessment/confidence/quality를 확인하며 점수만으로 동일 봇넷을 단정하지 않는다.
- 외부 클라이언트→TraceDNS의 TLS 보장과 TraceDNS→정보 제공자 연결은 별개다.
  기존 MISP search 구현은 upstream 인증서 검증을 비활성화한다. 운영 MISP 연결의
  신뢰/네트워크 통제는 별도로 검토해야 하며 이 변경이 그 연결을 강화했다고 해석하지 않는다.

## 검증 범위

`make test`에 v1 로그인·설정 readback·revision 충돌·RBAC·CSRF·Host·Origin·감사 장애·
body 제한·경로 allowlist·실제 no-VT worker·job 소유권·클라이언트 subprocess 테스트를 포함한다.
오프라인 명세와 서버 명세 생성물의 동일성도 검사한다. `make lint`를 함께 실행한다.
이 테스트는 별도 임시 계정 DB/loopback 서버를 쓰며 운영 서비스/설정을 건드리지 않는다.
외부 HTTPS 배포의 프록시/인증서/방화벽 연결은 별도 운영 검증이 필요하다.
