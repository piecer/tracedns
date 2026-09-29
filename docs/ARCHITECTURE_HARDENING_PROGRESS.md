# TraceDNS 구조 개선 작업 진행 기록

## 2026-09-29 — 기반 변경만 분리한 반영 후보

현재 반영 후보는 상태·작업 소유권, 설정·스케줄러, 영속 알림 전달, 조회 유효성 경계와 수용된 capture/redaction/shared capture-decode 구성요소로 한정한다. 제품 소스와 기존 테스트는 마지막 수용된 작업트리의 바이트를 유지한다. 이 절과 계획 문서의 범위 안내만 새로 정리한다.

- 미수용 Builder discovery 예약 반환 수정과 `aggregate-v1` 생산자 후보는 포함하지 않는다. 기존 조회 경로를 유지하며 신규 publication 경로를 활성화하지 않는다.
- 단일·분할 발행, bounded search, 신규 HTTP/auth/Status 연결, raw/IP/domain 일반 활성화와 Stage5 UI/API 소유권은 후속 미완료 범위다. 기반부 반영을 전체 4·5단계 완료로 해석하지 않는다.
- 이 문서 아래의 승인·중단·정책 대기·검사 수치는 당시의 역사 기록이다. 현재 분리 작업에 대한 재개 지시나 새 검증 결과가 아니다.
- 과거 scratch 증거 일부와 공용 측정 잠금이 유실되어 전체 과거 보존 증명은 복구되지 않았다. 삭제 원인은 미확정이다. 원 실패·손실 기록을 PASS로 덮거나 현재 소스 손실로 혼동하지 않는다.
- 분리본의 합격 여부는 동결된 정확한 소스와 `foundation.patch`를 대상으로 수행한 새 canonical/lint/browser 결과 및 독립 패키지 검토에 따른다. 최종 증거는 함께 제공되는 패키지의 검증 보고서가 권위다. 이 문서는 실행 전에 동결하므로 통과를 선확정하지 않는다.
- 패키지 검증은 별도 소유 잠금과 외부 통신이 차단된 로컬 fixture에서 수행한다. 이전 잠금을 복원한 것으로 취급하지 않으며 기존 유한 실험 예산·제품 한도·미사용 BR12 검증 횟수를 변경하지 않는다.
- 기존 사용자 작업트리와 제외된 실험본을 보존한다. 실제 commit/merge/push, 운영 배포·서비스 재시작과 외부 제공자 검증은 이 분리본 준비에 포함하지 않는다.

## 현재 상태 — 사용자 승인으로 재개, 전체 완료 아님

사용자가 이 브랜치의 미완료 작업을 완료까지 진행하도록 요청했고, 이어 다음 두 계약 변경을 명시적으로 승인했다. 따라서 아래의 이전 중단 기록은 역사적 증거로 보존하되, 현재 작업에 대한 중단 지시로 적용하지 않는다.

1. 캡처의 사용자 정의 콜백 실행을 막기 위해, 기존 작업량·메모리 한도 안에서 저장된 키의 타입을 검증하는 제한적 순회를 허용한다. 무시하는 값의 복사·발행이나 자원 한도 증가는 허용하지 않는다.
2. 축소 수명주기 실험의 누적 시나리오 상한을 512회에서 537회로 확대한다. 재개 기준 소비량은 505회이며 이후 최대 32회다. 할당 오류 조건 256회·검사 지점 160개 한도는 유지하고 기존 소비량을 초기화하지 않는다.

재개 시 승인 소스 271개의 해시와 현재 작업 트리의 동일성을 확인했다. 마지막 리뷰에서 정적으로 지적했던 `Operation._drive`의 종료 반복자 생성 경계에 실제 opcode 기반 단일 `MemoryError`를 주입했고, 자기 lease와 ticket이 정리된 뒤에도 `active/running`이 남는 실패를 재현했다. 이는 합성 할당 오류 주입이며 실제 메모리 고갈이나 제품 실행은 아니다. 원본 실험본과 기존 제품 소스는 이 재현에서 변경하지 않았다.

수명주기 최소 수정과 캡처 구현은 서로 다른 격리 디렉터리에서 진행한다. 독립 검토·회귀 검사·통합 검증 전에는 제품 변경을 승인하거나 4·5단계를 완료로 표시하지 않는다. 커밋·push·운영 배포·서비스 재시작·실제 외부 제공자 호출은 여전히 승인 범위 밖이다.

재개 증거 루트: `/home/piecer/.hermes/cache/scratch/tracedns-hardening-resume-icucobpd/`

- `APPROVED_RESUMPTION_ADDENDUM.md`: 현재 승인과 변경하지 않는 경계.
- `baseline.json`, `accepted-source-manifest.json`: 재개 기준 소스 확인.
- `d1-result.json`, `d1-process-receipt.json`: 실행으로 확인한 반복자 경계 실패와 소유 프로세스 부재.
- `proposed-gap-only-budget.json`: 승인된 추가 32회 이내의 검증 배분. 제안 당시의 파일명·상태는 보존하며 위 승인 부록이 현재 권한을 정한다.

아래 1–8절의 검사 수치와 중단 판정은 이전 기록이다. 새 결과와 합산하거나 재실행한 것으로 해석하지 않는다.

## 2026-09-27 재개 후 상태 — 캡처 구성요소 통합, 후속 단계 미완료

### 캡처와 레거시 발행 경계

승인 기준 271개 파일 위에 독립 검토를 통과한 9개 경로만 반영했다. `http_api/read_capture.py`와 캡처 회귀 모듈 6개, 레거시 발행 실패 회귀 모듈 1개를 추가하고, `monitor/engine.py`의 초기 등록·변경 이벤트 발행 뒤 예외 경계만 수정했다. 기존 다른 승인 소스 270개는 그대로 보존한다. 이 문서 변경은 제품 소스 통합과 별도로 기록한다.

- 제한적 저장 키 타입 검증으로 사용자 정의 키 비교 콜백을 실행하기 전에 거부한다. 무시하는 값 복사, 자원 한도 증가, 비버전 telemetry에 대한 신뢰 확대는 없다.
- 최대 설정 키와 루트/중첩 경로 검증 비용이 합쳐져 진행이 멈추던 `C-IR-01`을 제한된 소유 검증 상태로 교정했다. 실제 소유자를 사용한 원래 루트·중첩 실패와 수정 후 통과 증거를 보존했다.
- 레거시 경로가 선택된 이벤트/current를 변경한 뒤, 처음부터 잘못된 비선택 history/meta에서 예외가 발생하면 버전 갱신을 건너뛰던 `C-RR-01`과 초기 등록의 같은 원인을 수정했다. 원래 예외·부분 데이터·lease·무변경/telemetry 의미를 유지하고 상태 잠금 해제 전 버전을 한 번 갱신한다. 운영 `DeliveryRuntime` 장애를 재현했다는 주장은 아니다.
- 최종 독립 검토: owner/신규 회귀 161개, 변경 없는 캡처 223개, 역사 회귀 5개, 바이트 동일 외부 R4와 P1/P2/P3 통과. 이 집합들은 겹치므로 합산하지 않는다. 새 탐색 시나리오는 0/5 사용, 추가 수명주기 실험은 0회다.
- 부모의 새 격리 통합 검증: `make test` 1484개 통과, 실제 Ruff `make lint` 통과, `npm run test:e2e` 22개 통과. 브라우저는 격리된 실제 HTTP 서버와 fixture 데이터를 사용했으며 운영 서비스 검증이 아니다. 로그의 일반 `Request failed` 진단은 보존했고, 모든 브라우저 assertion은 통과했다.

독립 검토 소스는 279개 파일이다. `http_api/read_capture.py` SHA256은 `c2cbe51c35a20f8a055f720d7e0aeba66404168b6bf1fa49ca8fd0d51702b580`, `monitor/engine.py`는 `445358d881760affe43bbd5bf23fad0fa9ec5a4c4cace47cca62e48829fd9301`이다. 독립 검토 682개 증거 항목·8816개 보호 항목과 원래 프로세스 그룹/감독자 42개의 부재를 부모가 대조했다. 이 대조 자체는 새 동작 실행이 아니다.

메인 통합 후 최종 테스트·lint·브라우저 판정은 재개 증거 루트의 `capture-integration/` 아래 `04-main-make-test.json`, `05-main-make-lint.json`, `06-main-browser.json`, `ACCEPTANCE.json`으로 확인한다. IDE Pyright의 동적 타입 관련 진단은 canonical Ruff 통과와 구분하며, 타입 검사 전체 통과를 주장하지 않는다. 커밋·push·배포·운영 재시작은 수행하지 않는다.

이 구성요소는 아직 HTTP 발행 능력이 아니다. 파생 redaction, 분할 발행, 검색, 닫힌 HTTP 응답 연결과 Stage5 UI/API 소유권은 미완료다. 기존 브라우저 22개 통과가 이 미구현 경로의 E2E 통과를 의미하지 않는다.

### 당시 수명주기 기록 — 아래 제품 수용 기록으로 현재 상태 대체

반복자 경계 실패의 최소 수정과 관련 증거 보완은 격리 실험본에만 있다. 누적 소비량은 **526/537 시나리오, 220/256 할당 오류 조건, 160/160 검사 지점**이며, H 5개·I 6개 예약 슬롯은 미사용이다.

남은 P01/P16 판정은 `BLOCK_MISSING_MODEL_BARE_HEADER`다. 기존 건당 256바이트 논리 예약량 안에 원래 bare-header 비용과 새 제어 객체·동시 임시 비용이 들어가는지 귀속할 모델이 부족하다. 물리 크기 측정이나 `sizeof > 256`만으로 논리 초과를 재현했다고 판단하지 않는다. 앞서 지적된 버퍼 수명·생산자 퇴역 증거의 국소 검토 통과도 전체 수명주기 승인은 아니다.

건당 예약량을 보수적으로 재산정하는 별도 정책 질문은 **명시적 답변 대기**다. 전체 메타데이터 1MiB·작업공간 16MiB와 검증 상한은 유지하지만 동시 예약 수 및 기존 ‘512바이트에서 예약 2개 허용’ 조건이 바뀔 수 있다. 앞선 `1. 오케이 2. 오케이`는 제한적 키 검증과 537회 상한 승인이지 이 새 정책의 승인이 아니다. 무응답을 승인/거절로 간주하거나 잔여 11회를 소비하지 않는다.

### 최신 증거와 다음 경계

- 독립 최종 검토: `/home/piecer/.hermes/cache/scratch/tracedns-capture-owner-final-review-p97hyuqd/REPORT.md` 및 `verdict.json`.
- 재개 증거: `capture-owner-final-parent-verification.json`, `capture-integration/`, `CURRENT.json`.
- 미해결 비용 모델: `lifecycle-fit/DECISION.md`, `lifecycle-sizing-policy-proposal.md`.
- 수명주기 정책 결정·필수 증명·독립 검토 후에만 redaction 제품 연결과 후속 발행/검색/HTTP/UI 통합을 진행한다. Stage4·Stage5 및 전체 작업은 완료가 아니다.

## 2026-09-28 KST — 파생 마스킹 구성요소 독립 수용, HTTP 연결은 미완료

이 절은 위의 비용 모델 결정 대기와 이전 제품 BLOCK 상태를 대체한다. 과거 실패·중단·미수용 후보는 삭제하지 않으며, 그 당시 수치와 현재 결과를 합산하지 않는다.

### 축소 수명주기 실험 종료

사용자의 후속 완료 요청에 따른 제한적 비용 재산정 범위는 `APPROVED_SIZING_CONTINUATION.md`에 기록했다. 전역 metadata 1MiB·workspace 16MiB와 실험 상한은 유지하고, 건당 제어 예약량을 각 축 106728바이트로 보수적으로 재산정했다. 동시 admission 감소를 허용한 별도 변경이며 최초 두 항목 승인과 혼동하지 않는다.

P01–P20 및 독립 I6가 통과하여 축소 실험을 수용·종료했다. 누적 소비는 536/537 worlds, 224/256 allocation cases, 160/160 sites이며 부모 전용 H5 1회는 미사용으로 보존한다. 축소 모델의 수용만으로 실제 제품이나 HTTP 경로를 승인한 것은 아니다.

### 실제 derived-redaction 구현과 독립 수용

실제 DFS·기존 sanitizer·JSON 인코더에 수명주기 처리를 이식하고, 설정 검증·경로 재탐색·UTF8 복사·digest를 합산한 slice당 512 작업 및 누적 inclusive 16384 제한과 4096-node sliced preflight를 검증했다. 기존 일반 `security/redaction.py`와 승인된 캡처 구성요소는 변경하지 않는다.

독립 검토에서 초기화 helper 진입의 단일 합성 MemoryError가 미초기화 `_lease`의 AttributeError로 바뀌는 T01을 재현했다. 이 사례에서 누수나 비밀 유출을 관측한 것은 아니다. 효과 전 scalar bootstrap과 보호된 자원 획득을 분리하고, 같은 원인의 Projector·sliced admission 및 부분 초기화·진단 경로를 교정했다. 신규 회귀 14개를 추가했으며 원래 실패 증거와 잘못된 초기 selector/observer 기록은 보존했다.

- 최종 실제 모듈 SHA256: `991768734ccf9be9159ff831e08a94fb05c51ae8bbe6149284cc1f45625a7d64`.
- 독립 재검토의 새 실행: focused 290개 통과·기존 3개 skip, 원본54+외부5의 59개 통과, targeted 5개 통과. 서로 겹치는 집합을 합산하지 않는다.
- T01의 원래 assertion과 실제 fired1/Budget1을 유지했다. 부분 secret/key 재개 후 전체 secret 집합·객체·인코딩 bytes를 독립 oracle과 비교했고 실제 작업량 512 및 실제 4096-node preflight를 관측했다.
- 제품 독립 targeted 누적은 6/8이며 2개는 미사용으로 닫는다. 축소 실험을 추가 실행하거나 H5를 소비하지 않았다.
- Getter/wrapper와 변경된 예외 frame을 포함한 같은 control 모델에서 Builder 여유632, Projector/Encoding 여유600, sliced admission 여유4448바이트를 독립 재계산했다. 이는 조건부 논리 phase-union 모델이며 RSS·native OOM·보편적인 2ms 보장이 아니다.
- 최종 격리 수정본의 canonical은 1774개 통과·기존 3개 skip, 미실행0이며 Ruff도 통과했다. 독립 reviewer는 이 exact-source 실행 증거를 상속 검증했고, canonical을 자신이 재실행했다고 주장하지 않았다. 실제1101 및 cascade의 비계측 시간과 별도 allocation profile도 보존했다.

수용 증거는 재개 루트의 `redaction-constructor-rereview/REPORT.md`, `verdict.json`, `redaction-constructor-rereview-parent-verification.json`에 있다. 부모는 676개 evidence·10202개 보호 경로·286개 소스와 독립 실행 child/group 7개의 부재를 대조했다. 이 대조 자체는 새 제품 실행이 아니다.

### 통합 범위와 남은 작업

통합 대상은 `security/derived_redaction.py`와 `tests/test_stage4_redaction_{plan,projection,failures,cleanup,lifecycle,work_bounds}.py`의 일곱 새 경로이며, 진행 문서는 별도로 갱신한다. 승인된 기존 279개 제품·테스트 파일을 보존한다. 격리·현재 브랜치의 새 canonical/lint/browser 판정은 `redaction-integration/`의 개별 실행 receipts와 최종 `ACCEPTANCE.json`을 권위로 삼는다. 구성요소 검토 결과를 아직 실행하지 않은 통합 gate의 결과로 대신하지 않는다.

이 구성요소 추가는 HTTP 발행 경로의 연결 완료가 아니다. 공유 capture/decode, 단일·분할 발행, 검색, 닫힌 HTTP 응답 연결, Stage5 UI/API 소유권과 전체 closeout은 남아 있다. 기존 브라우저 suite는 격리 실제 HTTP 서버의 fixture 회귀이며 이 미구현 경로 또는 운영 서비스의 E2E 승인이 아니다. 커밋·push·배포·운영 서비스 재시작은 수행하지 않는다.

## 공유 capture/decode 구성요소 독립 수용과 exact-byte 통합 범위

이 절은 바로 위의 공유 capture/decode 미완료 항목에 대한 구성요소 판정을 갱신한다. 기존 절의 실패·중단·수치·당시 판정은 삭제하지 않는다. 독립 완료 검토 `shared-capture-decode-rereview-completion/`은 동결된 A–G/P0–P11의 19행과 인터페이스 9조항을 모두 **ACCEPT**했다. 이는 유한 내부 capture/decode 구성요소 수용이며 전체 Stage4·Stage5 완료가 아니다.

- 최초 독립 `gap-01`은 실제 clock CALL의 합성 단일 MemoryError 이후 running owner가 남던 제품 실패다. 원 BLOCK을 보존하고 수정 사이클 **1/2**에서 initial clock·source action·diagnostic finalizer의 보호/역순 lock 해제 경계를 교정했다. 신규 회귀 28개와 원 행동 회귀의 수정 후 결과는 별도 증거로 보존한다.
- 독립 실행 focused **661 passed / 기존 3 skips**, external **59 passed**, 원 gap **1 passed/fired1**, paid-cursor **1 passed/fired1**을 exact source·origin·전체 parametrized collection으로 확인했다. focused 내부 fault20/fired1 및 deadline12(controls6/expired6)는 이미 포함된 관측이다. 이 집합들은 겹치며 합산하지 않는다. 완료 검토 W 자체의 제품 import/실행은 **0**이고, 이 숫자는 이번 통합의 새 실행 결과가 아니다.
- 중단된 reviewer의 `content_policy_blocked`는 provider 중단 기록이지 제품 실패 또는 PASS가 아니다. 원 provenance 조회 실패, observer 보정, builder의 final-clock RED와 원 independent BLOCK을 유지했다. 보호 콘텐츠의 이전 변화는 `shared-capture-decode-rereview-recovery/content-disposition.json`에 승인된 정확한 5 postimage로만 대조했다. 이번 제품 통합의 허용 5경로와 별개이며, 새로운 불명 drift를 자동 승인하거나 복원하지 않는다.
- 검토된 capture SHA256은 `c8c1a81d503fb725077723b6b04745e8a4e1aed8f07dbfbb8cf63ca3d794c42c`, bridge는 `1cee64001515f0864f4f08dca9abb8457cf6281b720053c0883c1e0a40598e0b`이다. 기존 redaction SHA256 `991768734ccf9be9159ff831e08a94fb05c51ae8bbe6149284cc1f45625a7d64`는 그대로다. metadata1MiB/workspace16MiB, HEADER106728 및 기존 추가 control envelope를 유지하며 RSS/native OOM 또는 보편적 2ms 보장은 주장하지 않는다.
- 축소 실험 **536/537 worlds, 224/256 allocation cases, 160/160 sites와 미사용 H5**, 실제 redaction targeted **6/8과 미사용 2개**의 종료·예약 상태를 바꾸지 않았다. 통합 canonical 실행은 이 닫힌 실험을 다시 여는 fault sweep이나 새 독립 review가 아니다.

통합 허용 delta는 `http_api/read_capture.py` 수정과 `http_api/derived_capture.py`, `tests/test_derived_capture.py`, `tests/test_derived_capture_lifecycle.py` 신규 3개다. 이 진행 문서만 별도로 좁게 갱신하고 다른 기존 285개 소스 및 caller dirty 상태를 보존한다. accepted290 소스는 제품 4경로를 재구현하지 않고 검토된 바이트 그대로 승격한다.

원래 통합 시도의 판정은 재개 증거 루트의 `shared-capture-decode-integration/ACCEPTANCE.json`에 BLOCK으로 보존한다. 아래 namespace-only 재개의 최종 통합 판정은 `shared-capture-decode-integration-completion/ACCEPTANCE.json`과 **01-isolated-make-test / 02-isolated-make-lint / 03-isolated-browser / 04-main-make-test / 05-main-make-lint / 06-main-browser** 개별 receipt를 권위로 삼는다. 이 문서는 그 실행 전에 동결하며, 독립 수용이나 기대 수치로 아직 실행하지 않은 gate의 PASS를 대신하지 않는다. 새 read-only verifier는 원 보호 baseline을 보존한 채 허용된 main5 postimage만 반영하고 나머지 보호 항목을 정확히 대조한다.

남은 경계는 단일·분할 발행, 검색, 닫힌 HTTP 응답 연결, Stage5 UI/API 소유권 및 전체 closeout이다. 기존 browser suite는 로컬 격리 HTTP fixture 회귀이며 새 publication 경로나 운영 서비스 E2E 승인이 아니다. 일반 `Request failed` 로그와 IDE Pyright 진단은 assertion/Ruff 판정과 구분한다. 커밋·stage·push·배포·설치·제공자 호출·운영 서비스 재시작은 수행하지 않는다.

### 원 npm 외부 요청 BLOCK 보존과 namespace-only 통합 재개

원 통합 O는 격리 canonical **1922 passed / 기존 3 skips**, 실제 Ruff, browser **22 passed** 뒤 npm CLI update-notifier의 `GET registry.npmjs.org/npm` HTTP200을 발견하여 **BLOCK_EXTERNAL_NPM_UPDATE_CHECK**으로 중단했다. 제품 assertion 실패는 없었지만 네트워크 정책 실패이며 main 승격·main gate는 실행하지 않았다. 원 BLOCK·strict verifier exit1·npm 로그를 그대로 보존하고 통과로 재분류하지 않는다.

부모의 `shared-capture-decode-integration-reconciliation/verification.json` 실제 exit0은 원 BLOCK 증거와 소스 보존 대조다. 통합 ACCEPT가 아니다. `content-disposition.json`은 curator ledger, `code-verification/SKILL.md`, 두 reference의 정확한 네 postimage만 허용한다. 이는 앞선 W의 다섯 콘텐츠 disposition 및 이번 main 다섯 경로 승격과 별개다. 그 밖의 변경은 숨기거나 복원하지 않고 부모에게 돌려준다.

재개 N의 모든 canonical/lint/browser child tree는 `/usr/bin/unshare --user --map-current-user --keep-caps --net`의 별도 namespace에서만 실행한다. 그 안에서 lo만 올리고 IPv4/IPv6 비로컬 route 부재와 감독자/child namespace 분리, 실행 전후 topology를 기록한다. npm update_notifier=false/offline=true/audit=false/fund=false를 child 환경에만 적용하며 host-network fallback이나 host 서비스 변경은 없다. 기존 설치 Chromium·node_modules·public CA·literal venv와 공유 측정 lock 및 120/600/3/3초 경계를 유지한다.

부모의 snap launcher 및 host GLIBC version-only setup 실패도 보존한다. 새 N-local thin Ruff launcher는 부모가 해시 확인한 설치 Ruff0.16.8과 core24 loader/libraries를 그대로 exec하고 argv를 전달한다. `make lint RUFF=<N-local-launcher>`의 실제 실행만 lint gate이며 version preflight는 lint PASS를 대신하지 않는다. 설치·제품/테스트/Makefile/설정 수정이나 추가 fault campaign은 하지 않는다.

이 문서까지 동결한 뒤 새 격리 3 gates가 모두 통과한 경우에만 승인된 네 코드/테스트 postimage와 이 문서를 main에 반영하고, 마지막 편집 이후 main 3 gates를 새로 실행한다. 최종 권위는 **N=`shared-capture-decode-integration-completion/`의 `ACCEPTANCE.json`, 여섯 개별 receipts, `accepted-source-manifest.json` 및 실제 실행된 `verify_readonly.py` receipt**다. 아직 실행하지 않은 결과를 문서에서 선확정하지 않는다. 유한 구성요소 수용, 보존 대조, 통합 수용과 전체 Stage4/5·배포 완료는 계속 구분한다.

## 이전 중단 결정과 당시 문서 커밋의 범위

사용자 요청에 따라 추가 구현, 실패 재현, 검증 실험, 제품 통합 작업을 중단한다. 반복된 요청 처리 차단으로 더 진행하지 않기로 했으며, 이 문서는 지금까지의 진행 내역만 보존한다. 자동 재개하거나 새 수정 작업을 위임하지 않는다.

이 커밋은 **진행 기록 문서만** 포함한다. 기존 코드·테스트의 미커밋 변경과 사용자 파일은 작업 트리에 그대로 보존한다. 이 문서의 커밋이 코드 변경까지 Git에 저장하거나 제품 개선 전체를 완료했다는 뜻은 아니다. 원격 push·배포는 수행하지 않는다.

- 작업 시작 기준 브랜치: `master`
- 기준 HEAD: `687eae36b6bcb9f56a9601dc109a019e617c5306`
- 기록용 브랜치: `feature/architecture-hardening-progress`
- 저장소: `/home/piecer/dev/src/tracedns`
- 아래 테스트 수치는 각 단계에서 이미 실행한 기록이며, 이번 문서 정리에서 재실행한 결과가 아니다.

## 1. 원래 작업 목표

전면 재작성 없이 상태·작업 소유권, 설정 적용, 스케줄러, 영속 알림 전달, 대용량 조회, UI/API 경계를 단계적으로 개선한다. 단계별 격리 구현, 회귀 검사, 독립 검토를 거쳐 검증된 변경만 기존 작업 트리에 반영하는 방식으로 진행했다.

## 2. 기존 작업 트리에 반영하고 승인한 범위

| 단계 | 주요 변경 | 마지막 단계별 검증 기록 | 상태 |
| --- | --- | --- | --- |
| 초기 구조 감사 | 상태·설정·실행·조회 경계 조사 및 재현 | 테스트 552개, 정적 검사, 브라우저 3개 통과 | 감사 완료 |
| 1단계: 상태·작업 소유권 | 상태 복제, 세대별 유효성, 삭제와 실행 경합, 프로세스/Future 정리, 종료 중 신규 접수 차단 | 테스트 578개, 정적 검사, 브라우저 3개 통과 | 해당 범위 승인·작업 트리 반영 |
| 2단계: 설정·스케줄러 | revision 충돌 확인, 검증·컴파일 후 저장, 실패 시 기존 설정 유지, 디코더 등록·적용 순서, 스케줄링 및 종료 신호 처리 | 테스트 684개, 정적 검사, 브라우저 5개 통과 | 해당 범위 승인·작업 트리 반영 |
| 3단계: 영속 알림 전달 | 전달 의도·진행·미수용 상태 영속화, 재시도·재시작 처리, 관측 우선 정책, 인증·전달 상태 UI 개선 | 계약 37개, 테스트 1100개, 정적 검사, 브라우저 22개 통과 | 해당 범위 승인·작업 트리 반영 |
| 4단계 일부: 조회 유효성 경계 | 관측·표시 상태와 조회 결과의 유효성 확인, 부분 큐 처리·삭제 후 예외 발생 시 완료한 변경 기록 보존 | 테스트 1232개, 정적 검사, 브라우저 22개 통과 | 해당 범위만 승인·작업 트리 반영 |

이 수치는 서로 다른 단계의 전체 검사 결과이므로 합산하지 않는다. 현재 승인된 작업 트리 기준은 보호 파일 271개이며, **4단계 전체나 제품 배포가 완료된 것은 아니다.**

대표 변경 영역은 `monitor/repository.py`, `monitor/config_service.py`, `monitor/scheduler.py`, `monitor/signal_stop.py`, 알림 전달 관련 `monitor/delivery_*.py`, `security/jobs.py`, `http_server.py`, 설정·상태 API와 프런트엔드다. 이 문서가 해당 파일들을 이번 커밋에 포함하지는 않는다.

## 3. 격리 실험에서 진행했으나 제품에 반영하지 않은 범위

### 대용량 입력 캡처

선택된 데이터만 복사하는 계약을 검토하고 후보를 시험했다. 사용자 정의 키 비교가 호출되는 경로와 동결된 입력 계약이 충돌해 보류했다. 계약 변경은 승인되지 않았으며 제품에 통합하지 않았다.

### 민감정보 제외 처리와 자원 수명 관리

여러 격리 후보를 구현·검사했으나 독립 검토에서 참조·예약 반환·소유권 결함이 발견됐다. 최신 격리 제품 후보는 테스트 1473개 통과, 5개 실패, 3개 건너뜀 기록을 갖고 있으며 승인되지 않았다. 이 결과는 승인된 작업 트리의 1232개 통과 기록과 다른 대상이다.

이후 제품 코드와 분리된 수명주기 실험을 진행했다.

1. 생성자 실패 정리 함수의 진입 자체도 보호하도록 수정했다. 동일 조건의 수정 전 실패와 수정 후 통과를 확보했고, 독립 리뷰가 이 국소 수정을 인정했다.
2. 작업 종료 직전 상태 확인 실패로 실행 상태가 남는 경로를 수정했다. 기존 재현 조건은 통과했으나, 최신 독립 리뷰에서 새 반복문의 진입 경계가 별도 문제로 지적됐다. 이 수정 전체를 승인하지 않았다.
3. 생성자 참조 소멸 검사에서 제품 소유 참조와 호출자 인수·관측용 캐시의 참조를 분리했다. 제품 코드는 유지하고 검사만 보정했으며, 실제 재검증과 독립 리뷰가 보정을 인정했다.
4. 미실행 대상 검사 5개, 반환 순서 검사 4개, 메모리 구조 측정 6단계를 실행했다. 실행된 제한 범위에서 새 후보 실패는 관측되지 않았으나 전체 증명이 완료되지는 않았다.

## 4. 중단 시점의 정확한 판정

**전체 수명주기 실험과 제품 통합은 BLOCK 상태다.**

최신 독립 리뷰는 실행을 추가하지 않고 다음을 확인했다.

- 현재 실험본 `mechanism.py:634`의 반복자 생성이 예외 처리 범위보다 먼저 실행된다. 그 지점에서 실패하면 실행 소유 상태가 남을 수 있는 정적 경로가 있다. **실행으로 재현한 실패가 아니다.**
- 검사 목록이 같은 형태의 암묵적 반복자 생성 6곳을 누락했다. 지적된 위치는 `Budget.reserve`, `Owned.close`, `OwnedPayload.admit`, `Operation._unwind`, `Operation._drive`의 두 반복문이다. 6곳 전부를 실제 결함으로 확정한 것은 아니다.
- 실제 두 번째 인코딩과 예외가 보유하는 중간 버퍼의 수명 검증이 부족하다.
- 기존 제어 객체 구조 대비 새 구조의 증분 비용과 최대 동시 점유가 기존 허용량에 맞는지 입증되지 않았다.
- 반환 과정의 callback이 요구된 생산자 프레임 퇴역 시점에 발생했다는 귀속 근거가 부족하다.

독립 리뷰는 전체 프로세스 RSS 보장, 모든 native finalizer 조합 시험, 소스 해시가 바뀌었다는 이유만의 전체 검사 재실행을 추가 요구하지 않았다. 원래 기준보다 넓은 주장과 실제 필수 증명 결손을 구분했다.

이 지적 이후 **새 실패 재현, 반복문 수정, 검사 목록 수정은 실행하지 않았다.** 사용자의 중단 요청을 우선한다.

## 5. 검증 소비량과 보존 확인

- 누적 실험: 504 / 512 시나리오.
- 누적 할당 오류 조건: 208 / 256.
- 현재 기록된 검사 지점: 154 / 160.
- 최신 독립 리뷰의 추가 후보 실행: 0.
- 최신 실행 증거 171개와 승인 작업 트리 271개, 격리 제품 후보 276개의 해시를 부모가 확인했다.
- 최신 실행 작업자 17개의 PID/프로세스 그룹 부재와 공유 측정 lock 보존을 확인했다.
- 문서 정리를 시작할 때 실행 중인 위임 작업은 없었다.

해시 확인은 증거의 동일성 확인이며 새 테스트 실행을 의미하지 않는다. 마지막 독립 리뷰는 정적 검토이므로 새 실제 실패를 재현했다고 표현하지 않는다. 잔여 실험량은 재개 권한이나 완료 보장이 아니다.

## 6. 미완료로 남기는 작업

- 반복자 생성 경계 지적의 실제 재현 및 필요한 최소 수정.
- 누락된 검사 목록과 버퍼 수명·증분 메모리·반환 시점 증거 보완.
- 수정 후보의 독립 승인.
- 격리 제품 코드 연결과 제품 회귀·전체 테스트·정적 검사·브라우저 확인.
- 검증된 제품 변경의 기존 작업 트리 통합.
- 4단계의 남은 캡처·조회 결과 발행·검색·HTTP 연결.
- 5단계의 UI/API 작업 소유권과 최종 통합 검증.

위 목록은 진행 내역의 미완료 표시이며, 지금 실행할 계획이나 자동 재개 지시가 아니다.

## 7. 기존 증거 위치와 식별자

캠페인 증거 루트:

`/home/piecer/.hermes/cache/scratch/tracedns-hardening-tnkc2rhx/`

| 상대 위치 | 내용 |
| --- | --- |
| `stage1-accepted/`, `stage2-accepted/`, `stage3-accepted/` | 승인된 이전 단계 기록 |
| `stage4-owner-fences-accepted/` | 승인된 4단계 일부 기준 |
| `stage4-redaction-cleanup-repair/` | 승인되지 않은 격리 제품 후보 |
| `stage4-redaction-terminal-tail-repair/` | 국소 종료 경계 수정과 과거 실패·통과 기록 |
| `stage4-redaction-reference-attribution/` | 참조 소유자 분리 결과 |
| `stage4-redaction-validation-closeout/` | 마지막 실제 실행 결과, 검사별 판정 및 증거 목록 |
| `stage4-validation-closeout-parent-verification.json` | 부모의 마지막 증거·보존 확인 |
| `stage4-redaction-closeout-independent-review/` | 마지막 독립 리뷰, 정적 지적 및 원 기준 대조 |

마지막 실험본 `mechanism.py` SHA256:

`1369d3d55ae0e3ed414b800de9ee3f24e9cadabf13b2f69860a7babb4c938701`

마지막 실행 증거 `artifact-manifest.json` SHA256:

`ce6d85539a7eeeb84d157c868ed8d1522a73639f61ac9766bdf19cb8d037b3df`

이 경로는 로컬 scratch 증거다. 파일 본문은 이 문서 커밋에 포함하지 않았으며, 새 clone에서 사용할 수 있거나 영구 보존된다고 보장하지 않는다. 이전 `TRACEDNS_CONTINUATION.md`의 진행 중·재개 문구보다 **이 문서의 사용자 중단 결정이 우선**한다.

## 8. 이번 문서 커밋의 확인 범위

진행 내역 문서 한 개만 추가한다. 문서 형식과 staged diff, 실제 커밋의 포함 파일을 확인하며, 추가 구현·실험·제품 테스트는 수행하지 않는다. 기존 변경은 미커밋 상태로 유지하고 원격 push는 하지 않는다.
