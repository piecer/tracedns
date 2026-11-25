# 다중 사용자 운영

TraceDNS는 서버 세션과 로컬 SQLite 계정 DB를 사용한다. 무인 익명 운영으로 fallback하지 않는다.

## 최초 관리자

운영 서버의 서비스 계정으로만 아래 명령을 실행한다. 비밀번호는 인수·로그·설정 파일에 넣지 않으며 터미널에서 두 번 입력한다.

```bash
# 서비스 전용 DB에 최초 관리자 생성
.venv/bin/python -m security.cli --db /var/lib/tracedns/security/auth.sqlite bootstrap admin
```

DB 및 상위 디렉터리는 서비스 계정만 읽고 쓸 수 있어야 한다(0700/0600). 계정을 만들기 전 모니터 시작은 실패한다. 운영 DB·세션 파일을 저장소에 넣지 않는다.

## 실행과 TLS

외부 접근은 TLS 종료 reverse proxy 뒤에서 공개 origin과 신뢰할 프록시 IP를 명시한다.

```bash
# HTTPS reverse proxy 뒤 실행 예시
.venv/bin/python dns_monitor.py --security-db /var/lib/tracedns/security/auth.sqlite --http-host 127.0.0.1 --public-origin https://tracedns.example --trusted-proxy 127.0.0.1
```

`--insecure-http`은 기본적으로 loopback 바인딩에서만 허용된다. 신뢰된 내부망에서만 필요한 경우 `--allow-insecure-remote-http`와 `--public-origin http://<host>:<port>`를 함께 주어 원격 HTTP를 명시적으로 허용할 수 있다. 이 모드는 비밀번호·세션 쿠키·DNS 결과가 TLS 없이 전송되므로 인터넷, Wi-Fi, VPN 공유망에서는 사용하지 않는다.

## 외부 REST API / AI 클라이언트

`/api/v1`은 기존 UI와 동일한 세션·CSRF·역할·감사 경계를 통과한다.
프록시에서 공개 Host를 유지하고 `/api/v1` 경로를 그대로 전달한다.
별도의 익명 접근, CORS 허용, Bearer/API 키 우회를 추가하지 않는다.
외부 AI에는 viewer 또는 operator 전용 계정을 우선 사용하고, admin은 필요한 작업에만 부여한다.
계정의 최초 비밀번호 변경을 마친 뒤 secret manager로 클라이언트 환경에 주입한다.
`scripts/tracedns_api.py`는 HTTPS를 검증하고 세션을 메모리에만 보관하며 작업 후 로그아웃한다.
클라이언트는 서버의 LAN plaintext 허용 옵션과 무관하게 원격 HTTP를 거절한다.
API 계약/제한은 `docs/API.md`, AI 작업 절차는 루트 `SKILL.md`를 참고한다.

## 선택적 AI 제공자

외부 AI 클라이언트와 별개로, 기본 비활성화된 보조 기능은 네이티브 Ollama 또는
OpenAI-compatible Chat Completions를 명시적으로 선택한다. 관리자는 Settings의
AI provider(`#settings-ai`) 또는 admin 전용 `/ai/settings`에서 글로벌 revision을
확인해 URL·모델·발신 Bearer 키를 저장한다. 정상 설정 적용은 서버 재시작을 요구하지
않으며 저장 자체는 연결 검사·추론이 아니다. Bearer는 웹 로그인 우회가 아니다.

Ollama는 기존 정확한 모델 이름·digest와 루프백 HTTP origin을 유지한다. 숫자 루프백
또는 DNS 없이 `127.0.0.1`로 매핑되는 리터럴 `localhost`와 명시적 포트가 필요하다.
호환 제공자는 검증된 공개 HTTPS·전역 라우팅 주소 또는 명시적 loopback 정책을 쓴다.
사설 LAN·환경 프록시·리다이렉트·자체 서명 TLS는 허용하지 않는다. Job 요청은 임의
프롬프트·endpoint override를 받지 않으며 모델을 자동 다운로드하지 않는다.
로컬 런타임의 클라우드 차단·egress 정책과 모델 불변성은 런타임 소유자가 보장해야 하며,
루프백 주소만으로 증명되지 않는다. 외부 제공자에는 선택된 근거가 전송될 수 있으므로
보존 정책을 별도로 검토한다. `store=false`는 무보존의 증명이 아니다.

키는 기존 서버 설정 파일에 저장되고 공개 응답에는 존재 여부만 제공한다. 파일은
소유자 전용 권한으로 원자 교체되지만 암호화 저장이나 완전한 전원 장애 내구성을
보장하지 않는다. 설정 파일과 백업을 보호하고 키를 저장소·로그·브라우저 storage에
넣지 않는다. URL/제공자/정책 변경 시 기존 키를 암묵적으로 재사용할 수 없다.
자세한 역할·개인정보·자원 계약은 [LOCAL_AI.md](../LOCAL_AI.md)를 참고한다.

AI 작업은 admin도 원래 사용자·세션 경계를 우회할 수 없다. status/poll은 세션을
갱신하지 않는다. 추론 종료가 미확인인 `llm.provider` 기록은 감사 정리·재시작 후에도
차단을 유지한다. 단순 재시도나 오래된 DB 복원으로 이를 해제하지 않는다. 오프라인
복구는 TraceDNS와 이전 추론의 실제 정지를 운영자가 확인한 뒤 정확한 job ID로
수행하는 별도 확인 기록이며, 프로그램이 종료를 자동 증명하는 기능이 아니다.
호스팅 제공자의 실행 종료를 확인할 수 없다면 소켓 종료·키 변경·엔드포인트 교체를
정지 증거로 삼거나 `--confirm-provider-stopped`를 임의로 확인하지 않는다.

## 계정과 감사

저장된 대상 IP 재전송은 admin만 가능하며 legacy/versioned POST 모두 같은 Host/Origin,
세션·CSRF·사전 감사 경계를 사용한다. 본문은 최초 읽기부터 최대 4096바이트이고 임의
IP·destination·credential을 받지 않는다. `queued` 감사 결과는 접수이지 전달 완료가 아니다.
preview/confirmation은 검증된 `resend_id`로 연결하며 별도 보안 job을 만들지 않는다.
감사 완료 기록 장애나 네트워크 timeout 후에는 실제 접수가 됐을 수 있으므로 자동 재시도하지
않는다. 상세 운영 의미는 [DELIVERY_RESEND.md](../DELIVERY_RESEND.md)를 참고한다.

admin은 계정 생성·역할 변경·비활성화·임시 비밀번호 재설정·세션 철회와 전체 감사 로그/JSONL 내보내기를 수행한다. operator는 도메인과 분석/강제 조회를 관리한다. viewer는 저장된 관제 데이터만 본다. 마지막 활성 admin은 서버에서 보호한다.

감사는 UTC로 로그인, 계정/설정 변경, 권한 거절, 분석 및 강제 조회의 접수·완료/실패를 기록한다. 비밀번호, 세션·CSRF 토큰, API 키, webhook, 인증 URL은 기록/응답하지 않는다. 기본 보존은 180일이며 `--audit-retention-days`로 1–3650일을 지정한다.

감사 DB에 기록할 수 없으면 신규 사용자 작업은 503으로 차단된다. 기존 DNS 관측 루프는 유지되며 로그인한 UI에 감사 저장 장애가 표시된다. 재시작 시 완료되지 않은 intent는 `unknown`으로 보존한다.

## 백업과 복구

서비스를 중지한 뒤 private DB, `-wal`, `-shm`을 일관된 백업에 포함한다. 복원본의 소유자·권한을 검증하고, 필요하면 서버 로컬에서 `reset-password USER`를 실행한다. 감사 이벤트를 임의 수정하지 않는다.
