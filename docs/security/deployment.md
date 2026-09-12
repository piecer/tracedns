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

## 계정과 감사

admin은 계정 생성·역할 변경·비활성화·임시 비밀번호 재설정·세션 철회와 전체 감사 로그/JSONL 내보내기를 수행한다. operator는 도메인과 분석/강제 조회를 관리한다. viewer는 저장된 관제 데이터만 본다. 마지막 활성 admin은 서버에서 보호한다.

감사는 UTC로 로그인, 계정/설정 변경, 권한 거절, 분석 및 강제 조회의 접수·완료/실패를 기록한다. 비밀번호, 세션·CSRF 토큰, API 키, webhook, 인증 URL은 기록/응답하지 않는다. 기본 보존은 180일이며 `--audit-retention-days`로 1–3650일을 지정한다.

감사 DB에 기록할 수 없으면 신규 사용자 작업은 503으로 차단된다. 기존 DNS 관측 루프는 유지되며 로그인한 UI에 감사 저장 장애가 표시된다. 재시작 시 완료되지 않은 intent는 `unknown`으로 보존한다.

## 백업과 복구

서비스를 중지한 뒤 private DB, `-wal`, `-shm`을 일관된 백업에 포함한다. 복원본의 소유자·권한을 검증하고, 필요하면 서버 로컬에서 `reset-password USER`를 실행한다. 감사 이벤트를 임의 수정하지 않는다.
