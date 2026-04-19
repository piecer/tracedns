# TraceDNS 리팩토링 가이드

TraceDNS는 초기에 단일 `dns_monitor.py` 중심으로 구현되었고, 현재는 모니터링 엔진, HTTP API, 런타임 상태, 프론트엔드가 단계적으로 분리된 구조입니다. 이 문서는 현재 코드 구조를 기준으로 유지보수 위치와 테스트 방법을 정리합니다.

## 현재 구조

### 실행 진입점

- `dns_monitor.py`: CLI 인자 처리, 설정 로드, HTTP 서버 시작, 모니터링 루프 실행을 담당합니다.
- `http_server.py`: `ThreadingHTTPServer` 구성과 웹 UI/API 핸들러 연결을 담당합니다.

### 모니터링 엔진

- `monitor/engine.py`: 도메인별 조회 사이클, 변경 감지, 알림 배치, 제거 IP reconciliation을 담당합니다.
- `monitor/collect.py`: DNS/ENS 조회 결과를 `Snapshot`으로 수집하고 TXT/A/ENS 디코더를 적용합니다.
- `monitor/runtime_state.py`: `current_results`와 `history`를 안전하게 snapshot으로 복제하고 상태 버전을 관리합니다.
- `monitor/lifecycle.py`, `monitor/state_utils.py`, `monitor/stores.py`: NXDOMAIN lifecycle, 활성 IP 집계, 설정 snapshot을 보조합니다.

### HTTP API

- `http_api_handlers.py`: 아직 남아 있는 대형 API 라우팅과 분석 핸들러를 포함합니다.
- `http_api/basic_handlers.py`: `/config`, `/results`, `/decoders` 같은 기본 조회 핸들러를 분리했습니다.
- `http_api/settings_handlers.py`: `/settings` 읽기/저장을 담당합니다.
- `http_api/relationship_handlers.py`: Botnet IP relationship 분석 API를 담당합니다.
- `http_api/context.py`, `http_api/utils.py`: 핸들러 공용 context와 JSON 응답 유틸리티입니다.

### 디코더와 외부 연동

- `txt_decoder.py`, `a_decoder.py`, `ens_decoder.py`: TXT/A/ENS 디코딩과 custom decoder DSL을 담당합니다.
- `dns_query.py`, `ens_query.py`: DNS 및 ENS 조회를 담당합니다.
- `vt_lookup.py`: VirusTotal 조회와 디스크 캐시를 담당합니다.
- `alerts.py`, `mispupdate_code.py`: Teams/MISP 알림과 MISP attribute/sighting 처리를 담당합니다.

### 프론트엔드

- `dns_frontend.html`, `dns_frontend.css`, `dns_frontend.js`: 웹 UI입니다.
- `dns_frontend.js`는 아직 큰 파일이므로, 향후에는 Status, Settings, Domain Analysis, Botnet IP Analysis 단위로 분리하는 것이 좋습니다.
- Botnet Graph/Map 렌더링은 브라우저 안정성을 위해 표시 개수 cap과 렌더 캐시를 사용합니다. 서버 API 응답 스키마는 그대로 유지하고, UI에서만 표시량을 제한합니다.

## 유지보수 원칙

- API 스키마와 `dns_config.json` 키 이름은 사용자 설정과 테스트가 의존하므로 임의 변경하지 않습니다.
- 공유 상태를 읽을 때는 `monitor.runtime_state`의 snapshot 함수를 우선 사용합니다.
- 상태 변경 후에는 필요한 경우 `bump_state_version()`을 호출해 `/results`, `/ips` 캐시가 갱신되도록 합니다.
- 대량 데이터 UI는 테이블/그래프/지도 렌더링을 한 번에 무제한 수행하지 않고, cap, in-flight guard, AbortController, render signature 캐시를 사용합니다.
- VT/MISP 같은 외부 연동은 테스트에서 실제 네트워크 호출에 의존하지 않도록 mock 또는 캐시 경로를 사용합니다.

## 테스트

repo 루트가 곧 `tracedns` 패키지 디렉터리라서, 테스트 실행 시 부모 디렉터리를 `PYTHONPATH`에 넣어야 합니다.

```bash
make test
```

위 명령은 다음과 동일합니다.

```bash
PYTHONPATH=$(pwd)/.. python3 -m unittest discover -s tests -p 'test_*.py' -v
```

브라우저 무응답 관련 변경을 검증할 때는 Botnet IP Analysis에서 300개 이상의 IP를 넣고, Relationships 설정을 `Top pairs=5000`, `Pair gate=off`, `Min score=0`으로 둔 뒤 Table/Graph/Map 전환을 반복해 확인합니다. VT API 호출이 필수는 아니며, VT off 또는 캐시된 응답으로도 UI 안정성을 확인할 수 있습니다.

## 향후 정리 후보

- `http_api_handlers.py`에 남은 POST 라우팅과 custom decoder 핸들러를 `http_api/` 하위 모듈로 더 분리합니다.
- `dns_frontend.js`를 화면 단위 모듈로 나누고 공통 DOM 렌더 유틸리티를 별도 파일로 이동합니다.
- 패키지 실행/테스트 편의를 위해 `pyproject.toml` 또는 명시적 package layout을 도입할 수 있습니다.
