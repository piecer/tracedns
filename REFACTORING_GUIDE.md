# DNS Monitor 리팩토링 가이드

기존 `dns_monitor.py`를 기능별로 분리하여 코드의 가독성과 유지보수성을 개선했습니다.

## 파일 구조

### 1. **dns_monitor.py** (225줄)
메인 애플리케이션. DNS 모니터링 루프와 프로그램 초기화를 담당합니다.

**주요 기능:**
- CLI 인자 파싱
- 설정 파일 로드
- 타이머 기반 모니터링 루프
- HTTP 서버 시작
- 신호 처리 (SIGINT)

**사용법:**
```bash
python dns_monitor.py -d example.com,test.com -s 8.8.8.8,1.1.1.1 -i 60 --http-port 8000
```

---

### 2. **dns_query.py** (59줄)
DNS 쿼리를 실행합니다.

**주요 함수:**
- `query_dns(server, domain, rtype='A', timeout=2.0)`: DNS A/TXT 레코드 조회

**특징:**
- dnspython 라이브러리 사용
- 타임아웃 설정 지원
- 오류 처리

---

### 3. **txt_decoder.py** (256줄)
TXT 레코드에서 인코딩된 IP 주소를 디코딩합니다.

**주요 함수:**
- `decode_txt_hidden_ips(txt_values, method='cafebabe_xor_base64')`: 디코딩 실행

**지원하는 디코딩 방식:**
- `cafebabe_xor_base64`: Base64 디코드 후 0xcafebabe XOR
- `plain_base64`: Base64 디코드 후 직접 해석
- `btea_variant`: BTEA(Simplified XXTEA) 암호화 복호화

**특징:**
- 플러그인 방식 디코더 레지스트리
- 새 디코더 쉽게 추가 가능

---

### 4. **config_manager.py** (93줄)
설정 파일 읽기/쓰기 및 데이터 정규화

**주요 함수:**
- `read_config(path)`: JSON 설정 파일 읽기
- `write_config(path, cfg)`: JSON 설정 파일 쓰기
- `normalize_domains(value)`: 도메인 정보 정규화

**특징:**
- 다양한 입력 형식 지원
- 안전한 에러 처리

---

### 5. **history_manager.py** (99줄)
모니터링 히스토리 관리

**주요 함수:**
- `load_history_files(history_dir)`: 히스토리 파일 로드
- `persist_history_entry(history_dir, domain, history_obj)`: 히스토리 저장
- `ensure_history_dir(path)`: 디렉토리 생성

**특징:**
- 레거시 호환성 지원
- 구조화된 히스토리 포맷

---

### 6. **http_server.py** (361줄)
웹 UI 및 REST API 서버

**주요 클래스:**
- `ThreadingHTTPServer`: 멀티스레드 HTTP 서버
- `ConfigHandler`: HTTP 요청 처리

**엔드포인트:**
- `GET /`: 웹 UI (HTML)
- `GET /config`: 현재 설정
- `GET /results`: 현재 조회 결과
- `GET /history`: 도메인 히스토리
- `GET /ip`: IP 검색
- `GET /ips`: 모든 IP 집계
- `POST /config`: 설정 수정
- `POST /resolve`: 강제 조회 요청

**특징:**
- 실시간 설정 변경 지원
- JSON 기반 API

---

## 의존성 관계

```
dns_monitor.py
├── dns_query.py
├── txt_decoder.py
├── config_manager.py
├── history_manager.py
└── http_server.py
    └── config_manager.py
```

---

## 마이그레이션 노트

### 이전
```bash
python dns_monitor_old.py.bak
```

### 이후
```bash
python dns_monitor.py
```

기능은 동일하며, 코드만 모듈화되었습니다.

---

## 새 모듈 추가 예시

### TXT 디코더 추가
```python
# txt_decoder.py 에 다음 추가

@txt_decode_register('my_custom_format')
def decode_txt_my_custom_format(txt_values):
    """내 커스텀 포맷 디코더"""
    # 구현...
    return ip_list
```

그 후 DNS 설정에서:
```json
{
  "domains": [
    {
      "name": "example.com",
      "type": "TXT",
      "txt_decode": "my_custom_format"
    }
  ]
}
```

---

## 테스트

각 모듈을 독립적으로 테스트할 수 있습니다:

```python
from dns_query import query_dns
from txt_decoder import decode_txt_hidden_ips
from config_manager import read_config, normalize_domains

# DNS 쿼리
result = query_dns('8.8.8.8', 'example.com')

# TXT 디코딩
decoded = decode_txt_hidden_ips(['encoded_value'])

# 설정 읽기
cfg = read_config('dns_config.json')
```

---

## 백업

기존 원본 파일은 `dns_monitor_old.py.bak`로 백업되어 있습니다.
