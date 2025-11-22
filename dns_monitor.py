#!/usr/bin/env python3
import time
import argparse
import sys
import signal
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
import base64
import logging
import struct

# dnspython 필요: pip install dnspython
try:
    import dns.resolver
except ImportError:
    print("ERROR: dnspython이 필요합니다. 설치: pip install dnspython", file=sys.stderr)
    sys.exit(1)

# DNS 쿼리 유틸 함수
def query_dns(server, domain, rtype='A', timeout=2.0):
    """
    server: 'x.y.z.w'
    domain: domain string
    rtype: 'A' or 'TXT'
    반환: 리스트 (성공) 또는 None(오류)
    """
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [server]
        r.timeout = timeout
        r.lifetime = timeout
        if rtype.upper() == 'TXT':
            answers = r.resolve(domain, 'TXT')
            vals = []
            for rr in answers:
                # dnspython: rr.strings 또는 str(rr)
                try:
                    if hasattr(rr, 'strings'):
                        parts = []
                        for s in rr.strings:
                            if isinstance(s, bytes):
                                parts.append(s.decode('utf-8', errors='ignore'))
                            else:
                                parts.append(str(s))
                        vals.append(''.join(parts))
                    else:
                        vals.append(str(rr))
                except Exception:
                    vals.append(str(rr))
            return sorted(list({v for v in vals if v is not None}))
        else:
            answers = r.resolve(domain, 'A')
            ips = sorted({str(a) for a in answers})
            return ips
    except Exception:
        return None

# 읽기/쓰기 유틸 추가
def read_config(path):
    """
    config JSON 파일을 읽어 dict 반환. 파일 경로가 비어있거나 읽기 실패 시 빈 dict 반환.
    """
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f) or {}
    except Exception as e:
        logging.warning("read_config failed (%s): %s", path, e)
        return {}

def write_config(path, cfg):
    """
    cfg(dict)를 지정된 경로에 JSON으로 저장. 실패 시 경고 로깅.
    """
    if not path:
        return
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.warning("write_config failed (%s): %s", path, e)

# TXT 디코딩 방식 레지스트리
TXT_DECODE_METHODS = {}

def txt_decode_register(name):
    def deco(fn):
        TXT_DECODE_METHODS[name] = fn
        return fn
    return deco

@txt_decode_register('cafebabe_xor_base64')
def decode_txt_cafebabe_xor_base64(txt_values):
    """
    기존 방식: base64 decode 후 0xcafebabe xor → 4byte ip
    """
    out = []
    seen = set()
    for v in txt_values or []:
        if not v: continue
        parts = [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]
        for part in parts:
            try:
                raw = base64.b64decode(part, validate=True)
                if len(raw) < 4:
                    continue
                val = int.from_bytes(raw[0:4], byteorder='big', signed=False)
                x = val ^ 0xcafebabe
                ip_bytes = x.to_bytes(4, byteorder='big')
                ip_str = '.'.join(str(b) for b in ip_bytes)
                if ip_str not in seen:
                    seen.add(ip_str)
                    out.append(ip_str)
            except Exception:
                continue
    return sorted(out)

# 예시: 새로운 방식 추가
@txt_decode_register('plain_base64')
def decode_txt_plain_base64(txt_values):
    """
    각 토큰을 base64 decode하여 4바이트를 바로 IP로 해석
    """
    out = []
    seen = set()
    for v in txt_values or []:
        if not v: continue
        parts = [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]
        for part in parts:
            try:
                raw = base64.b64decode(part, validate=True)
                if len(raw) < 4:
                    continue
                ip_bytes = raw[0:4]
                ip_str = '.'.join(str(b) for b in ip_bytes)
                if ip_str not in seen:
                    seen.add(ip_str)
                    out.append(ip_str)
            except Exception:
                continue
    return sorted(out)

# --- new/updated BTEA variant decoder (replace previous decode_txt_btea_variant) ---
def _u32(x: int) -> int:
    return x & 0xFFFFFFFF

def _key_u32_le(key: bytes):
    k = key[:16].ljust(16, b"\x00")
    return list(struct.unpack("<4I", k))

def _btea_decrypt_variant(buf: bytearray, k32):
    """
    변형 XXTEA 복호화 (스크립트 로직 반영)
    buf: bytearray (in-place)
    k32: list of 4 u32 little-endian
    """
    DELTA = 0x61C88647
    n = len(buf) // 4
    if n <= 1:
        return
    v = list(struct.unpack("<%dI" % n, buf))
    rounds = (0x34 // n) + 6
    s = _u32(-DELTA * rounds)
    y = v[0]
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 2, -1, -1):
            z = v[p]
            y_old = v[p+1]
            idx = ((p + 1) & 3) ^ e
            mx = (_u32((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) +
                  _u32((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ _u32((y ^ s) + (z ^ k32[idx]))
            v[p+1] = y = _u32(y_old - mx)
        z = v[n - 1]
        y0 = v[0]
        mx0 = (_u32((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) +
               _u32((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ _u32((y ^ s) + (z ^ k32[e]))
        v[0] = y = _u32(y0 - mx0)
        s = _u32(s + DELTA)
    buf[:] = struct.pack("<%dI" % n, *v)

def _b64decode_pad(s: str) -> bytes:
    s = s.strip()
    if len(s) % 4:
        s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s, validate=False)

def decode_txt_token(token: str, key: str = "bL8U5QfWAbQN6mPX") -> bytes:
    raw = bytearray(_b64decode_pad(token))
    # C 코드처럼 4바이트 단위 데이터만 TEA 적용
    if len(raw) >= 8 and (len(raw) % 4) == 0:
        try:
            k32 = _key_u32_le(key.encode("ascii"))
            _btea_decrypt_variant(raw, k32)
        except Exception:
            pass
    # trailing NUL 제거
    while raw and raw[-1] == 0:
        raw.pop()
    return bytes(raw)

def try_parse_ipv4_ascii(b: bytes) -> str:
    try:
        s = b.decode("ascii")
    except Exception:
        return ""
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return s
    return ""

@txt_decode_register('btea_variant')
def decode_txt_btea_variant(txt_values, key='bL8U5QfWAbQN6mPX'):
    """
    제공하신 스크립트 로직을 반영한 디코더.
    - 각 토큰을 base64->(조건부)변형-XXTEA 복호화->NUL 제거
    - plaintext가 ascii IPv4면 그대로 추가
    - 그렇지 않지만 4바이트 블록이면 BE/LE 후보 IP들을 추가(보조)
    """
    out = []
    seen = set()
    for v in txt_values or []:
        if not v:
            continue
        parts = [p.strip() for p in v.replace(',', '|').split('|') if p.strip()]
        for part in parts:
            s = part.strip()
            if not s:
                continue
            try:
                decoded = decode_txt_token(s, key=key)
            except Exception:
                continue
            # ASCII IPv4 직접 검사
            ip = try_parse_ipv4_ascii(decoded)
            if ip:
                if ip not in seen:
                    seen.add(ip)
                    out.append(ip)
                continue
            # 아닐 경우, hex/4바이트 블록 후보 BE/LE 생성 (스크립트처럼)
            if len(decoded) and (len(decoded) % 4) == 0:
                be_candidates = []
                le_candidates = []
                for i in range(0, len(decoded), 4):
                    a, b, c, d = decoded[i:i+4]
                    be_candidates.append(f"{a}.{b}.{c}.{d}")
                    le_candidates.append(f"{d}.{c}.{b}.{a}")
                # 추가: 포함되지 않은 후보만 추가
                for cand in be_candidates + le_candidates:
                    if cand not in seen:
                        seen.add(cand)
                        out.append(cand)
                continue
            # 마지막으로, decoded 텍스트에 마침표가 있고 숫자 조합이라면 시도해봄
            try:
                txt = decoded.decode('ascii', errors='ignore')
                parts_ip = txt.split('.')
                if len(parts_ip) == 4 and all(p.isdigit() for p in parts_ip):
                    # rotate? 스크립트에서는 회전하지 않으므로 그대로 사용
                    if txt not in seen:
                        seen.add(txt)
                        out.append(txt)
            except Exception:
                pass
    return sorted(out)

def decode_txt_hidden_ips(txt_values, method='cafebabe_xor_base64'):
    """
    txt_values: list of TXT strings
    method: 디코딩 방식 이름 (기본값: cafebabe_xor_base64)
    """
    fn = TXT_DECODE_METHODS.get(method)
    if not fn:
        return []
    return fn(txt_values)

# --- HTTP server for realtime config edits ---
def load_frontend_html():
    # 기본 파일이 있으면 사용, 없으면 내장 폴백(간단)
    path = os.path.join(os.path.dirname(__file__), "dns_frontend.html")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return "<html><body>Frontend missing</body></html>"

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def make_handler(shared_config, config_lock, config_path, history_dir, current_results, history):
    frontend_html = load_frontend_html()

    class ConfigHandler(BaseHTTPRequestHandler):
        def _send_json(self, obj, code=200):
            b = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            if parsed.path == '/config':
                with config_lock:
                    cfg = {
                        'domains': list(shared_config.get('domains', [])),  # list of dicts
                        'servers': list(shared_config.get('servers', [])),
                        'interval': shared_config.get('interval')
                    }
                self._send_json(cfg)
                return

            if parsed.path == '/results':
                try:
                    # copy current_results
                    data = {}
                    for d, m in current_results.items():
                        data[d] = {}
                        for srv, info in m.items():
                            data[d][srv] = {
                                'type': info.get('type'),
                                'values': list(info.get('values', [])),
                                'decoded_ips': list(info.get('decoded_ips', [])),
                                'ts': info.get('ts')
                            }
                    self._send_json({'results': data})
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
                return

            if parsed.path == '/history':
                domain = qs.get('domain', [None])[0]
                if not domain:
                    return self._send_json({'error':'domain required'}, 400)
                h = history.get(domain, [])
                return self._send_json({'domain': domain, 'history': h})

            if parsed.path == '/ip':
                ip = qs.get('ip', [None])[0]
                if not ip:
                    return self._send_json({'error':'ip required'}, 400)
                # search current_results and history for this ip
                matches = []
                # current (include decoded_ips)
                for d, m in current_results.items():
                    for srv, info in m.items():
                        # A records in values
                        if info.get('type') == 'A' and ip in info.get('values', []):
                            matches.append({
                                'domain': d,
                                'server': srv,
                                'type': 'current',
                                'rtype': 'A',
                                'ts': info.get('ts'),
                                'values': list(info.get('values', []))
                            })
                        # TXT-derived ips
                        if info.get('decoded_ips') and ip in info.get('decoded_ips', []):
                            matches.append({
                                'domain': d,
                                'server': srv,
                                'type': 'current',
                                'rtype': 'TXT-derived',
                                'ts': info.get('ts'),
                                'decoded_ips': list(info.get('decoded_ips', [])),
                                'values': list(info.get('values', []))
                            })
                # history
                for d, events in history.items():
                    for ev in events:
                        rtype = ev.get('type','A')
                        if 'new' in ev:
                            # check both old/new values and decoded ips if present
                            if rtype == 'A' and (ip in ev.get('new',{}).get('values',[]) or ip in ev.get('old',{}).get('values',[])):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'rtype': rtype,
                                    'ts': ev.get('ts'),
                                    'old': ev.get('old'),
                                    'new': ev.get('new')
                                })
                            if rtype == 'TXT':
                                if ip in ev.get('new',{}).get('decoded_ips',[]) or ip in ev.get('old',{}).get('decoded_ips',[]):
                                    matches.append({
                                        'domain': d,
                                        'server': ev.get('server'),
                                        'type': 'history',
                                        'rtype': rtype,
                                        'ts': ev.get('ts'),
                                        'old': ev.get('old'),
                                        'new': ev.get('new')
                                    })
                        elif 'values' in ev:
                            if rtype == 'A' and ip in ev.get('values', []):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'rtype': rtype,
                                    'ts': ev.get('ts'),
                                    'values': ev.get('values')
                                })
                            if rtype == 'TXT' and ip in ev.get('decoded_ips', []):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'rtype': rtype,
                                    'ts': ev.get('ts'),
                                    'values': ev.get('values'),
                                    'decoded_ips': ev.get('decoded_ips')
                                })
                return self._send_json({'ip': ip, 'matches': matches})

            if parsed.path == '/ips':
                # 전체 IP 집계: current_results + history 를 합쳐 IP별 도메인, 카운트, 마지막 TS 계산
                try:
                    ip_map = {}
                    # current
                    for d, m in current_results.items():
                        for srv, info in m.items():
                            for ip in info.get('values', []) if info.get('type')=='A' else []:
                                ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                ent['domains'].add(d)
                                ent['count'] += 1
                                ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
                            # include decoded ips from TXT
                            for ip in info.get('decoded_ips', []):
                                ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                ent['domains'].add(d)
                                ent['count'] += 1
                                ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
                    # history
                    for d, events in history.items():
                        for ev in events:
                            ts = ev.get('ts', 0)
                            if 'new' in ev or 'old' in ev:
                                for side in ('new','old'):
                                    side_obj = ev.get(side, {})
                                    for ip in side_obj.get('values', []) if ev.get('type','A')=='A' else []:
                                        ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                        ent['domains'].add(d)
                                        ent['count'] += 1
                                        ent['last_ts'] = max(ent['last_ts'], ts)
                                    for ip in side_obj.get('decoded_ips', []) if ev.get('type','A')=='TXT' else []:
                                        ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                        ent['domains'].add(d)
                                        ent['count'] += 1
                                        ent['last_ts'] = max(ent['last_ts'], ts)
                            elif 'values' in ev:
                                if ev.get('type','A') == 'A':
                                    for ip in ev.get('values', []):
                                        ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                        ent['domains'].add(d)
                                        ent['count'] += 1
                                        ent['last_ts'] = max(ent['last_ts'], ts)
                                elif ev.get('type','A') == 'TXT':
                                    for ip in ev.get('decoded_ips', []):
                                        ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                        ent['domains'].add(d)
                                        ent['count'] += 1
                                        ent['last_ts'] = max(ent['last_ts'], ts)
                    out = []
                    for ip, v in ip_map.items():
                        out.append({
                            'ip': ip,
                            'domains': sorted(list(v['domains'])),
                            'count': v['count'],
                            'last_ts': v['last_ts']
                        })
                    out.sort(key=lambda x: (-x['count'], -x['last_ts']))
                    self._send_json({'ips': out})
                except Exception as e:
                    self._send_json({'error': str(e)}, 500)
                return

            if parsed.path == '/':
                b = frontend_html.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type','text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(b)))
                self.end_headers()
                self.wfile.write(b)
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == '/config':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length>0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error':'invalid json'}, 400)

                with config_lock:
                    if 'domains' in data:
                        # domains can be list of strings or dicts
                        shared_config['domains'] = normalize_domains(data['domains'])
                    if 'servers' in data:
                        sv = data['servers']
                        if isinstance(sv, list):
                            shared_config['servers'] = [str(x).strip() for x in sv if str(x).strip()]
                        elif isinstance(sv, str):
                            shared_config['servers'] = [s.strip() for s in sv.split(',') if s.strip()]
                    if 'interval' in data:
                        try:
                            iv = int(data['interval'])
                            shared_config['interval'] = max(1, iv)
                        except Exception:
                            pass

                    if config_path:
                        to_write = {
                            'domains': shared_config.get('domains', []),
                            'servers': shared_config.get('servers', []),
                            'interval': shared_config.get('interval')
                        }
                        write_config(config_path, to_write)

                    resp = {
                        'status':'ok',
                        'domains': shared_config.get('domains'),
                        'servers': shared_config.get('servers'),
                        'interval': shared_config.get('interval')
                    }
                return self._send_json(resp)

            if parsed.path == '/resolve':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length>0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    data = {}

                with config_lock:
                    req = {}
                    if 'domains' in data:
                        req['domains'] = normalize_domains(data['domains'])
                    elif 'domain' in data:
                        req['domains'] = normalize_domains(data['domain'])
                    if 'servers' in data:
                        sv = data['servers']
                        if isinstance(sv, list):
                            req['servers'] = [str(x).strip() for x in sv if str(x).strip()]
                        elif isinstance(sv, str):
                            req['servers'] = [s.strip() for s in sv.split(',') if s.strip()]
                    shared_config['_force_resolve'] = req
                return self._send_json({'status':'ok', 'requested': True})

            if parsed.path == '/ip':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length>0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error':'invalid json'}, 400)
                ip = data.get('ip')
                if not ip:
                    return self._send_json({'error':'ip required'}, 400)
                matches = []
                for d, m in current_results.items():
                    for srv, info in m.items():
                        if info.get('type') == 'A' and ip in info.get('values', []):
                            matches.append({
                                'domain': d,
                                'server': srv,
                                'type': 'current',
                                'rtype': 'A',
                                'ts': info.get('ts'),
                                'values': list(info.get('values', []))
                            })
                for d, events in history.items():
                    for ev in events:
                        rtype = ev.get('type','A')
                        if 'new' in ev:
                            if rtype == 'A' and (ip in ev.get('new',{}).get('values',[]) or ip in ev.get('old',{}).get('values',[])):
                                matches.append({'domain': d, 'server': ev.get('server'), 'type':'history', 'rtype': rtype, 'ts': ev.get('ts'), 'old': ev.get('old'), 'new': ev.get('new')})
                        elif 'values' in ev:
                            if rtype == 'A' and ip in ev.get('values', []):
                                matches.append({'domain': d, 'server': ev.get('server'), 'type':'history', 'rtype': rtype, 'ts': ev.get('ts'), 'values': ev.get('values')})
                return self._send_json({'ip': ip, 'matches': matches})

            self.send_response(404)
            self.end_headers()

    return ConfigHandler

def ensure_history_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print(f"[WARN] cannot create history dir {path}: {e}", file=sys.stderr)

def load_history_files(history_dir):
    h = {}
    if not os.path.isdir(history_dir):
        return h
    for fn in os.listdir(history_dir):
        if not fn.endswith('.json'):
            continue
        dom = fn[:-5]
        try:
            with open(os.path.join(history_dir, fn), 'r', encoding='utf-8') as f:
                arr = json.load(f)
                if isinstance(arr, list):
                    h[dom] = arr
        except Exception:
            pass
    return h

def persist_history_entry(history_dir, domain, history_list):
    try:
        ensure_history_dir(history_dir)
        fn = os.path.join(history_dir, f"{domain}.json")
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(history_list, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[WARN] cannot persist history for {domain}: {e}", file=sys.stderr)

def normalize_domains(value):
    """
    반환: list of dicts: [{ 'name': 'example.com', 'type': 'A', 'txt_decode': 'cafebabe_xor_base64' }, ...]
    입력 허용:
      - dict에 txt_decode 필드가 있으면 그대로 반영
    """
    if not value:
        return []
    out = []
    seen = set()
    items = value if isinstance(value, list) else [value]
    for it in items:
        if it is None:
            continue
        if isinstance(it, dict):
            name = str(it.get('name','')).strip()
            typ = str(it.get('type','A')).upper() if it.get('type') else 'A'
            txt_decode = it.get('txt_decode')
        else:
            s = str(it)
            # split comma/newline
            parts = [p.strip() for p in s.replace(',', '\n').splitlines() if p.strip()]
            # each part default type A
            for p in parts:
                name = p
                typ = 'A'
                txt_decode = None
                if name and name not in seen:
                    out.append({'name': name, 'type': typ})
                    seen.add(name)
            continue
        if not name or name in seen:
            continue
        d = {'name': name, 'type': typ}
        if txt_decode:
            d['txt_decode'] = txt_decode
        out.append(d)
        seen.add(name)
    return out

def main():
    parser = argparse.ArgumentParser(description="DNS 모니터 (여러 도메인, 웹 UI)")
    parser.add_argument("-d", "--domains", default="", help="확인할 도메인들 (쉼표 또는 줄바꿈 구분)")
    parser.add_argument("-s", "--servers", default="8.8.8.8,1.1.1.1", help="검사할 DNS 서버 리스트(쉼표 구분)")
    parser.add_argument( "-i", "--interval", type=int, default=60, help="체크 간격(초)")
    parser.add_argument("-c", "--config", default="", help="설정 파일(JSON) 경로")
    parser.add_argument("--http-port", type=int, default=8000, help="웹 UI 포트")
    args = parser.parse_args()

    cli_specified = {
        'domains': any(o in sys.argv for o in ('-d','--domains')),
        'servers': any(o in sys.argv for o in ('-s','--servers')),
        'interval': any(o in sys.argv for o in ('-i','--interval'))
    }

    # parse CLI domains
    if args.domains:
        if '\n' in args.domains or ',' in args.domains:
            domains_arg = [s.strip() for s in args.domains.replace(',', '\n').splitlines() if s.strip()]
        else:
            domains_arg = [args.domains.strip()]
    else:
        domains_arg = []

    servers_arg = [s.strip() for s in args.servers.split(",") if s.strip()]
    interval_arg = max(1, args.interval)
    config_path = args.config
    http_port = args.http_port

    # load file config once
    file_cfg = read_config(config_path)
    domains0 = domains_arg if cli_specified['domains'] else file_cfg.get('domains', domains_arg or [])
    if isinstance(domains0, str):
        domains0 = [s.strip() for s in domains0.replace(',', '\n').splitlines() if s.strip()]
    if cli_specified['servers']:
        servers0 = servers_arg
    else:
        fs = file_cfg.get('servers')
        if isinstance(fs, list):
            servers0 = [str(s).strip() for s in fs if str(s).strip()]
        elif isinstance(fs, str):
            servers0 = [s.strip() for s in fs.split(',') if s.strip()]
        else:
            servers0 = servers_arg
    interval0 = interval_arg if cli_specified['interval'] else int(file_cfg.get('interval', interval_arg))

    # shared config
    config_lock = threading.Lock()
    shared_config = {
        'domains': domains0,
        'servers': servers0,
        'interval': max(1, int(interval0))
    }

    # history persistence dir (next to config file if provided, else local ./dns_history)
    if config_path:
        history_dir = config_path + ".history"
    else:
        history_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_history")
    ensure_history_dir(history_dir)

    # in-memory result & history
    current_results = {}   # { domain: { server: "ip,ip" } }
    history = load_history_files(history_dir)  # { domain: [events...] }

    # start HTTP server
    handler_class = make_handler(shared_config, config_lock, config_path, history_dir, current_results, history)
    httpd = ThreadingHTTPServer(('0.0.0.0', http_port), handler_class)
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()
    print(f"[INFO] HTTP config UI running on http://0.0.0.0:{http_port}/")

    running = True
    def handle_sigint(signum, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, handle_sigint)

    while running:
        with config_lock:
            domains = normalize_domains(shared_config.get('domains', []))  # list of dicts
            servers = list(shared_config.get('servers', []))
            interval = int(shared_config.get('interval') or 60)
            force_req = shared_config.pop('_force_resolve', None)

        for dobj in domains:
            current_results.setdefault(dobj['name'], {})
            history.setdefault(dobj['name'], [])

        if force_req and 'domains' in force_req:
            target_domains = normalize_domains(force_req.get('domains'))
        else:
            target_domains = domains

        target_servers_override = force_req.get('servers') if force_req and 'servers' in force_req else None

        for dobj in target_domains:
            name = dobj.get('name','').strip()
            rtype = dobj.get('type','A').upper()
            txt_decode = dobj.get('txt_decode', 'cafebabe_xor_base64')
            if not name:
                continue
            svr_list = target_servers_override or servers
            for srv in svr_list:
                result_vals = query_dns(srv, name, rtype=rtype)
                if result_vals is None:
                    print(f"[ERROR] DNS {srv} query failed for {name} ({rtype})")
                    continue
                ts = int(time.time())
                decoded = []
                if rtype == 'TXT':
                    decoded = decode_txt_hidden_ips(result_vals, method=txt_decode)
                prev = current_results.get(name, {}).get(srv)
                if prev is None:
                    current_results.setdefault(name, {})[srv] = {
                        'type': rtype,
                        'values': result_vals,
                        'decoded_ips': decoded,
                        'ts': ts
                    }
                    print(f"[INIT] {name} ({rtype}) @ {srv} -> {result_vals} decoded:{decoded}")
                else:
                    if prev.get('values') != result_vals or prev.get('type') != rtype:
                        ev = {
                            'ts': ts,
                            'server': srv,
                            'type': rtype,
                            'old': {'values': prev.get('values', []), 'decoded_ips': prev.get('decoded_ips', []), 'ts': prev.get('ts')},
                            'new': {'values': result_vals, 'decoded_ips': decoded, 'ts': ts}
                        }
                        history.setdefault(name, []).append(ev)
                        current_results[name][srv] = {
                            'type': rtype,
                            'values': result_vals,
                            'decoded_ips': decoded,
                            'ts': ts
                        }
                        print(f"[NOTICE] {name} ({rtype}) @ {srv} changed: {prev.get('values')} -> {result_vals} decoded:{decoded}")
                        persist_history_entry(history_dir, name, history[name])
                    # else unchanged

        # sleep ticks
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

    print("Exiting DNS monitor.")
    httpd.shutdown()
    httpd.server_close()

if __name__ == "__main__":
    main()