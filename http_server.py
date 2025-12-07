#!/usr/bin/env python3
"""
HTTP 서버 및 웹 UI 모듈
"""
import os
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

from config_manager import normalize_domains, write_config


def load_frontend_html():
    """
    프론트엔드 HTML을 로드합니다.
    기본 파일이 있으면 사용, 없으면 내장 폴백(간단)을 사용합니다.
    
    Returns:
        str: HTML 콘텐츠
    """
    path = os.path.join(os.path.dirname(__file__), "dns_frontend.html")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return "<html><body>Frontend missing</body></html>"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """스레드 기반 HTTP 서버"""
    daemon_threads = True


def make_handler(shared_config, config_lock, config_path, history_dir, current_results, history):
    """
    HTTP 요청 핸들러 클래스를 생성합니다.
    
    Args:
        shared_config (dict): 공유 설정 딕셔너리
        config_lock (threading.Lock): 설정 액세스 락
        config_path (str): 설정 파일 경로
        history_dir (str): 히스토리 디렉토리 경로
        current_results (dict): 현재 조회 결과
        history (dict): 히스토리 객체
    
    Returns:
        class: HTTP 요청 핸들러 클래스
    """
    frontend_html = load_frontend_html()

    class ConfigHandler(BaseHTTPRequestHandler):
        def _send_json(self, obj, code=200):
            """JSON 응답을 전송합니다."""
            b = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            """GET 요청 처리"""
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            
            if parsed.path == '/config':
                with config_lock:
                    cfg = {
                        'domains': list(shared_config.get('domains', [])),
                        'servers': list(shared_config.get('servers', [])),
                        'interval': shared_config.get('interval')
                    }
                self._send_json(cfg)
                return

            if parsed.path == '/results':
                try:
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
                    return self._send_json({'error': 'domain required'}, 400)
                h_obj = history.get(domain, {'meta': {}, 'events': [], 'current': {}})
                return self._send_json({'domain': domain, 'history': h_obj})

            if parsed.path == '/ip':
                ip = qs.get('ip', [None])[0]
                if not ip:
                    return self._send_json({'error': 'ip required'}, 400)
                matches = []
                
                # current results
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
                for d, hist_obj in history.items():
                    events = hist_obj.get('events', []) if isinstance(hist_obj, dict) else (hist_obj or [])
                    for ev in events:
                        rtype = ev.get('type', 'A')
                        ts = ev.get('ts', 0)
                        if 'new' in ev:
                            if rtype == 'A' and (ip in ev.get('new', {}).get('values', []) or ip in ev.get('old', {}).get('values', [])):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'rtype': rtype,
                                    'ts': ts,
                                    'old': ev.get('old'),
                                    'new': ev.get('new')
                                })
                            if rtype == 'TXT' and (ip in ev.get('new', {}).get('decoded_ips', []) or ip in ev.get('old', {}).get('decoded_ips', [])):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'rtype': rtype,
                                    'ts': ts,
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
                                    'ts': ts,
                                    'values': ev.get('values')
                                })
                            if rtype == 'TXT' and ip in ev.get('decoded_ips', []):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'rtype': rtype,
                                    'ts': ts,
                                    'values': ev.get('values'),
                                    'decoded_ips': ev.get('decoded_ips')
                                })
                return self._send_json({'ip': ip, 'matches': matches})

            if parsed.path == '/ips':
                # IP 집계: current_results + history를 합쳐 IP별 도메인, 카운트, 마지막 TS 계산
                try:
                    ip_map = {}
                    
                    # current results
                    for d, m in current_results.items():
                        for srv, info in m.items():
                            for ip in info.get('values', []) if info.get('type') == 'A' else []:
                                ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                ent['domains'].add(d)
                                ent['count'] += 1
                                ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
                            for ip in info.get('decoded_ips', []):
                                ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                ent['domains'].add(d)
                                ent['count'] += 1
                                ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
                    
                    # history events
                    for d, hist_obj in history.items():
                        events = hist_obj.get('events', []) if isinstance(hist_obj, dict) else (hist_obj or [])
                        for ev in events:
                            ts = ev.get('ts', 0)
                            if 'new' in ev or 'old' in ev:
                                for side in ('new', 'old'):
                                    side_obj = ev.get(side, {})
                                    for ip in side_obj.get('values', []) if ev.get('type', 'A') == 'A' else []:
                                        ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                        ent['domains'].add(d)
                                        ent['count'] += 1
                                        ent['last_ts'] = max(ent['last_ts'], ts)
                                    for ip in side_obj.get('decoded_ips', []) if ev.get('type', 'A') == 'TXT' else []:
                                        ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                        ent['domains'].add(d)
                                        ent['count'] += 1
                                        ent['last_ts'] = max(ent['last_ts'], ts)
                            elif 'values' in ev:
                                if ev.get('type', 'A') == 'A':
                                    for ip in ev.get('values', []):
                                        ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                                        ent['domains'].add(d)
                                        ent['count'] += 1
                                        ent['last_ts'] = max(ent['last_ts'], ts)
                                elif ev.get('type', 'A') == 'TXT':
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
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(b)))
                self.end_headers()
                self.wfile.write(b)
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            """POST 요청 처리"""
            parsed = urlparse(self.path)
            
            if parsed.path == '/config':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error': 'invalid json'}, 400)

                with config_lock:
                    if 'domains' in data:
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
                        'status': 'ok',
                        'domains': shared_config.get('domains'),
                        'servers': shared_config.get('servers'),
                        'interval': shared_config.get('interval')
                    }
                return self._send_json(resp)

            if parsed.path == '/resolve':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
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
                return self._send_json({'status': 'ok', 'requested': True})

            if parsed.path == '/ip':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error': 'invalid json'}, 400)
                ip = data.get('ip')
                if not ip:
                    return self._send_json({'error': 'ip required'}, 400)
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
                for d, hist_obj in history.items():
                    events = hist_obj.get('events', []) if isinstance(hist_obj, dict) else (hist_obj or [])
                    for ev in events:
                        rtype = ev.get('type', 'A')
                        if 'new' in ev:
                            if rtype == 'A' and (ip in ev.get('new', {}).get('values', []) or ip in ev.get('old', {}).get('values', [])):
                                matches.append({'domain': d, 'server': ev.get('server'), 'type': 'history', 'rtype': rtype, 'ts': ev.get('ts'), 'old': ev.get('old'), 'new': ev.get('new')})
                        elif 'values' in ev:
                            if rtype == 'A' and ip in ev.get('values', []):
                                matches.append({'domain': d, 'server': ev.get('server'), 'type': 'history', 'rtype': rtype, 'ts': ev.get('ts'), 'values': ev.get('values')})
                return self._send_json({'ip': ip, 'matches': matches})

            self.send_response(404)
            self.end_headers()

    return ConfigHandler
