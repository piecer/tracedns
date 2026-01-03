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

from config_manager import normalize_domains, write_config, read_config
import time
from txt_decoder import TXT_DECODE_METHODS, analyze_domain_decoding
try:
    from vt_lookup import get_ip_report
except Exception:
    # vt_lookup optional; if missing or import fails, get_ip_report will be treated as unavailable
    get_ip_report = None


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

        # ---- Handlers extracted for readability ----
        def _handle_config(self):
            with config_lock:
                cfg = {
                    'domains': list(shared_config.get('domains', [])),
                    'servers': list(shared_config.get('servers', [])),
                    'interval': shared_config.get('interval')
                }
            self._send_json(cfg)

        def _handle_results(self):
            try:
                data = {}
                for d, m in current_results.items():
                    data[d] = {}
                    for srv, info in m.items():
                        entry = {
                            'type': info.get('type'),
                            'values': list(info.get('values', [])),
                            'decoded_ips': list(info.get('decoded_ips', [])),
                            'ts': info.get('ts')
                        }
                        if info.get('type') == 'TXT' and info.get('txt_decode'):
                            entry['txt_decode'] = info.get('txt_decode')
                        data[d][srv] = entry
                self._send_json({'results': data})
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        def _handle_decoders(self):
            try:
                names = sorted(list(TXT_DECODE_METHODS.keys()))
                # include any registered custom decoder metadata from shared_config
                custom = list(shared_config.get('custom_decoders', []) or [])
                self._send_json({'decoders': names, 'custom': custom})
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        def _gather_ip_map(self):
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
            return ip_map

        def _handle_ips(self, qs):
            try:
                ip_map = self._gather_ip_map()
                # apply 'since' filter if requested (seconds)
                since_val = qs.get('since', [None])[0]
                cutoff = None
                if since_val is not None:
                    try:
                        s = int(since_val)
                        cutoff = int(time.time()) - s
                    except Exception:
                        cutoff = None

                include_vt = bool(int(qs.get('include_vt', ['0'])[0]) if qs.get('include_vt') else False)
                out = []
                for ip, v in ip_map.items():
                    # validate IP syntax
                    valid = True
                    try:
                        import ipaddress as _ip
                        _ip.ip_address(ip)
                    except Exception:
                        valid = False
                    if cutoff is not None and v.get('last_ts', 0) < cutoff:
                        continue
                    row = {
                        'ip': ip,
                        'domains': sorted(list(v['domains'])),
                        'count': v['count'],
                        'last_ts': v['last_ts'],
                        'valid': valid
                    }
                    # optionally include VirusTotal reputation info (requires env var VIRUSTOTAL_API_KEY)
                    if include_vt and get_ip_report:
                        try:
                            rep = get_ip_report(ip)
                            row['vt'] = rep
                        except Exception:
                            row['vt'] = None

                    out.append(row)
                out.sort(key=lambda x: (-x['count'], -x['last_ts']))
                self._send_json({'ips': out})
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        def _handle_history(self, domain):
            if not domain:
                return self._send_json({'error': 'domain required'}, 400)
            h_obj = history.get(domain, {'meta': {}, 'events': [], 'current': {}})
            return self._send_json({'domain': domain, 'history': h_obj})

        def _handle_ip_query(self, ip):
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

        def do_GET(self):
            """GET 요청 처리 (간단한 라우팅)"""
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)

            if parsed.path == '/config':
                return self._handle_config()
            if parsed.path == '/results':
                return self._handle_results()
            if parsed.path == '/decoders':
                return self._handle_decoders()
            if parsed.path == '/decoders/custom':
                # simple GET support to list allowed ops
                try:
                    ops = ['regex', 'base64', 'urlsafe_b64', 'xor_hex', 'extract_ip_prefix', 'ascii']
                    return self._send_json({'allowed_ops': ops})
                except Exception:
                    return self._send_json({'error': 'unable to list ops'}, 500)
            if parsed.path == '/history':
                domain = qs.get('domain', [None])[0]
                return self._handle_history(domain)
            if parsed.path == '/ip':
                ip = qs.get('ip', [None])[0]
                return self._handle_ip_query(ip)
            if parsed.path == '/ips':
                return self._handle_ips(qs)
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

            if parsed.path == '/analyze':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error': 'invalid json'}, 400)
                domain = data.get('domain')
                txt = data.get('txt') or data.get('sample')
                if not domain or not txt:
                    return self._send_json({'error': 'domain and txt required'}, 400)
                try:
                    res = analyze_domain_decoding(domain, txt)
                    # res is already a structured object with analysis and best
                    payload = {'domain': domain, 'sample': txt}
                    payload.update(res)
                    return self._send_json(payload)
                except Exception as e:
                    return self._send_json({'error': str(e)}, 500)

            if parsed.path == '/verify':
                # verify decoders for a list of domains (or all configured domains)
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error': 'invalid json'}, 400)

                domains = None
                if 'domains' in data and isinstance(data['domains'], list):
                    domains = [d.get('name') if isinstance(d, dict) else d for d in data['domains']]
                else:
                    # fallback to shared_config domains
                    with config_lock:
                        domains = [d.get('name') if isinstance(d, dict) else d for d in shared_config.get('domains', [])]

                results = {}
                for dom in domains:
                    if not dom:
                        continue
                    # gather a sample TXT value from current_results if available
                    sample_vals = []
                    for srv, info in (current_results.get(dom) or {}).items():
                        if info.get('type') == 'TXT':
                            sample_vals.extend(info.get('values', []) or [])
                    sample = '|'.join(sample_vals) if sample_vals else ''
                    try:
                        analysis = analyze_domain_decoding(dom, sample)
                    except Exception as e:
                        results[dom] = {'error': str(e)}
                        continue

                    # attach VT reports per decoded ip if available
                    for name, info in (analysis.get('analysis') or {}).items():
                        ips = info.get('ips', [])
                        detailed = []
                        for ip in ips:
                            valid = True
                            try:
                                import ipaddress as _ip
                                _ip.ip_address(ip)
                            except Exception:
                                valid = False
                            vt = None
                            if get_ip_report:
                                try:
                                    vt = get_ip_report(ip)
                                except Exception:
                                    vt = None
                            detailed.append({'ip': ip, 'valid': valid, 'vt': vt})
                        info['detailed_ips'] = detailed

                    results[dom] = analysis

                return self._send_json({'results': results})

            if parsed.path == '/decoders/custom' and self.command == 'POST':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error': 'invalid json'}, 400)

                name = data.get('name')
                steps = data.get('steps')
                if not name or not isinstance(steps, list):
                    return self._send_json({'error': 'name and steps required'}, 400)
                try:
                    # server-side validation: limit steps and sizes
                    if not isinstance(steps, list) or len(steps) == 0 or len(steps) > 12:
                        return self._send_json({'error': 'steps must be a non-empty list with <=12 steps'}, 400)
                    # each step size limits
                    total_chars = 0
                    import re as _re
                    for s in steps:
                        if not isinstance(s, dict) or 'op' not in s:
                            return self._send_json({'error': 'each step must be a dict with op field'}, 400)
                        total_chars += sum(len(str(v)) for v in s.values())
                        if total_chars > 2000:
                            return self._send_json({'error': 'steps too large'}, 400)
                        op = s.get('op')
                        if op == 'regex':
                            pat = s.get('pattern','')
                            if not isinstance(pat, str) or len(pat) > 300:
                                return self._send_json({'error': 'regex pattern too long'}, 400)
                            try:
                                _re.compile(pat)
                            except Exception as e:
                                return self._send_json({'error': 'invalid regex: '+str(e)}, 400)
                        if op == 'xor_hex':
                            key = s.get('key','')
                            if not isinstance(key, str) or len(key) > 128:
                                return self._send_json({'error': 'xor_hex key too long'}, 400)

                    from txt_decoder import register_custom_decoder
                    ok = register_custom_decoder(name, steps)
                    if not ok:
                        return self._send_json({'error': 'failed to register (name conflict or invalid steps)'}, 400)
                    # persist into shared_config and write to disk
                    with config_lock:
                        lst = shared_config.setdefault('custom_decoders', [])
                        # avoid duplicate names
                        exists = any(x.get('name') == name for x in lst)
                        if not exists:
                            lst.append({'name': name, 'steps': steps})
                        # write back to config file
                        if config_path:
                            try:
                                cfg = read_config(config_path) or {}
                                cfg['domains'] = cfg.get('domains', shared_config.get('domains', []))
                                cfg['servers'] = cfg.get('servers', shared_config.get('servers', []))
                                cfg['interval'] = cfg.get('interval', shared_config.get('interval'))
                                cfg['custom_decoders'] = lst
                                write_config(config_path, cfg)
                            except Exception:
                                pass
                        return self._send_json({'status': 'ok', 'registered': name})
                except Exception as e:
                    return self._send_json({'error': str(e)}, 500)

                if parsed.path == '/decoders/custom' and self.command == 'DELETE':
                    length = int(self.headers.get('Content-Length', '0'))
                    body = self.rfile.read(length) if length > 0 else b''
                    try:
                        data = json.loads(body.decode('utf-8')) if body else {}
                    except Exception:
                        return self._send_json({'error': 'invalid json'}, 400)
                    name = data.get('name')
                    if not name:
                        return self._send_json({'error': 'name required'}, 400)
                    try:
                        from txt_decoder import unregister_custom_decoder
                        ok = unregister_custom_decoder(name)
                        if not ok:
                            return self._send_json({'error': 'not removed (builtin or not found)'}, 400)
                        # remove from shared_config and persist
                        with config_lock:
                            lst = shared_config.get('custom_decoders', [])
                            newlst = [x for x in lst if x.get('name') != name]
                            shared_config['custom_decoders'] = newlst
                            if config_path:
                                try:
                                    cfg = read_config(config_path) or {}
                                    cfg['custom_decoders'] = newlst
                                    cfg['domains'] = cfg.get('domains', shared_config.get('domains', []))
                                    cfg['servers'] = cfg.get('servers', shared_config.get('servers', []))
                                    cfg['interval'] = cfg.get('interval', shared_config.get('interval'))
                                    write_config(config_path, cfg)
                                except Exception:
                                    pass
                        return self._send_json({'status': 'ok', 'removed': name})
                    except Exception as e:
                        return self._send_json({'error': str(e)}, 500)

                if parsed.path == '/decoders/custom' and self.command == 'PUT':
                    length = int(self.headers.get('Content-Length', '0'))
                    body = self.rfile.read(length) if length > 0 else b''
                    try:
                        data = json.loads(body.decode('utf-8')) if body else {}
                    except Exception:
                        return self._send_json({'error': 'invalid json'}, 400)
                    name = data.get('name')
                    steps = data.get('steps')
                    if not name or not isinstance(steps, list):
                        return self._send_json({'error': 'name and steps required'}, 400)
                    try:
                        # validate similar to register
                        if not isinstance(steps, list) or len(steps) == 0 or len(steps) > 12:
                            return self._send_json({'error': 'steps must be a non-empty list with <=12 steps'}, 400)
                        import re as _re
                        total_chars = 0
                        for s in steps:
                            if not isinstance(s, dict) or 'op' not in s:
                                return self._send_json({'error': 'each step must be a dict with op field'}, 400)
                            total_chars += sum(len(str(v)) for v in s.values())
                            if total_chars > 2000:
                                return self._send_json({'error': 'steps too large'}, 400)
                            if s.get('op') == 'regex':
                                pat = s.get('pattern','')
                                if not isinstance(pat, str) or len(pat) > 300:
                                    return self._send_json({'error': 'regex pattern too long'}, 400)
                                try:
                                    _re.compile(pat)
                                except Exception as e:
                                    return self._send_json({'error': 'invalid regex: '+str(e)}, 400)

                        from txt_decoder import unregister_custom_decoder, register_custom_decoder
                        # unregister old (if exists and not builtin)
                        unregister_custom_decoder(name)
                        ok = register_custom_decoder(name, steps)
                        if not ok:
                            return self._send_json({'error': 'failed to register updated decoder'}, 400)
                        # update shared_config and persist
                        with config_lock:
                            lst = shared_config.setdefault('custom_decoders', [])
                            # replace or append
                            replaced = False
                            for i,x in enumerate(lst):
                                if x.get('name') == name:
                                    lst[i] = {'name': name, 'steps': steps}
                                    replaced = True
                                    break
                            if not replaced:
                                lst.append({'name': name, 'steps': steps})
                            if config_path:
                                try:
                                    cfg = read_config(config_path) or {}
                                    cfg['custom_decoders'] = lst
                                    cfg['domains'] = cfg.get('domains', shared_config.get('domains', []))
                                    cfg['servers'] = cfg.get('servers', shared_config.get('servers', []))
                                    cfg['interval'] = cfg.get('interval', shared_config.get('interval'))
                                    write_config(config_path, cfg)
                                except Exception:
                                    pass
                        return self._send_json({'status': 'ok', 'updated': name})
                    except Exception as e:
                        return self._send_json({'error': str(e)}, 500)

            if parsed.path == '/decoders/custom/preview' and self.command == 'POST':
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error': 'invalid json'}, 400)
                steps = data.get('steps')
                sample = data.get('sample')
                if not isinstance(steps, list) or sample is None:
                    return self._send_json({'error': 'steps(list) and sample required'}, 400)
                try:
                    # validate steps similar to register path (but lighter)
                    if not isinstance(steps, list) or len(steps) == 0 or len(steps) > 12:
                        return self._send_json({'error': 'steps must be a non-empty list with <=12 steps'}, 400)
                    import re as _re
                    total_chars = 0
                    for s in steps:
                        if not isinstance(s, dict) or 'op' not in s:
                            return self._send_json({'error': 'each step must be a dict with op field'}, 400)
                        total_chars += sum(len(str(v)) for v in s.values())
                        if total_chars > 2000:
                            return self._send_json({'error': 'steps too large'}, 400)
                        if s.get('op') == 'regex':
                            pat = s.get('pattern','')
                            if not isinstance(pat, str) or len(pat) > 300:
                                return self._send_json({'error': 'regex pattern too long'}, 400)
                            try:
                                _re.compile(pat)
                            except Exception as e:
                                return self._send_json({'error': 'invalid regex: '+str(e)}, 400)

                    from txt_decoder import create_custom_decoder
                    dec = create_custom_decoder(steps)
                    if not dec:
                        return self._send_json({'error': 'invalid steps'}, 400)
                    res = dec([sample])
                    return self._send_json({'sample': sample, 'decoded': res})
                except Exception as e:
                    return self._send_json({'error': str(e)}, 500)

            self.send_response(404)
            self.end_headers()

    return ConfigHandler
