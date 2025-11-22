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

# dnspython 필요: pip install dnspython
try:
    import dns.resolver
except ImportError:
    print("ERROR: dnspython이 필요합니다. 설치: pip install dnspython", file=sys.stderr)
    sys.exit(1)

def read_config(path):
    """JSON 포맷: { "domains": ["a.com","b.com"], "servers": ["8.8.8.8","1.1.1.1"], "interval": 60 }"""
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            return cfg if isinstance(cfg, dict) else {}
    except Exception as e:
        print(f"[WARN] config load failed ({path}): {e}", file=sys.stderr)
        return {}

def write_config(path, cfg):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[WARN] config write failed ({path}): {e}", file=sys.stderr)

def query_dns(server, domain, timeout=2.0):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.timeout = timeout
    r.lifetime = timeout
    try:
        answers = r.resolve(domain, 'A')
        ips = sorted({str(a) for a in answers})
        return ips   # 변경: CSV 문자열이 아니라 리스트 반환
    except Exception:
        return None

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
                        'domains': list(shared_config.get('domains', [])),
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
                            data[d][srv] = {'ips': list(info.get('ips', [])), 'ts': info.get('ts')}
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
                # current
                for d, m in current_results.items():
                    for srv, info in m.items():
                        if ip in info.get('ips', []):
                            matches.append({
                                'domain': d,
                                'server': srv,
                                'type': 'current',
                                'ts': info.get('ts'),
                                'ips': list(info.get('ips', []))
                            })
                # history
                for d, events in history.items():
                    for ev in events:
                        # ev may contain 'old'/'new' or 'ips' depending on format; support both
                        # new style: ev = {'ts':..., 'server':..., 'old':{'ips':...,'ts':...}, 'new':{'ips':...,'ts':...}}
                        if 'new' in ev:
                            if ip in ev.get('new', {}).get('ips', []) or ip in ev.get('old', {}).get('ips', []):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'ts': ev.get('ts'),
                                    'old': ev.get('old'),
                                    'new': ev.get('new')
                                })
                        elif 'ips' in ev:
                            if ip in ev.get('ips', []):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'ts': ev.get('ts'),
                                    'ips': ev.get('ips')
                                })
                return self._send_json({'ip': ip, 'matches': matches})

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
                    # domains normalize (accept list or string)
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
                # POST /ip with JSON {"ip":"1.2.3.4"} to query
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length>0 else b''
                try:
                    data = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    return self._send_json({'error':'invalid json'}, 400)
                ip = data.get('ip')
                if not ip:
                    return self._send_json({'error':'ip required'}, 400)
                # reuse GET logic: perform same search
                matches = []
                for d, m in current_results.items():
                    for srv, info in m.items():
                        if ip in info.get('ips', []):
                            matches.append({
                                'domain': d,
                                'server': srv,
                                'type': 'current',
                                'ts': info.get('ts'),
                                'ips': list(info.get('ips', []))
                            })
                for d, events in history.items():
                    for ev in events:
                        if 'new' in ev:
                            if ip in ev.get('new', {}).get('ips', []) or ip in ev.get('old', {}).get('ips', []):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'ts': ev.get('ts'),
                                    'old': ev.get('old'),
                                    'new': ev.get('new')
                                })
                        elif 'ips' in ev:
                            if ip in ev.get('ips', []):
                                matches.append({
                                    'domain': d,
                                    'server': ev.get('server'),
                                    'type': 'history',
                                    'ts': ev.get('ts'),
                                    'ips': ev.get('ips')
                                })
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
    입력값을 도메인 리스트로 정규화:
    - list -> 각 항목을 comma/newline 으로 분해, strip, 빈값 제거, 중복 제거(순서 보존)
    - str  -> comma/newline 으로 분해, strip, 빈값 제거, 중복 제거
    """
    if not value:
        return []
    out = []
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    for it in items:
        if it is None:
            continue
        s = str(it)
        # 통일: comma 를 newline으로 바꾼 뒤 splitlines (CRLF 포함)
        parts = [p.strip() for p in s.replace(',', '\n').splitlines() if p.strip()]
        for p in parts:
            if p not in out:
                out.append(p)
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
            domains = normalize_domains(shared_config.get('domains', []))
            servers = list(shared_config.get('servers', []))
            interval = int(shared_config.get('interval') or 60)
            force_req = shared_config.pop('_force_resolve', None)

        # ensure entries exist
        for d in domains:
            current_results.setdefault(d, {})
            history.setdefault(d, [])

        target_domains = normalize_domains(force_req.get('domains')) if force_req and 'domains' in force_req else domains
        target_servers_override = force_req.get('servers') if force_req and 'servers' in force_req else None

        for d in target_domains:
            d = d.strip()
            if not d:
                continue
            svr_list = target_servers_override or servers
            for srv in svr_list:
                result_ips = query_dns(srv, d)  # now list or None
                if result_ips is None:
                    print(f"[ERROR] DNS {srv} query failed for {d}")
                    continue
                ts = int(time.time())
                prev = current_results.get(d, {}).get(srv)
                if prev is None:
                    current_results.setdefault(d, {})[srv] = {'ips': result_ips, 'ts': ts}
                    print(f"[INIT] {d} @ {srv} -> {result_ips}")
                else:
                    if prev.get('ips') != result_ips:
                        ev = {
                            'ts': ts,
                            'server': srv,
                            'old': {'ips': prev.get('ips', []), 'ts': prev.get('ts')},
                            'new': {'ips': result_ips, 'ts': ts}
                        }
                        history.setdefault(d, []).append(ev)
                        current_results[d][srv] = {'ips': result_ips, 'ts': ts}
                        print(f"[NOTICE] {d} @ {srv} changed: {prev.get('ips')} -> {result_ips}")
                        persist_history_entry(history_dir, d, history[d])
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