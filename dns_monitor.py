#!/usr/bin/env python3
"""
DNS 모니터 메인 애플리케이션
여러 도메인을 여러 DNS 서버에서 모니터링하고 웹 UI를 통해 결과를 확인합니다.
"""
import time
import argparse
import sys
import signal
import threading
import logging
import os

from dns_query import query_dns
from txt_decoder import decode_txt_hidden_ips, register_custom_decoder
from config_manager import read_config, normalize_domains, write_config
from history_manager import load_history_files, persist_history_entry, ensure_history_dir
from http_server import ThreadingHTTPServer, make_handler


def main():
    """메인 함수: DNS 모니터링을 시작합니다."""
    parser = argparse.ArgumentParser(description="DNS 모니터 (여러 도메인, 웹 UI)")
    parser.add_argument("-d", "--domains", default="", help="확인할 도메인들 (쉼표 또는 줄바꿈 구분)")
    parser.add_argument("-s", "--servers", default="8.8.8.8,1.1.1.1", help="검사할 DNS 서버 리스트(쉼표 구분)")
    parser.add_argument("-i", "--interval", type=int, default=60, help="체크 간격(초)")
    parser.add_argument("-c", "--config", default="dns_config.json", help="설정 파일(JSON) 경로")
    parser.add_argument("--http-port", type=int, default=8000, help="웹 UI 포트")
    args = parser.parse_args()

    cli_specified = {
        'domains': any(o in sys.argv for o in ('-d', '--domains')),
        'servers': any(o in sys.argv for o in ('-s', '--servers')),
        'interval': any(o in sys.argv for o in ('-i', '--interval'))
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

    # restore custom decoders from file config (if any) and register at runtime
    file_custom = file_cfg.get('custom_decoders', []) if isinstance(file_cfg, dict) else []
    shared_config['custom_decoders'] = []
    for entry in file_custom:
        try:
            name = entry.get('name') if isinstance(entry, dict) else None
            steps = entry.get('steps') if isinstance(entry, dict) else None
            if name and isinstance(steps, list):
                ok = register_custom_decoder(name, steps)
                if ok:
                    shared_config['custom_decoders'].append({'name': name, 'steps': steps})
        except Exception:
            continue

    # history persistence dir
    if config_path:
        history_dir = config_path + ".history"
    else:
        history_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_history")
    ensure_history_dir(history_dir)

    # in-memory result & history
    current_results = {}   # { domain: { server: snapshot } }
    history = load_history_files(history_dir)  # { domain: {meta, events, current} }

    # restore current_results from history if present
    for domain, hist_obj in list(history.items()):
        curr = hist_obj.get('current', {}) if isinstance(hist_obj, dict) else {}
        if isinstance(curr, dict) and curr:
            current_results.setdefault(domain, {})
            # copy snapshot servers
            for srv, snap in curr.items():
                current_results[domain][srv] = {
                    'type': snap.get('type'),
                    'values': snap.get('values', []),
                    'decoded_ips': snap.get('decoded_ips', []),
                    'ts': snap.get('ts', 0)
                }

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
            name = dobj.get('name', '').strip()
            # ensure history has dict structure
            if name and name not in history:
                history[name] = {'meta': {}, 'events': [], 'current': {}}
            current_results.setdefault(dobj['name'], {})

        if force_req and 'domains' in force_req:
            target_domains = normalize_domains(force_req.get('domains'))
        else:
            target_domains = domains

        target_servers_override = force_req.get('servers') if force_req and 'servers' in force_req else None

        for dobj in target_domains:
            time.sleep(1)
            name = dobj.get('name', '').strip()
            rtype = dobj.get('type', 'A').upper()
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
                    # pass domain name to decoder so domain-specific rules can be applied
                    decoded = decode_txt_hidden_ips(result_vals, method=txt_decode, domain=name)
                prev = current_results.get(name, {}).get(srv)
                # ensure history dict exists
                history.setdefault(name, {'meta': {}, 'events': [], 'current': {}})
                hist_obj = history[name]
                if prev is None:
                    # initial population: record snapshot and meta.first_seen if missing
                    snap = {
                        'type': rtype,
                        'values': result_vals,
                        'decoded_ips': decoded,
                        'ts': ts
                    }
                    if rtype == 'TXT':
                        snap['txt_decode'] = txt_decode
                    current_results.setdefault(name, {})[srv] = snap
                    # update history current snapshot
                    hist_snap = {
                        'type': rtype,
                        'values': result_vals,
                        'decoded_ips': decoded,
                        'ts': ts
                    }
                    if rtype == 'TXT':
                        hist_snap['txt_decode'] = txt_decode
                    hist_obj.setdefault('current', {})[srv] = hist_snap
                    # set first_seen if missing
                    meta = hist_obj.setdefault('meta', {})
                    if not meta.get('first_seen'):
                        meta['first_seen'] = ts
                    # set last_changed if not present
                    if not meta.get('last_changed'):
                        meta['last_changed'] = ts
                    print(f"[INIT] {name} ({rtype}) @ {srv} -> {result_vals} decoded:{decoded}")
                    # persist so restarts can reuse
                    persist_history_entry(history_dir, name, hist_obj)
                else:
                    if prev.get('values') != result_vals or prev.get('type') != rtype:
                        ev = {
                            'ts': ts,
                            'server': srv,
                            'type': rtype,
                            'old': {'values': prev.get('values', []), 'decoded_ips': prev.get('decoded_ips', []), 'ts': prev.get('ts')},
                            'new': {'values': result_vals, 'decoded_ips': decoded, 'ts': ts}
                        }
                        # append event, update meta and current snapshot
                        hist_obj.setdefault('events', []).append(ev)
                        meta = hist_obj.setdefault('meta', {})
                        meta['last_changed'] = ts
                        if not meta.get('first_seen'):
                            meta['first_seen'] = ev['old'].get('ts', ts)
                        snap_update = {
                            'type': rtype,
                            'values': result_vals,
                            'decoded_ips': decoded,
                            'ts': ts
                        }
                        if rtype == 'TXT':
                            snap_update['txt_decode'] = txt_decode
                        hist_obj.setdefault('current', {})[srv] = snap_update
                        current_results[name][srv] = snap_update
                        print(f"[NOTICE] {name} ({rtype}) @ {srv} changed: {prev.get('values')} -> {result_vals} decoded:{decoded}")
                        persist_history_entry(history_dir, name, hist_obj)
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
