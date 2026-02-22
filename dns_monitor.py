#!/usr/bin/env python3
"""TraceDNS main entry.

This file should stay thin: argument parsing, config loading, HTTP server wiring,
then delegating work to the monitoring engine.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time

from alerts import init_from_alerts as alerts_init_from_dict
from alerts import init_from_config as alerts_init
from config_manager import normalize_domains, read_config
from history_manager import ensure_history_dir, load_history_files
from http_server import ThreadingHTTPServer, make_handler
from monitor.engine import reconcile_removed_ips, run_full_cycle
from monitor.state_utils import collect_active_ip_map
from txt_decoder import register_custom_decoder


logger = logging.getLogger(__name__)


def _setup_logging():
    level = os.environ.get('TRACEDNS_LOG_LEVEL', 'INFO').upper().strip()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format='[%(levelname)s] %(asctime)s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )


def main():
    _setup_logging()

    parser = argparse.ArgumentParser(description="DNS monitor (multiple domains, web UI)")
    parser.add_argument("-d", "--domains", default="", help="Domains to monitor (comma or newline separated)")
    parser.add_argument("-s", "--servers", default="8.8.8.8,1.1.1.1", help="Comma-separated list of DNS servers to query")
    parser.add_argument("-i", "--interval", type=int, default=60, help="Check interval in seconds")
    parser.add_argument("-c", "--config", default="dns_config.json", help="Path to JSON config file")
    parser.add_argument("--http-port", type=int, default=8000, help="HTTP UI port")
    parser.add_argument("--max-workers", type=int, default=8, help="Max worker threads for per-domain parallel DNS queries")
    args = parser.parse_args()

    cli_specified = {
        'domains': any(o in sys.argv for o in ('-d', '--domains')),
        'servers': any(o in sys.argv for o in ('-s', '--servers')),
        'interval': any(o in sys.argv for o in ('-i', '--interval')),
        'max_workers': any(o in sys.argv for o in ('--max-workers',)),
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
    interval_arg = max(1, int(args.interval))
    config_path = args.config
    http_port = int(args.http_port)
    max_workers_arg = max(1, int(args.max_workers))

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
    max_workers0 = max_workers_arg if cli_specified['max_workers'] else int(file_cfg.get('max_workers', max_workers_arg))

    # shared config state (mutated by HTTP API)
    config_lock = threading.Lock()
    shared_config = {
        'domains': domains0,
        'servers': servers0,
        'interval': max(1, int(interval0)),
        'max_workers': max(1, int(max_workers0)),
    }

    # restore custom TXT decoders from file config (if any)
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

    # restore custom A decoders
    file_custom_a = file_cfg.get('custom_a_decoders', []) if isinstance(file_cfg, dict) else []
    shared_config['custom_a_decoders'] = []
    for entry in file_custom_a:
        try:
            name = entry.get('name') if isinstance(entry, dict) else None
            steps = entry.get('steps') if isinstance(entry, dict) else None
            if name and isinstance(steps, list):
                from a_decoder import register_custom_a_decoder

                ok = register_custom_a_decoder(name, steps)
                if ok:
                    shared_config['custom_a_decoders'].append({'name': name, 'steps': steps, 'decoder_type': 'A'})
        except Exception:
            continue

    # restore alert settings from file config (if any)
    alerts_cfg = {}
    try:
        alerts_cfg = file_cfg.get('alerts') if isinstance(file_cfg, dict) else None
        if alerts_cfg:
            shared_config['alerts'] = alerts_cfg
            # Apply VT API key to vt_lookup module
            try:
                vt_key = alerts_cfg.get('vt_api_key')
                if vt_key:
                    from vt_lookup import set_api_key

                    set_api_key(vt_key)
            except Exception:
                pass
            # Apply VT cache TTL
            try:
                ttl_days = alerts_cfg.get('vt_cache_ttl_days')
                if ttl_days not in (None, ''):
                    from vt_lookup import set_cache_ttl_days

                    set_cache_ttl_days(ttl_days)
            except Exception:
                pass
    except Exception:
        shared_config['alerts'] = {}
        alerts_cfg = {}

    # initialize alerting (Teams + MISP)
    alerting_ready = False
    if isinstance(alerts_cfg, dict) and alerts_cfg:
        try:
            alerting_ready = bool(alerts_init_from_dict(alerts_cfg))
        except Exception:
            alerting_ready = False
    if not alerting_ready:
        try:
            alerting_ready = bool(alerts_init('config.ini'))
        except Exception:
            try:
                alerting_ready = bool(alerts_init())
            except Exception:
                alerting_ready = False

    # history persistence dir
    history_dir = (config_path + ".history") if config_path else os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_history")
    ensure_history_dir(history_dir)

    # in-memory result & history
    current_results = {}  # { domain: { server: snapshot } }
    history = load_history_files(history_dir)  # { domain: {meta, events, current} }

    # restore current_results from history if present
    for domain, hist_obj in list(history.items()):
        curr = hist_obj.get('current', {}) if isinstance(hist_obj, dict) else {}
        if isinstance(curr, dict) and curr:
            current_results.setdefault(domain, {})
            for srv, snap in curr.items():
                restored = {
                    'type': snap.get('type'),
                    'values': snap.get('values', []),
                    'decoded_ips': snap.get('decoded_ips', []),
                    'ts': snap.get('ts', 0),
                }
                if snap.get('txt_decode'):
                    restored['txt_decode'] = snap.get('txt_decode')
                if snap.get('a_decode'):
                    restored['a_decode'] = snap.get('a_decode')
                if snap.get('a_xor_key'):
                    restored['a_xor_key'] = snap.get('a_xor_key')
                current_results[domain][srv] = restored

    configured_names = {d.get('name', '').strip() for d in normalize_domains(shared_config.get('domains', [])) if isinstance(d, dict) and d.get('name')}
    active_ip_map_prev = collect_active_ip_map(current_results, configured_names)

    # start HTTP server
    handler_class = make_handler(shared_config, config_lock, config_path, history_dir, current_results, history)
    httpd = ThreadingHTTPServer(('0.0.0.0', http_port), handler_class)
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()
    logger.info("HTTP config UI running on http://0.0.0.0:%s/", http_port)

    running = True

    def handle_sigint(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, handle_sigint)

    # Consecutive DNS query failure counters: key=(domain, server, rtype)
    query_fail_counts = {}

    while running:
        with config_lock:
            domains = normalize_domains(shared_config.get('domains', []))
            servers = list(shared_config.get('servers', []))
            interval = int(shared_config.get('interval') or 60)
            max_workers = int(shared_config.get('max_workers') or 8)
            force_req = shared_config.pop('_force_resolve', None)

        active_ip_map_now = run_full_cycle(
            domains_raw=domains,
            servers=servers,
            current_results=current_results,
            history=history,
            history_dir=history_dir,
            query_fail_counts=query_fail_counts,
            max_workers=max_workers,
            force_req=force_req,
        )

        # reconcile removed IPs only for full scans
        if not (force_req and 'domains' in force_req):
            active_ip_map_prev = reconcile_removed_ips(active_ip_map_prev, active_ip_map_now)

        # sleep ticks
        for _ in range(max(1, interval)):
            if not running:
                break
            time.sleep(1)

    logger.info("Exiting DNS monitor.")
    httpd.shutdown()
    httpd.server_close()


if __name__ == "__main__":
    main()
