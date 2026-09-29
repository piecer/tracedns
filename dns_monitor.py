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
from copy import deepcopy

from alerts import init_from_alerts as alerts_init_from_dict  # noqa: F401 - legacy import seam
from alerts import init_from_config as alerts_init  # noqa: F401 - legacy import seam
from config_manager import normalize_domains, read_config
from sns_query import DEFAULT_SOLAR_PROXY_HOSTS
from history_manager import ensure_history_dir, load_history_files
from http_server import ThreadingHTTPServer, make_handler
from monitor.diagnostics import diagnostic_reason
from monitor.engine import (
    clear_query_failure as _clear_query_failure_impl,
    drop_snapshot_for_failed_target as _drop_snapshot_for_failed_target_impl,
    mark_query_failure as _mark_query_failure_impl,
    reconcile_removed_ips as reconcile_removed_ips,
    reconcile_scan,
    run_full_cycle,
)
from monitor.lifecycle import update_nxdomain_lifecycle as _update_nxdomain_lifecycle_impl
from monitor.removal_grace import IpRemovalGraceTracker as IpRemovalGraceTracker
from monitor.runtime_state import clone_snapshot
from monitor.state_utils import collect_active_ip_map
from monitor.stores import bounded_int, ConfigStore
from monitor.scheduler import MonitorScheduler
from monitor.signal_stop import SignalStopBridge
from monitor.targets import active_target_projection
from monitor.config_service import ConfigError, ConfigService


logger = logging.getLogger(__name__)


# Compatibility wrappers for legacy tests/imports.
def _mark_query_failure(fail_counts, key):
    return _mark_query_failure_impl(fail_counts, key)


def _clear_query_failure(fail_counts, key):
    return _clear_query_failure_impl(fail_counts, key)


def _drop_snapshot_for_failed_target(current_results, history, name, srv, ts=None):
    return _drop_snapshot_for_failed_target_impl(current_results, history, name, srv, ts=ts)


def _update_nxdomain_lifecycle(history, name, query_total, success_count, nxdomain_count, error_count, ts_now):
    return _update_nxdomain_lifecycle_impl(
        history,
        name,
        query_total=query_total,
        success_count=success_count,
        nxdomain_count=nxdomain_count,
        error_count=error_count,
        ts_now=ts_now,
    )


def _build_initial_new_ip_tuples(rtype, domain, values=None, decoded_ips=None):
    if not domain:
        return []
    r = str(rtype or '').upper()
    if r in ('TXT', 'ENS', 'SNS'):
        ips = sorted(set(decoded_ips or []))
    elif r == 'A':
        ips = sorted(set(values or []))
    else:
        ips = []
    return [(ip, domain, r) for ip in ips if str(ip or '').strip()]


def _build_changed_new_ip_tuples(
    rtype,
    domain,
    prev_values=None,
    new_values=None,
    prev_decoded_ips=None,
    new_decoded_ips=None,
):
    if not domain:
        return []
    r = str(rtype or '').upper()
    if r in ('TXT', 'ENS', 'SNS'):
        added = sorted(set(new_decoded_ips or []) - set(prev_decoded_ips or []))
    elif r == 'A':
        added = sorted(set(new_values or []) - set(prev_values or []))
    else:
        added = []
    return [(ip, domain, r) for ip in added if str(ip or '').strip()]


def _setup_logging():
    level = os.environ.get('TRACEDNS_LOG_LEVEL', 'INFO').upper().strip()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format='[%(levelname)s] %(asctime)s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )


def restore_current_results(history):
    """Build current runtime snapshots from persisted history metadata."""
    restored_results = {}
    for domain, hist_obj in (history or {}).items():
        current = hist_obj.get('current', {}) if isinstance(hist_obj, dict) else {}
        if not isinstance(current, dict) or not current:
            continue
        snapshots = {
            str(server): clone_snapshot(snapshot)
            for server, snapshot in current.items()
            if isinstance(snapshot, dict)
        }
        if snapshots:
            restored_results[str(domain)] = snapshots
    return restored_results


def build_arg_parser():
    parser = argparse.ArgumentParser(description="DNS monitor (multiple domains, web UI)")
    parser.add_argument("-d", "--domains", default="", help="Domains to monitor (comma or newline separated)")
    parser.add_argument("-s", "--servers", default="8.8.8.8,1.1.1.1", help="Comma-separated list of DNS servers to query")
    parser.add_argument("-i", "--interval", type=int, default=60, help="Check interval in seconds")
    parser.add_argument("-c", "--config", default="dns_config.json", help="Path to JSON config file")
    parser.add_argument("--http-host", default="127.0.0.1", help="HTTP UI bind host")
    parser.add_argument("--http-port", type=int, default=8000, help="HTTP UI port")
    parser.add_argument("--max-workers", type=int, default=8, help="Max worker threads for per-domain parallel DNS queries")
    parser.add_argument('--security-db', default=os.path.expanduser('~/.local/share/tracedns/security/auth.sqlite'))
    parser.add_argument('--public-origin', default='', help='HTTPS public origin behind trusted proxy')
    parser.add_argument('--insecure-http', action='store_true', help='Explicit insecure HTTP mode')
    parser.add_argument('--allow-insecure-remote-http', action='store_true',
                        help='DANGEROUS: allow plaintext HTTP beyond loopback; use only on a trusted LAN')
    parser.add_argument('--trusted-proxy', action='append', default=[], help='Trusted proxy IP; repeatable')
    parser.add_argument('--audit-retention-days', type=int, default=180)
    parser.add_argument('--session-idle-minutes', type=int, default=30)
    parser.add_argument('--session-hours', type=int, default=12)
    return parser


def main():
    _setup_logging()

    args = build_arg_parser().parse_args()
    from security.startup import open_security
    try:
        security_store = open_security(args)
    except (ValueError, OSError) as exc:
        logger.error('Security startup failed; reason=%s', diagnostic_reason(exc))
        raise SystemExit(2) from None


    def specified(*options):
        return any(arg == option or arg.startswith(option + '=')
                   for arg in sys.argv[1:] for option in options)

    cli_specified = {
        'domains': specified('-d', '--domains'),
        'servers': specified('-s', '--servers'),
        'interval': specified('-i', '--interval'),
        'max_workers': specified('--max-workers'),
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
    http_host = str(args.http_host).strip() or '127.0.0.1'
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

    interval0 = interval_arg if cli_specified['interval'] else bounded_int(file_cfg.get('interval'), interval_arg, 1, 86400)
    max_workers0 = max_workers_arg if cli_specified['max_workers'] else bounded_int(file_cfg.get('max_workers'), max_workers_arg, 1, 64)

    # shared config state (mutated by HTTP API)
    config_lock = threading.RLock()
    shared_config = deepcopy({k: v for k, v in file_cfg.items() if not k.startswith('_')})
    shared_config.update({
        '_config_revision': int(file_cfg.get('config_revision') or 0),
        'config_revision': int(file_cfg.get('config_revision') or 0),
        'domains': domains0,
        'domain_metadata': dict(file_cfg.get('domain_metadata') or {}),
        'servers': servers0,
        'interval': bounded_int(interval0, 60, 1, 86400),
        'max_workers': bounded_int(max_workers0, 8, 1, 64),
        'ens_rpc_url': str(file_cfg.get('ens_rpc_url') or '').strip(),
        'DEFAULT_SOLAR_PROXY_HOSTS': list(file_cfg.get('DEFAULT_SOLAR_PROXY_HOSTS',
                                         file_cfg.get('DEFAULT_SNS_PROXY_HOSTS', DEFAULT_SOLAR_PROXY_HOSTS)) or []),
        'DEFAULT_SNS_PROXY_HOSTS': list(file_cfg.get('DEFAULT_SNS_PROXY_HOSTS',
                                       file_cfg.get('DEFAULT_SOLAR_PROXY_HOSTS', DEFAULT_SOLAR_PROXY_HOSTS)) or []),
    })


    # The same compiler and publication owner serve startup and HTTP writes.
    config_service = ConfigService(shared_config, config_lock, config_path)
    try:
        config_service.initialize_decoders()
    except ConfigError:
        logger.error('Invalid startup decoder configuration; monitor not started')
        raise SystemExit(2) from None

    # history persistence dir
    history_dir = (config_path + ".history") if config_path else os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_history")
    ensure_history_dir(history_dir)

    # in-memory result & history
    history = load_history_files(history_dir)  # { domain: {meta, events, current} }
    current_results = restore_current_results(history)
    from monitor.repository import MonitorStateRepository
    state_repository = MonitorStateRepository(current_results, history, history_dir,
                                               shared_config['domains'], startup=True)
    config_service.state_repository = state_repository
    config_service.current_results = current_results
    config_service.history = history
    config_service.history_dir = history_dir
    # Required production dependency: never silently run without pinned decoders.
    from decoder_registry import snapshot_registry
    cfg_store = ConfigStore(shared_config, config_lock, state_repository=state_repository,
                            registry_snapshot=snapshot_registry)
    scheduler = MonitorScheduler(cfg_store)
    # Legacy tracker remains a helper facade only; the ledger owns grace.
    removal_tracker = None
    from monitor.delivery_runtime import DeliveryRuntime
    delivery = DeliveryRuntime(cfg_store, history_dir=history_dir)
    config_service.delivery_runtime = delivery
    # Every post-ledger startup failure shares the same cleanup path.
    httpd = None
    stop_housekeeping = None
    http_thread = None
    signal_stop = None
    try:
        delivery.apply_local_settings(delivery.selected_alerts)
        initial = cfg_store.snapshot()
        projection = active_target_projection(initial.domains, initial.servers,
                                              initial.ens_rpc_url, initial.sns_proxy_hosts)
        active_ip_map_prev = collect_active_ip_map(current_results, active_providers=projection)
        handler_class = make_handler(shared_config, config_lock, config_path, history_dir, current_results, history,
                                     security_store=security_store, public_origin=args.public_origin,
                                     insecure_http=args.insecure_http,
                                     allow_insecure_remote_http=args.allow_insecure_remote_http,
                                     trusted_proxies=args.trusted_proxy, state_repository=state_repository,
                                     config_service=config_service, delivery_health=delivery.store.health_snapshot)
        from security.startup import start_housekeeping
        if args.allow_insecure_remote_http:
            logger.warning('DANGEROUS: plaintext HTTP is exposed beyond loopback; credentials and sessions are not TLS-protected')
        httpd = ThreadingHTTPServer((http_host, http_port), handler_class)
        delivery.worker.start()
        stop_housekeeping = start_housekeeping(security_store)
        http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_thread.start()
        logger.info("HTTP config UI running on http://%s:%s/", http_host, http_port)

        signal_stop = SignalStopBridge(scheduler.stop)
        with config_lock:
            shared_config['_signal_stop'] = signal_stop
        signal_stop.start((signal.SIGINT, signal.SIGTERM))

        query_fail_counts = {}
        while True:
            snap = scheduler.next_scan()
            if snap is None:
                break
            domains = normalize_domains(snap.domains)
            active_ip_map_now = run_full_cycle(
                domains_raw=domains,
                servers=snap.servers,
                current_results=current_results,
                history=history,
                history_dir=history_dir,
                query_fail_counts=query_fail_counts,
                max_workers=snap.max_workers,
                force_req=snap.force_req,
                ens_rpc_url=snap.ens_rpc_url,
                sns_proxy_hosts=snap.sns_proxy_hosts,
                suppressed_added_ips=None,
                state_repository=state_repository,
                target_leases=snap.target_leases,
                registry_view=snap.registry_view,
            )

            accepted, active_ip_map_prev = reconcile_scan(
                cfg_store, snap, active_ip_map_prev, active_ip_map_now, removal_tracker)
            scheduler.completed(snap, accepted=accepted)
    finally:
        # Each owned resource gets its cleanup even if another cleanup fails.
        # Keep the primary exception; a failed stop never authorizes store close.
        primary_error = sys.exc_info()[1]
        cleanup_errors = []

        def cleanup(action):
            try:
                return action()
            except Exception as exc:
                cleanup_errors.append(exc)
                logger.warning('Monitor cleanup failed; reason=cleanup_failed')
                return None

        cleanup(scheduler.stop)
        if signal_stop is not None and cleanup(signal_stop.close) is False:
            logger.warning('Signal stop coordinator is still draining')
        # This serial runner has returned: no producer remains in admission.
        delivery_stop = cleanup(delivery.stop)
        if delivery_stop is not None and not delivery_stop['stopped']:
            logger.warning('Delivery callback still running; ledger and in-flight claim retained')
        logger.info("Exiting DNS monitor.")
        if stop_housekeeping is not None:
            cleanup(stop_housekeeping.set)
        if http_thread is not None and http_thread.is_alive():
            cleanup(httpd.shutdown)
        if httpd is not None:
            cleanup(httpd.server_close)
        if primary_error is None and cleanup_errors:
            raise cleanup_errors[0]


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Embedded callers retain the original exception. The CLI is a public
        # diagnostic sink, not permission to print credential-bearing traceback.
        logger.error('Monitor failed; reason=%s', diagnostic_reason(exc))
        raise SystemExit(2) from None
