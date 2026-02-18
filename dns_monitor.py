#!/usr/bin/env python3
"""
DNS monitor main application.
Monitors multiple domains across multiple DNS servers and exposes results via a web UI.
"""
import time
import argparse
import sys
import signal
import threading
import os

from dns_query import query_dns
from txt_decoder import decode_txt_hidden_ips, register_custom_decoder
from a_decoder import decode_a_hidden_ips
from config_manager import read_config, normalize_domains
from history_manager import load_history_files, persist_history_entry, ensure_history_dir
from http_server import ThreadingHTTPServer, make_handler
from alerts import (
    init_from_config as alerts_init,
    init_from_alerts as alerts_init_from_dict,
    alert_new_ips,
    alert_removed_ips,
)


def _collect_active_ip_map(current_results, allowed_domains=None):
    """Build managed IP -> domain-name-set map from current snapshots."""
    allow = None if allowed_domains is None else set(allowed_domains)
    out = {}
    for domain, server_map in (current_results or {}).items():
        if allow is not None and domain not in allow:
            continue
        if not isinstance(server_map, dict):
            continue
        for _, snap in server_map.items():
            if not isinstance(snap, dict):
                continue
            rtype = str(snap.get('type', '')).upper()
            if rtype == 'TXT':
                ips = snap.get('decoded_ips', []) or []
            elif rtype == 'A':
                # A-type with post-process enabled already stores managed/transformed IPs in values.
                ips = snap.get('values', []) or []
            else:
                ips = []
            for ip in ips:
                s = str(ip or '').strip()
                if not s:
                    continue
                out.setdefault(s, set()).add(domain)
    return out


def _mark_query_failure(fail_counts, key):
    """Increment failure count for a key and return the new count."""
    try:
        count = int(fail_counts.get(key, 0)) + 1
    except Exception:
        count = 1
    fail_counts[key] = count
    return count


def _clear_query_failure(fail_counts, key):
    """Reset failure count for a key after a successful query."""
    fail_counts.pop(key, None)


def _drop_snapshot_for_failed_target(current_results, history, name, srv, ts=None):
    """Drop current snapshot for a domain/server pair.

    Returns True when something was removed.
    """
    removed = False
    if name in current_results and isinstance(current_results.get(name), dict):
        if srv in current_results[name]:
            current_results[name].pop(srv, None)
            removed = True

    hist_obj = history.setdefault(name, {'meta': {}, 'events': [], 'current': {}})
    current_map = hist_obj.setdefault('current', {})
    if isinstance(current_map, dict) and srv in current_map:
        current_map.pop(srv, None)
        removed = True

    if removed and ts:
        try:
            hist_obj.setdefault('meta', {})['last_changed'] = int(ts)
        except Exception:
            pass
    return removed


def _build_initial_new_ip_tuples(rtype, domain, values=None, decoded_ips=None):
    """Build new-IP alert tuples for the first observed snapshot."""
    if not domain:
        return []
    if str(rtype or '').upper() == 'TXT':
        ips = sorted(set(decoded_ips or []))
    elif str(rtype or '').upper() == 'A':
        ips = sorted(set(values or []))
    else:
        ips = []
    src = str(rtype or '').upper()
    return [(ip, domain, src) for ip in ips if str(ip or '').strip()]


def _build_changed_new_ip_tuples(
    rtype,
    domain,
    prev_values=None,
    new_values=None,
    prev_decoded_ips=None,
    new_decoded_ips=None,
):
    """Build newly-added IP alert tuples between previous and new snapshot."""
    if not domain:
        return []
    r = str(rtype or '').upper()
    if r == 'TXT':
        added = sorted(set(new_decoded_ips or []) - set(prev_decoded_ips or []))
    elif r == 'A':
        added = sorted(set(new_values or []) - set(prev_values or []))
    else:
        added = []
    return [(ip, domain, r) for ip in added if str(ip or '').strip()]


def _update_nxdomain_lifecycle(
    history,
    name,
    query_total,
    success_count,
    nxdomain_count,
    error_count,
    ts_now
):
    """Update per-domain NXDOMAIN lifecycle metadata.

    Lifecycle rules:
    - Any successful answer in the cycle clears active NXDOMAIN lifecycle.
    - NXDOMAIN lifecycle activates only when all responses are NXDOMAIN or error
      and there is at least one NXDOMAIN.
    - Pure transport failures are tracked separately and do not activate NXDOMAIN.
    """
    if not name:
        return False
    hist_obj = history.setdefault(name, {'meta': {}, 'events': [], 'current': {}})
    meta = hist_obj.setdefault('meta', {})
    changed = False

    total = int(query_total or 0)
    succ = int(success_count or 0)
    nx = int(nxdomain_count or 0)
    err = int(error_count or 0)

    meta['dns_cycle_total'] = total
    meta['dns_cycle_success_count'] = succ
    meta['dns_cycle_nxdomain_count'] = nx
    meta['dns_cycle_error_count'] = err

    all_failed = total > 0 and err >= total
    no_success = succ <= 0
    nxdomain_all_or_error = total > 0 and no_success and nx > 0 and (nx + err) >= total

    if nx > 0 and not meta.get('nxdomain_first_seen'):
        meta['nxdomain_first_seen'] = int(ts_now)
        changed = True

    if succ > 0:
        if meta.get('nxdomain_active'):
            meta['nxdomain_active'] = False
            changed = True
        if meta.get('nxdomain_since'):
            meta.pop('nxdomain_since', None)
            changed = True
        if meta.get('dns_error_only_active'):
            meta['dns_error_only_active'] = False
            changed = True
        if changed:
            meta['nxdomain_cleared_ts'] = int(ts_now)
        meta['dns_last_success_ts'] = int(ts_now)
        return changed

    if nxdomain_all_or_error:
        if not meta.get('nxdomain_active'):
            meta['nxdomain_active'] = True
            changed = True
        if not meta.get('nxdomain_since'):
            meta['nxdomain_since'] = int(ts_now)
            changed = True
        if meta.get('dns_error_only_active'):
            meta['dns_error_only_active'] = False
            changed = True
    elif all_failed:
        if not meta.get('dns_error_only_active'):
            meta['dns_error_only_active'] = True
            changed = True
    else:
        if meta.get('dns_error_only_active'):
            meta['dns_error_only_active'] = False
            changed = True

    return changed


def main():
    """Main entry: start the DNS monitoring loop and HTTP UI."""
    parser = argparse.ArgumentParser(description="DNS monitor (multiple domains, web UI)")
    parser.add_argument("-d", "--domains", default="", help="Domains to monitor (comma or newline separated)")
    parser.add_argument("-s", "--servers", default="8.8.8.8,1.1.1.1", help="Comma-separated list of DNS servers to query")
    parser.add_argument("-i", "--interval", type=int, default=60, help="Check interval in seconds")
    parser.add_argument("-c", "--config", default="dns_config.json", help="Path to JSON config file")
    parser.add_argument("--http-port", type=int, default=8000, help="HTTP UI port")
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

    # restore custom A decoders from file config
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
    except Exception:
        shared_config['alerts'] = {}
        alerts_cfg = {}

    # initialize alerting (Teams + MISP)
    # Priority: dns_config.json alerts -> config.ini fallback
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
                restored = {
                    'type': snap.get('type'),
                    'values': snap.get('values', []),
                    'decoded_ips': snap.get('decoded_ips', []),
                    'ts': snap.get('ts', 0)
                }
                if snap.get('txt_decode'):
                    restored['txt_decode'] = snap.get('txt_decode')
                if snap.get('a_decode'):
                    restored['a_decode'] = snap.get('a_decode')
                if snap.get('a_xor_key'):
                    restored['a_xor_key'] = snap.get('a_xor_key')
                current_results[domain][srv] = restored

    # active managed IP baseline (configured domains only); used for removal detection.
    configured_names = {
        d.get('name', '').strip()
        for d in normalize_domains(shared_config.get('domains', []))
        if d.get('name')
    }
    active_ip_map_prev = _collect_active_ip_map(current_results, configured_names)

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

    # Consecutive DNS query failure counters: key=(domain, server, rtype)
    query_fail_counts = {}

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
            a_decode = dobj.get('a_decode', 'none')
            a_xor_key = dobj.get('a_xor_key')
            a_decode_active = str(a_decode or '').strip().lower() not in ('', 'none')
            if not name:
                continue
            domain_query_total = 0
            domain_success_count = 0
            domain_nxdomain_count = 0
            domain_error_count = 0
            svr_list = target_servers_override or servers
            for srv in svr_list:
                domain_query_total += 1
                fail_key = (name, srv, rtype)
                qret = query_dns(srv, name, rtype=rtype, with_meta=True)
                if isinstance(qret, dict):
                    queried_vals = qret.get('values', []) if isinstance(qret.get('values'), list) else []
                    qstatus = str(qret.get('status') or 'error').lower()
                else:
                    queried_vals = qret if isinstance(qret, list) else []
                    qstatus = 'ok' if isinstance(qret, list) else 'error'

                if qstatus == 'nxdomain':
                    domain_nxdomain_count += 1
                    print(f"[NOTICE] DNS {srv} returned NXDOMAIN for {name} ({rtype})")
                elif qstatus in ('ok', 'nodata'):
                    domain_success_count += 1
                elif qstatus == 'error':
                    domain_error_count += 1

                if qstatus == 'error':
                    fail_count = _mark_query_failure(query_fail_counts, fail_key)
                    print(f"[ERROR] DNS {srv} query failed for {name} ({rtype})")
                    # Drop stale snapshot after consecutive failures.
                    if fail_count >= 3:
                        ts_fail = int(time.time())
                        removed = _drop_snapshot_for_failed_target(current_results, history, name, srv, ts=ts_fail)
                        if removed:
                            print(f"[NOTICE] Removed stale snapshot after {fail_count} consecutive DNS failures: {name} ({rtype}) @ {srv}")
                            try:
                                hist_obj = history.get(name)
                                if isinstance(hist_obj, dict):
                                    persist_history_entry(history_dir, name, hist_obj)
                            except Exception:
                                pass
                    continue
                _clear_query_failure(query_fail_counts, fail_key)
                ts = int(time.time())
                decoded = []
                result_vals = queried_vals
                if rtype == 'TXT':
                    # pass domain name to decoder so domain-specific rules can be applied
                    decoded = decode_txt_hidden_ips(result_vals, method=txt_decode, domain=name)
                elif rtype == 'A':
                    if a_decode_active:
                        # If A post-process is enabled, manage only transformed IPs.
                        transformed = decode_a_hidden_ips(queried_vals, method=a_decode, key_hex=a_xor_key, domain=name)
                        result_vals = sorted(set(transformed or []))
                        # Exclude raw-resolved IPs from managed fields when decode is enabled.
                        decoded = []
                    else:
                        decoded = []
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
                    elif rtype == 'A':
                        snap['a_decode'] = a_decode or 'none'
                        if a_xor_key:
                            snap['a_xor_key'] = a_xor_key
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
                    elif rtype == 'A':
                        hist_snap['a_decode'] = a_decode or 'none'
                        if a_xor_key:
                            hist_snap['a_xor_key'] = a_xor_key
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
                    # initial observation for a newly tracked domain/server can still contain new IOC IPs
                    try:
                        tuples = _build_initial_new_ip_tuples(
                            rtype,
                            name,
                            values=result_vals,
                            decoded_ips=decoded,
                        )
                        if tuples:
                            alert_new_ips(tuples)
                    except Exception:
                        pass
                else:
                    if (
                        prev.get('values') != result_vals
                        or prev.get('type') != rtype
                        or (prev.get('decoded_ips') or []) != (decoded or [])
                    ):
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
                        elif rtype == 'A':
                            snap_update['a_decode'] = a_decode or 'none'
                            if a_xor_key:
                                snap_update['a_xor_key'] = a_xor_key
                        hist_obj.setdefault('current', {})[srv] = snap_update
                        current_results[name][srv] = snap_update
                        print(f"[NOTICE] {name} ({rtype}) @ {srv} changed: {prev.get('values')} -> {result_vals} decoded:{decoded}")
                        persist_history_entry(history_dir, name, hist_obj)
                        # If a decoder produced derived IPs, alert only on newly added ones.
                        try:
                            tuples = _build_changed_new_ip_tuples(
                                rtype,
                                name,
                                prev_values=prev.get('values'),
                                new_values=result_vals,
                                prev_decoded_ips=prev.get('decoded_ips'),
                                new_decoded_ips=decoded,
                            )
                            if tuples:
                                alert_new_ips(tuples)
                        except Exception:
                            pass
                    # else unchanged

            # Update per-domain NXDOMAIN lifecycle metadata once per domain cycle.
            try:
                ts_cycle = int(time.time())
                lifecycle_changed = _update_nxdomain_lifecycle(
                    history,
                    name,
                    domain_query_total,
                    domain_success_count,
                    domain_nxdomain_count,
                    domain_error_count,
                    ts_cycle
                )
                if lifecycle_changed:
                    hist_obj = history.get(name)
                    if isinstance(hist_obj, dict):
                        persist_history_entry(history_dir, name, hist_obj)
            except Exception:
                pass

        # Reconcile active IP set only after a full configured-domain scan.
        full_domain_scan = not (force_req and 'domains' in force_req)
        if full_domain_scan:
            configured_names = {d.get('name', '').strip() for d in domains if d.get('name')}
            active_ip_map_now = _collect_active_ip_map(current_results, configured_names)
            removed_ips = sorted(set(active_ip_map_prev.keys()) - set(active_ip_map_now.keys()))
            if removed_ips:
                removed_tuples = []
                for ip in removed_ips:
                    labels = sorted(active_ip_map_prev.get(ip, set()))
                    removed_tuples.append((ip, ",".join(labels) if labels else "unknown"))
                try:
                    alert_removed_ips(removed_tuples)
                except Exception:
                    pass
            active_ip_map_prev = active_ip_map_now

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
