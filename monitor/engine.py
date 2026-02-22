from __future__ import annotations

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Sequence, Tuple

from alerts import alert_new_ips, alert_removed_ips
from history_manager import persist_history_entry
from models import DomainSpec, coerce_domains, Snapshot

from .collect import collect_snapshot
from .lifecycle import update_nxdomain_lifecycle
from .state_utils import collect_active_ip_map, collect_domain_managed_ips


logger = logging.getLogger(__name__)


def mark_query_failure(fail_counts: Dict[Any, int], key: Any) -> int:
    try:
        count = int(fail_counts.get(key, 0)) + 1
    except Exception:
        count = 1
    fail_counts[key] = count
    return count


def clear_query_failure(fail_counts: Dict[Any, int], key: Any) -> None:
    fail_counts.pop(key, None)


def drop_snapshot_for_failed_target(current_results: Dict[str, Any], history: Dict[str, Any], name: str, srv: str, ts: Optional[int] = None) -> bool:
    """Drop current snapshot for a domain/server pair. Returns True when something was removed."""
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


def _snapshot_dict(snap: Snapshot) -> Dict[str, Any]:
    return snap.to_dict() if isinstance(snap, Snapshot) else {}


def run_domain_cycle(
    *,
    domain: DomainSpec,
    servers: Sequence[str],
    current_results: Dict[str, Any],
    history: Dict[str, Any],
    history_dir: str,
    query_fail_counts: Dict[Any, int],
    max_workers: int = 8,
) -> None:
    """Run one cycle for a single domain across all servers.

    Updates current_results + history in-place.
    Sends alert_new_ips for any newly added managed IPs (domain-level aggregate).
    Updates NXDOMAIN lifecycle.
    """
    name = domain.name
    rtype = str(domain.type or 'A').upper()
    if not name:
        return

    current_results.setdefault(name, {})
    history.setdefault(name, {'meta': {}, 'events': [], 'current': {}})

    domain_prev_managed_ips = collect_domain_managed_ips(current_results, name, rtype=rtype)

    # Query all servers in parallel (bounded).
    # Note: dnspython releases the GIL during network IO; threading helps.
    domain_query_total = 0
    domain_success_count = 0
    domain_nxdomain_count = 0
    domain_error_count = 0

    max_workers_eff = max(1, int(max_workers or 1))
    futures = []
    with ThreadPoolExecutor(max_workers=max_workers_eff) as ex:
        for srv in servers:
            domain_query_total += 1
            futures.append(ex.submit(collect_snapshot, domain, str(srv)))

        for fut in as_completed(futures):
            collected = fut.result()
            srv = collected.query.server
            status = str(collected.query.status or 'error').lower()
            fail_key = (name, srv, rtype)

            if status == 'nxdomain':
                domain_nxdomain_count += 1
                logger.info("DNS %s returned NXDOMAIN for %s (%s)", srv, name, rtype)
            elif status in ('ok', 'nodata'):
                domain_success_count += 1
            elif status == 'error':
                domain_error_count += 1

            if status == 'error':
                fail_count = mark_query_failure(query_fail_counts, fail_key)
                logger.warning("DNS %s query failed for %s (%s) (consecutive=%s)", srv, name, rtype, fail_count)
                # Drop stale snapshot after consecutive failures.
                if fail_count >= 3:
                    ts_fail = int(time.time())
                    removed = drop_snapshot_for_failed_target(current_results, history, name, srv, ts=ts_fail)
                    if removed:
                        logger.info(
                            "Removed stale snapshot after %s consecutive DNS failures: %s (%s) @ %s",
                            fail_count,
                            name,
                            rtype,
                            srv,
                        )
                        try:
                            persist_history_entry(history_dir, name, history.get(name))
                        except Exception:
                            pass
                continue

            clear_query_failure(query_fail_counts, fail_key)
            snap = collected.snapshot
            if snap is None:
                continue

            ts = int(snap.ts or time.time())
            prev_obj = current_results.get(name, {}).get(srv)
            prev = Snapshot.from_legacy(prev_obj) if isinstance(prev_obj, dict) else None

            hist_obj = history[name]
            # initial population
            if prev_obj is None:
                current_results.setdefault(name, {})[srv] = _snapshot_dict(snap)
                hist_obj.setdefault('current', {})[srv] = _snapshot_dict(snap)
                meta = hist_obj.setdefault('meta', {})
                meta.setdefault('first_seen', ts)
                meta.setdefault('last_changed', ts)
                logger.info("INIT %s (%s) @ %s -> %s decoded=%s", name, rtype, srv, snap.values, snap.decoded_ips)
                try:
                    persist_history_entry(history_dir, name, hist_obj)
                except Exception:
                    pass
                continue

            # changed?
            changed = (
                (prev.get('values') if isinstance(prev_obj, dict) else prev.values) != snap.values
                or (prev.get('decoded_ips') if isinstance(prev_obj, dict) else prev.decoded_ips) != snap.decoded_ips
                or str((prev.get('type') if isinstance(prev_obj, dict) else prev.type) or '').upper() != str(snap.type or '').upper()
            )

            if changed:
                ev = {
                    'ts': ts,
                    'server': srv,
                    'type': rtype,
                    'old': {
                        'values': (prev_obj or {}).get('values', []) if isinstance(prev_obj, dict) else (prev.values if prev else []),
                        'decoded_ips': (prev_obj or {}).get('decoded_ips', []) if isinstance(prev_obj, dict) else (prev.decoded_ips if prev else []),
                        'ts': (prev_obj or {}).get('ts') if isinstance(prev_obj, dict) else (prev.ts if prev else 0),
                    },
                    'new': {'values': snap.values, 'decoded_ips': snap.decoded_ips, 'ts': ts},
                }
                hist_obj.setdefault('events', []).append(ev)
                meta = hist_obj.setdefault('meta', {})
                meta['last_changed'] = ts
                meta.setdefault('first_seen', ev['old'].get('ts', ts) if isinstance(ev.get('old'), dict) else ts)
                hist_obj.setdefault('current', {})[srv] = _snapshot_dict(snap)
                current_results[name][srv] = _snapshot_dict(snap)
                logger.info(
                    "CHANGED %s (%s) @ %s: %s -> %s decoded=%s",
                    name,
                    rtype,
                    srv,
                    ev['old'].get('values'),
                    snap.values,
                    snap.decoded_ips,
                )
                try:
                    persist_history_entry(history_dir, name, hist_obj)
                except Exception:
                    pass

    # Update per-domain NXDOMAIN lifecycle metadata once per domain cycle.
    try:
        ts_cycle = int(time.time())
        lifecycle_changed = update_nxdomain_lifecycle(
            history,
            name,
            domain_query_total,
            domain_success_count,
            domain_nxdomain_count,
            domain_error_count,
            ts_cycle,
        )
        if lifecycle_changed:
            try:
                persist_history_entry(history_dir, name, history.get(name))
            except Exception:
                pass
    except Exception:
        pass

    # Domain-level alerting: aggregate all DNS server results and send once per domain cycle.
    try:
        domain_now_managed_ips = collect_domain_managed_ips(current_results, name, rtype=rtype)
        added_ips = sorted(domain_now_managed_ips - domain_prev_managed_ips)
        if added_ips:
            tuples = [(ip, name, rtype) for ip in added_ips]
            alert_new_ips(tuples)
    except Exception:
        pass


def run_full_cycle(
    *,
    domains_raw: List[Any],
    servers: Sequence[str],
    current_results: Dict[str, Any],
    history: Dict[str, Any],
    history_dir: str,
    query_fail_counts: Dict[Any, int],
    max_workers: int = 8,
    force_req: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run a full scan cycle across domains.

    Returns the updated active_ip_map (for removal reconciliation).
    """
    domains = coerce_domains(domains_raw)

    # Optional forced resolve subset.
    if force_req and 'domains' in force_req:
        target_domains = coerce_domains(force_req.get('domains') or [])
    else:
        target_domains = domains

    target_servers_override = force_req.get('servers') if force_req and 'servers' in force_req else None

    # Ensure entries
    for ds in domains:
        if ds.name:
            current_results.setdefault(ds.name, {})
            history.setdefault(ds.name, {'meta': {}, 'events': [], 'current': {}})

    for ds in target_domains:
        svr_list = target_servers_override or list(servers)
        if not svr_list:
            continue
        run_domain_cycle(
            domain=ds,
            servers=svr_list,
            current_results=current_results,
            history=history,
            history_dir=history_dir,
            query_fail_counts=query_fail_counts,
            max_workers=max_workers,
        )

    # Removal reconciliation only after full configured scan (not force subset)
    full_domain_scan = not (force_req and 'domains' in force_req)
    if full_domain_scan:
        configured_names = {ds.name for ds in domains if ds.name}
        return collect_active_ip_map(current_results, configured_names)

    # For forced subset, don't update baseline
    configured_names = {ds.name for ds in domains if ds.name}
    return collect_active_ip_map(current_results, configured_names)


def reconcile_removed_ips(active_ip_map_prev: Dict[str, Any], active_ip_map_now: Dict[str, Any]) -> Dict[str, Any]:
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
    return active_ip_map_now
