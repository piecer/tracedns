from __future__ import annotations

import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from alerts import alert_new_ips, alert_removed_ips
from config_manager import domain_storage_name
from history_manager import persist_history_entry, trim_history_events
from models import DomainSpec, coerce_domains, Snapshot

from .collect import collect_snapshot
from .diagnostics import diagnostic_reason, provider_label
from .lifecycle import update_nxdomain_lifecycle
from .removal_grace import IpRemovalGraceTracker
from .repository import MonitorStateRepository, normalized_domain_specs
from .runtime_state import bump_state_version, clone_history_entry, state_lock
from .state_utils import collect_active_ip_map, collect_domain_managed_ips


logger = logging.getLogger(__name__)

# Safety: protect shared mutable state when we later add domain-level parallelism.
# Even with current per-domain threading, keeping writes guarded makes behavior deterministic.
_STATE_LOCK = state_lock()

# Best-effort alert dedupe to prevent bursts/duplicates when concurrency increases.
# key: (action, domain, ip) -> last_ts
_ALERT_DEDUPE: Dict[Tuple[str, str, str], int] = {}
_ALERT_DEDUPE_TTL_SECONDS = 60


def mark_query_failure(fail_counts: Dict[Any, int], key: Any) -> int:
    with _STATE_LOCK:
        try:
            count = int(fail_counts.get(key, 0)) + 1
        except Exception:
            count = 1
        fail_counts[key] = count
        return count


def clear_query_failure(fail_counts: Dict[Any, int], key: Any) -> None:
    with _STATE_LOCK:
        fail_counts.pop(key, None)


def drop_snapshot_for_failed_target(current_results: Dict[str, Any], history: Dict[str, Any], name: str, srv: str, ts: Optional[int] = None) -> bool:
    """Drop current snapshot for a domain/server pair. Returns True when something was removed."""
    with _STATE_LOCK:
        removed = False
        try:
            if name in current_results and isinstance(current_results.get(name), dict):
                if srv in current_results[name]:
                    current_results[name].pop(srv, None)
                    removed = True

            if name in history:
                hist_obj = history[name]
                current_map = hist_obj.setdefault('current', {})
                if isinstance(current_map, dict) and srv in current_map:
                    current_map.pop(srv, None)
                    removed = True

                if removed and ts:
                    try:
                        hist_obj.setdefault('meta', {})['last_changed'] = int(ts)
                    except Exception:
                        pass
        finally:
            # Fence a partial removal even when malformed history raises.
            if removed:
                bump_state_version()
        return removed


def _snapshot_dict(snap: Snapshot) -> Dict[str, Any]:
    return snap.to_dict() if isinstance(snap, Snapshot) else {}


_HISTORY_DECODER_KEYS = (
    'txt_decode', 'a_decode', 'a_xor_key',
    'ens_text_key', 'ens_decode', 'ens_xor_byte',
    'ens_node', 'ens_resolver', 'ens_options',
    'sns_decode', 'sns_options',
)


def _history_snapshot(value: Any) -> Dict[str, Any]:
    snapshot = _snapshot_dict(value) if isinstance(value, Snapshot) else value
    item = snapshot if isinstance(snapshot, dict) else {}
    out = {
        'values': item.get('values', []),
        'decoded_ips': item.get('decoded_ips', []),
        'ts': item.get('ts', 0),
    }
    if item.get('decoded_endpoints'):
        out['decoded_endpoints'] = item['decoded_endpoints']
    for key in _HISTORY_DECODER_KEYS:
        if item.get(key) not in (None, ''):
            out[key] = item[key]
    return out


def _snapshot_changed(previous: Any, current: Snapshot) -> bool:
    """Compare observable DNS values and the provenance used to decode them."""
    prev = _snapshot_dict(previous) if isinstance(previous, Snapshot) else previous
    prev = prev if isinstance(prev, dict) else {}
    current_dict = _snapshot_dict(current)
    if (prev.get('values') or []) != (current_dict.get('values') or []):
        return True
    if (prev.get('decoded_ips') or []) != (current_dict.get('decoded_ips') or []):
        return True
    if (prev.get('decoded_endpoints') or []) != (current_dict.get('decoded_endpoints') or []):
        return True
    if str(prev.get('type') or '').upper() != str(current_dict.get('type') or '').upper():
        return True
    return any(prev.get(key) != current_dict.get(key) for key in _HISTORY_DECODER_KEYS)


def _dedupe_alert(action: str, entries: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    """Drop recently-sent duplicate alerts (best effort).

    entries: (ip, domain/label, source_type)
    """
    now = int(time.time())
    keep: List[Tuple[str, str, str]] = []
    with _STATE_LOCK:
        # prune occasionally
        for k, ts in list(_ALERT_DEDUPE.items()):
            if (now - int(ts or 0)) > _ALERT_DEDUPE_TTL_SECONDS:
                _ALERT_DEDUPE.pop(k, None)

        for ip, label, source_type in entries or []:
            key = (action, str(label or ''), str(ip or ''))
            last = _ALERT_DEDUPE.get(key, 0)
            if last and (now - last) <= _ALERT_DEDUPE_TTL_SECONDS:
                continue
            _ALERT_DEDUPE[key] = now
            keep.append((ip, label, source_type))

    return keep


def _domain_storage_name(domain: DomainSpec) -> str:
    return domain_storage_name({
        'name': domain.name,
        'type': domain.type,
        'ens_text_key': domain.ens_text_key,
        'ens_node': domain.ens_node,
        'ens_resolver': domain.ens_resolver,
    })


def run_domain_cycle(*, state_repository=None, target_lease=None, cycle_id='',
                     cycle_quality=None, positive_observations=None, **kwargs):
    """Production collects privately, admits once, then publishes independently."""
    runtime = getattr(state_repository, 'delivery_runtime', None)
    if runtime is None:
        return _collect_domain_cycle(state_repository=state_repository, target_lease=target_lease,
                                     positive_observations=positive_observations, **kwargs)
    import uuid
    candidate = state_repository.observation_candidate(target_lease)
    if candidate is None:
        if cycle_quality is not None:
            cycle_quality.append(False)
        return []
    version, current, history, failures = candidate
    name = target_lease.name
    domain = kwargs['domain']
    providers = kwargs.get('active_servers', kwargs['servers'])
    before = collect_domain_managed_ips({name: current}, name, rtype=domain.type, active_servers=providers)
    private_current, private_history = {name: current}, {name: history}
    private_repo = MonitorStateRepository(private_current, private_history, kwargs['history_dir'], [domain])
    private_lease = private_repo.capture()[name]
    private_lease.target.failures.update(failures)
    private_positive, quality = {}, []
    private_args = dict(kwargs, current_results=private_current, history=private_history)
    entries = _collect_domain_cycle(**private_args, state_repository=private_repo,
        target_lease=private_lease, positive_observations=private_positive,
        persist_candidate=False, cycle_quality=quality)
    after = collect_domain_managed_ips(private_current, name, rtype=domain.type, active_servers=providers)
    observation = None
    if private_positive:
        observation = {'target': name, 'managed_ips': sorted(after), 'before_ips': sorted(before),
            'source_operation_id': uuid.uuid4().hex, 'cycle_id': cycle_id,
            'observed_at': runtime.clock(), 'label': name, 'source_type': str(domain.type).upper()}
    accepted = state_repository.accept_observation(target_lease, version, current, history,
                                                   private_lease.target.failures, observation)
    if cycle_quality is not None:
        cycle_quality.append(accepted and bool(quality) and all(quality))
    if not accepted:
        return []
    if positive_observations is not None:
        positive_observations.update(private_positive)
    try:
        persistence = persist_history_entry(kwargs['history_dir'], name, history, detailed=True,
            commit=lambda temporary, destination: state_repository.commit_history(target_lease, temporary, destination))
    except Exception:
        persistence = 'failed'
    runtime.history_persistence = persistence if isinstance(persistence, str) else ('saved' if persistence else 'failed')
    if runtime.history_persistence != 'saved':
        runtime.note_history_failure()
    return entries


def _collect_domain_cycle(
    *,
    domain: DomainSpec,
    servers: Sequence[str],
    current_results: Dict[str, Any],
    history: Dict[str, Any],
    history_dir: str,
    query_fail_counts: Dict[Any, int],
    max_workers: int = 8,
    state_repository=None,
    target_lease=None,
    positive_observations=None,
    registry_view=None,
    active_servers=None,
    persist_candidate=True,
    cycle_quality=None,
) -> List[Tuple[str, str, str]]:
    """Run one cycle for a single domain across all servers.

    Updates current_results + history in-place.
    Returns newly added managed IP tuples for this domain:
      [(ip, domain, source_type), ...]
    Updates NXDOMAIN lifecycle.
    """
    query_name = domain.name
    rtype = str(domain.type or 'A').upper()
    name = _domain_storage_name(domain)
    if not query_name or not name:
        return []

    application_owned = state_repository is not None
    if state_repository is None:
        state_repository = MonitorStateRepository(current_results, history, history_dir, [domain])
        target_lease = state_repository.capture().get(name)
    if not state_repository.valid(target_lease):
        return []
    if application_owned:
        # Counts belong to this incarnation, not the reusable target name.
        query_fail_counts = target_lease.target.failures

    def persist_owned(snapshot):
        if not persist_candidate:
            return True
        return persist_history_entry(
            history_dir, name, snapshot,
            commit=lambda temporary, destination: state_repository.commit_history(
                target_lease, temporary, destination),
        )

    active_servers = servers if active_servers is None else active_servers
    provider_slots = {str(server): provider_label(rtype, slot)
                      for slot, server in enumerate(active_servers, 1)}
    domain_prev_managed_ips = collect_domain_managed_ips(current_results, name, rtype=rtype,
                                                        active_servers=active_servers)
    added_alert_tuples: List[Tuple[str, str, str]] = []

    def collect_owned(server):
        if registry_view is None:  # Direct helper compatibility, not production bootstrap.
            return collect_snapshot(domain, server)
        from decoder_registry import use_registry
        with use_registry(registry_view):
            return collect_snapshot(domain, server)

    # Query all servers in parallel (bounded).
    # Note: dnspython releases the GIL during network IO; threading helps.
    domain_query_total = 0
    domain_success_count = 0
    domain_nxdomain_count = 0
    domain_error_count = 0

    max_workers_eff = max(1, int(max_workers or 1))
    futures = {}
    with ThreadPoolExecutor(max_workers=max_workers_eff) as ex:
        for srv in servers:
            if not state_repository.valid(target_lease):
                return []
            domain_query_total += 1
            server = str(srv)
            futures[ex.submit(collect_owned, server)] = server

        for fut in as_completed(futures):
            submitted_server = futures[fut]
            try:
                collected = fut.result()
            except Exception as exc:
                domain_error_count += 1
                if cycle_quality is not None:
                    cycle_quality.append(False)
                fail_key = (name, submitted_server, rtype)
                with _STATE_LOCK:
                    if not state_repository.valid(target_lease):
                        return []
                    fail_count = mark_query_failure(query_fail_counts, fail_key)
                logger.error('Query worker failed; provider=%s consecutive=%s reason=%s',
                             provider_slots.get(submitted_server, provider_label(rtype, 0)),
                             fail_count, diagnostic_reason(exc))
                continue
            label = provider_slots.get(submitted_server, provider_label(rtype, 0))
            srv = collected.query.server
            status = str(collected.query.status or 'error').lower()
            if cycle_quality is not None:
                cycle_quality.append(status in ('ok', 'nodata', 'nxdomain') and collected.snapshot is not None)
            fail_key = (name, srv, rtype)

            if status == 'nxdomain':
                domain_nxdomain_count += 1
                logger.info('Query NXDOMAIN; provider=%s', label)
            elif status in ('ok', 'nodata'):
                domain_success_count += 1
            elif status == 'error':
                domain_error_count += 1

            if status == 'error':
                with _STATE_LOCK:
                    if not state_repository.valid(target_lease):
                        return []
                    fail_count = mark_query_failure(query_fail_counts, fail_key)
                logger.warning('Query failed; provider=%s consecutive=%s reason=%s',
                               label, fail_count, diagnostic_reason(getattr(collected.query, 'error', None)))
                # Drop stale snapshot after consecutive failures.
                if fail_count >= 3:
                    ts_fail = int(time.time())
                    with _STATE_LOCK:
                        if not state_repository.valid(target_lease):
                            return []
                        removed = drop_snapshot_for_failed_target(current_results, history, name, srv, ts=ts_fail)
                        hist_to_persist = clone_history_entry(history.get(name)) if removed else None
                    if removed:
                        logger.info('Removed stale snapshot; provider=%s consecutive=%s', label, fail_count)
                        try:
                            persist_owned(hist_to_persist)
                        except Exception:
                            pass
                continue

            with _STATE_LOCK:
                if not state_repository.valid(target_lease):
                    return []
                clear_query_failure(query_fail_counts, fail_key)
            snap = collected.snapshot
            if snap is None:
                continue

            ts = int(snap.ts or time.time())
            with _STATE_LOCK:
                if state_repository.valid(target_lease) and positive_observations is not None:
                    positive_observations.setdefault(name, {})[srv] = _snapshot_dict(snap)
            with _STATE_LOCK:
                if not state_repository.valid(target_lease):
                    return []
                prev_obj = current_results[name].get(srv)
                hist_obj = history[name]
            prev = Snapshot.from_legacy(prev_obj) if isinstance(prev_obj, dict) else None
            # initial population
            if prev_obj is None:
                hist_to_persist = None
                with _STATE_LOCK:
                    if not state_repository.valid(target_lease):
                        return []
                    hist_obj = history[name]
                    current_results[name][srv] = _snapshot_dict(snap)
                    try:
                        hist_obj.setdefault('current', {})[srv] = _snapshot_dict(snap)
                        meta = hist_obj.setdefault('meta', {})
                        meta.setdefault('first_seen', ts)
                        meta.setdefault('last_changed', ts)
                    finally:
                        # Current is published even if a later history update fails.
                        bump_state_version()
                    hist_to_persist = clone_history_entry(hist_obj)
                logger.info('INIT snapshot; provider=%s values=%s decoded=%s',
                            label, len(snap.values), len(snap.decoded_ips))
                try:
                    persist_owned(hist_to_persist)
                except Exception:
                    pass
                continue

            # changed?
            changed = _snapshot_changed(prev_obj if isinstance(prev_obj, dict) else prev, snap)

            if changed:
                hist_to_persist = None
                ev = {
                    'ts': ts,
                    'server': srv,
                    'type': rtype,
                    'old': _history_snapshot(prev_obj if isinstance(prev_obj, dict) else prev),
                    'new': _history_snapshot(snap),
                }
                with _STATE_LOCK:
                    if not state_repository.valid(target_lease):
                        return []
                    hist_obj = history[name]
                    events = hist_obj.setdefault('events', [])
                    events.append(ev)
                    try:
                        hist_obj['events'] = trim_history_events(events)
                        meta = hist_obj.setdefault('meta', {})
                        meta['last_changed'] = ts
                        meta.setdefault('first_seen', ev['old'].get('ts', ts) if isinstance(ev.get('old'), dict) else ts)
                        hist_obj.setdefault('current', {})[srv] = _snapshot_dict(snap)
                        current_results[name][srv] = _snapshot_dict(snap)
                    finally:
                        # The event is published even if a later history update fails.
                        bump_state_version()
                    hist_to_persist = clone_history_entry(hist_obj)
                logger.info('CHANGED snapshot; provider=%s values=%s decoded=%s',
                            label, len(snap.values), len(snap.decoded_ips))
                try:
                    persist_owned(hist_to_persist)
                except Exception:
                    pass

    # Update per-domain NXDOMAIN lifecycle metadata once per domain cycle.
    try:
        ts_cycle = int(time.time())
        hist_to_persist = None
        with _STATE_LOCK:
            if not state_repository.valid(target_lease):
                return []
            had_meta = bool(history[name].get('meta'))
            lifecycle_changed = update_nxdomain_lifecycle(
                history,
                name,
                domain_query_total,
                domain_success_count,
                domain_nxdomain_count,
                domain_error_count,
                ts_cycle,
            )
            # Even default lifecycle fields admit a new domain_meta projection.
            if lifecycle_changed or (not had_meta and bool(history[name].get('meta'))):
                bump_state_version()
            if lifecycle_changed:
                hist_to_persist = clone_history_entry(history.get(name))
        if lifecycle_changed:
            try:
                persist_owned(hist_to_persist)
            except Exception:
                pass
    except Exception:
        pass

    # Domain-level change extraction (alert sending happens at full-cycle level).
    try:
        domain_now_managed_ips = collect_domain_managed_ips(current_results, name, rtype=rtype,
                                                           active_servers=active_servers)
        added_ips = sorted(domain_now_managed_ips - domain_prev_managed_ips)
        if added_ips:
            added_alert_tuples.extend([(ip, name, rtype) for ip in added_ips])
    except Exception:
        pass
    return added_alert_tuples


from security.jobs import audited_force


class CycleResult(dict):
    """Compatible active map plus fresh positive query evidence for forces."""
    def __init__(self, active, positive, complete=True):
        super().__init__(active)
        self.positive = positive
        self.complete = complete


@audited_force
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
    ens_rpc_url: Optional[str] = None,
    sns_proxy_hosts: Optional[List[str]] = None,
    suppressed_added_ips: Optional[Set[str]] = None,
    state_repository=None,
    target_leases=None,
    registry_view=None,
) -> Dict[str, Any]:
    """Run a full scan cycle across domains.

    Returns the updated active_ip_map (for removal reconciliation).
    """
    domains: List[DomainSpec] = normalized_domain_specs(domains_raw)

    # Optional forced resolve subset.
    if force_req and 'domains' in force_req:
        target_domains = coerce_domains(force_req.get('domains') or [])
    else:
        target_domains = domains

    target_servers_override = force_req.get('servers') if force_req and 'servers' in force_req else None

    application_owned = state_repository is not None
    if state_repository is None:
        state_repository = MonitorStateRepository(current_results, history, history_dir, domains)
    if force_req and '_target_leases' in force_req:
        # Original admission tokens are authoritative; never use freshly
        # captured tokens to resurrect old queued intent.
        target_leases = force_req['_target_leases']
        registry_view = force_req.get('_registry_view', registry_view)
        from copy import deepcopy
        # The envelope is not target authority. Execute detached copies of the
        # definitions owned by original admission tokens, including every token.
        target_domains = [deepcopy(lease.target.definition) for lease in target_leases.values()
                          if lease is not None]
        if force_req.get('_terminal_outcome') is not None or not all(
                state_repository.valid(lease) for lease in target_leases.values()):
            from security.jobs import finish_force
            finish_force(force_req, 'failure')
            return {}
    elif force_req and application_owned:
        # Legacy helper requests without a repository are allowed below; an
        # application-owned repository never grants missing admission tokens.
        from security.jobs import finish_force
        finish_force(force_req, 'failure')
        return {}
    if target_leases is None:
        target_leases = state_repository.capture()

    import uuid
    cycle_id = uuid.uuid4().hex
    cycle_quality = []
    delivery_runtime = getattr(state_repository, 'delivery_runtime', None)
    positive_observations = {}
    cycle_added_tuples: List[Tuple[str, str, str]] = []
    for ds in target_domains:
        target_lease = target_leases.get(_domain_storage_name(ds))
        if not state_repository.valid(target_lease):
            continue
        from .targets import providers_for
        svr_list = providers_for(
            ds, target_servers_override if target_servers_override is not None else servers,
            force_req.get('ens_rpc_url', ens_rpc_url) if force_req else ens_rpc_url,
            force_req.get('sns_proxy_hosts', sns_proxy_hosts) if force_req else sns_proxy_hosts)
        if not svr_list:
            continue
        domain_added = run_domain_cycle(
            domain=ds,
            servers=svr_list,
            current_results=current_results,
            history=history,
            history_dir=history_dir,
            query_fail_counts=query_fail_counts,
            max_workers=max_workers,
            state_repository=state_repository,
            target_lease=target_lease,
            positive_observations=positive_observations,
            registry_view=registry_view,
            cycle_id=cycle_id, cycle_quality=cycle_quality,
            active_servers=providers_for(ds, servers, ens_rpc_url, sns_proxy_hosts),
        )
        if domain_added:
            cycle_added_tuples.extend(domain_added)

    # Added-IP alerts are sent once per full cycle (not per domain/server).
    if cycle_added_tuples:
        suppressed = {str(ip).strip() for ip in (suppressed_added_ips or set()) if str(ip or '').strip()}
        if suppressed:
            before_count = len(cycle_added_tuples)
            cycle_added_tuples = [entry for entry in cycle_added_tuples if str(entry[0]) not in suppressed]
            suppressed_count = before_count - len(cycle_added_tuples)
            if suppressed_count:
                logger.info("Suppressed %s reappeared-IP addition alert(s) during removal grace", suppressed_count)

    if cycle_added_tuples and delivery_runtime is None:
        deduped_added = state_repository.admit_additions(target_leases, cycle_added_tuples, _dedupe_alert)
        if deduped_added:
            try:
                scope = 'force' if (force_req and 'domains' in force_req) else 'full'
                if target_servers_override is not None:
                    server_targets = len([str(x).strip() for x in (target_servers_override or []) if str(x).strip()])
                else:
                    server_targets = len([str(x).strip() for x in (servers or []) if str(x).strip()])
                alert_new_ips(
                    deduped_added,
                    context={
                        'scan_scope': scope,
                        'domain_targets': len(target_domains),
                        'server_targets': int(server_targets),
                    },
                )
            except Exception:
                pass

    if force_req and not all(state_repository.valid(target_leases.get(_domain_storage_name(ds)))
                             for ds in target_domains):
        from security.jobs import finish_force
        finish_force(force_req, 'failure')
        return {}

    # Projection always uses the complete configured provider set, even when
    # this execution selected a DNS subset. Retired raw history stays intact.
    from .targets import active_target_projection
    projection = active_target_projection(domains, servers, ens_rpc_url, sns_proxy_hosts)
    return CycleResult(collect_active_ip_map(current_results, active_providers=projection),
                       collect_active_ip_map(positive_observations, active_providers=projection),
                       complete=all(cycle_quality))


def reconcile_scan(store, snapshot, previous, current, tracker):
    """Admission of baseline/grace is atomic relative to config publication."""
    runtime = getattr(store.state_repository, 'delivery_runtime', None)
    if runtime is not None:
        accepted = runtime.complete(snapshot, current)
        return accepted, (current if accepted and snapshot.force_req is None
                          and getattr(current, 'complete', True) else previous)
    with store.lock:
        if snapshot.force_req is not None:
            job = snapshot.force_req
            leases = job.get('_target_leases')
            if job.get('_terminal_outcome') == 'failure' or leases is None:
                return False, previous
            accepted = store.state_repository.admit_force_positive(
                leases, lambda: tracker.cancel_present(getattr(current, 'positive', {})))
            return accepted, previous
        accepted, removed = store.state_repository.admit_reconciliation(
            snapshot.generation, snapshot.target_leases,
            lambda: _dedupe_alert('Removed', tracker.reconcile(previous, current)))
    if not accepted:
        return False, previous
    if removed:
        try:
            alert_removed_ips(removed, context={
                'scan_scope': 'full', 'domain_targets': len(snapshot.domains),
                'server_targets': len(snapshot.servers)})
        except Exception:
            pass
    return True, current


def reconcile_removed_ips(
    active_ip_map_prev: Dict[str, Any],
    active_ip_map_now: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
    removal_tracker: Optional[IpRemovalGraceTracker] = None,
) -> Dict[str, Any]:
    """Reconcile removals, deferring alerts when a grace tracker is supplied.

    The no-tracker path retains the historical immediate-removal behavior for
    compatibility with direct callers. The monitor runtime supplies a
    persistent 24-hour tracker.
    """
    tracker = removal_tracker or IpRemovalGraceTracker(grace_seconds=0)
    removed_tuples = tracker.reconcile(active_ip_map_prev, active_ip_map_now)
    if removed_tuples:
        removed_tuples = _dedupe_alert('Removed', removed_tuples)
        if removed_tuples:
            try:
                alert_removed_ips([(ip, label, _t) for (ip, label, _t) in removed_tuples], context=context)
            except Exception:
                pass
    return active_ip_map_now
