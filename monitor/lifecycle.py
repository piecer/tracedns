from __future__ import annotations

from typing import Any, Dict


def update_nxdomain_lifecycle(history: Dict[str, Any], name: str, query_total: int, success_count: int, nxdomain_count: int, error_count: int, ts_now: int) -> bool:
    """Update per-domain NXDOMAIN lifecycle metadata.

    Kept behavior-compatible with legacy `_update_nxdomain_lifecycle`.

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
