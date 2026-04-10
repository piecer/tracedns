from __future__ import annotations

import threading
from typing import Any, Dict, Tuple


_STATE_LOCK = threading.RLock()
_STATE_VERSION = 1


def state_lock() -> threading.RLock:
    return _STATE_LOCK


def get_state_version() -> int:
    with _STATE_LOCK:
        return int(_STATE_VERSION)


def bump_state_version() -> int:
    global _STATE_VERSION
    with _STATE_LOCK:
        _STATE_VERSION += 1
        return int(_STATE_VERSION)


def clone_snapshot(snapshot_obj: Any) -> Dict[str, Any]:
    if not isinstance(snapshot_obj, dict):
        return {}
    out = {
        'type': snapshot_obj.get('type'),
        'values': list(snapshot_obj.get('values') or []),
        'decoded_ips': list(snapshot_obj.get('decoded_ips') or []),
        'ts': int(snapshot_obj.get('ts') or 0),
    }
    for key in ('txt_decode', 'a_decode', 'a_xor_key', 'ens_text_key', 'ens_decode', 'ens_xor_byte'):
        if key in snapshot_obj and snapshot_obj.get(key) is not None:
            out[key] = snapshot_obj.get(key)
    ens_options = snapshot_obj.get('ens_options')
    if isinstance(ens_options, dict) and ens_options:
        out['ens_options'] = dict(ens_options)
    return out


def clone_current_results(current_results: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    out: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for domain, server_map in (current_results or {}).items():
        if not isinstance(server_map, dict):
            continue
        out[str(domain)] = {
            str(server): clone_snapshot(info)
            for server, info in server_map.items()
            if isinstance(info, dict)
        }
    return out


def clone_history_meta(history: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for domain, hist_obj in (history or {}).items():
        if not isinstance(hist_obj, dict):
            continue
        meta = hist_obj.get('meta')
        if isinstance(meta, dict):
            out[str(domain)] = dict(meta)
    return out


def clone_history_entry(
    history_obj: Any,
    *,
    include_events: bool = True,
    include_current: bool = True,
) -> Dict[str, Any]:
    if not isinstance(history_obj, dict):
        return {'meta': {}, 'events': [], 'current': {}}
    meta = history_obj.get('meta')
    events = history_obj.get('events')
    current = history_obj.get('current')
    return {
        'meta': dict(meta) if isinstance(meta, dict) else {},
        'events': list(events) if include_events and isinstance(events, list) else [],
        'current': clone_current_results({'_': current}).get('_', {})
        if include_current and isinstance(current, dict)
        else {},
    }


def snapshot_results_inputs(
    current_results: Dict[str, Any],
    history: Dict[str, Any],
) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
    with _STATE_LOCK:
        return (
            int(_STATE_VERSION),
            clone_current_results(current_results),
            clone_history_meta(history),
        )


def snapshot_current_results_only(current_results: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    with _STATE_LOCK:
        return int(_STATE_VERSION), clone_current_results(current_results)


def snapshot_history_meta_only(history: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    with _STATE_LOCK:
        return int(_STATE_VERSION), clone_history_meta(history)


def snapshot_history_domain(history: Dict[str, Any], domain: str) -> Tuple[int, Dict[str, Any]]:
    with _STATE_LOCK:
        return int(_STATE_VERSION), clone_history_entry(history.get(domain))


def snapshot_current_and_history_events(
    current_results: Dict[str, Any],
    history: Dict[str, Any],
) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
    with _STATE_LOCK:
        return (
            int(_STATE_VERSION),
            clone_current_results(current_results),
            {
                str(domain): clone_history_entry(hist_obj, include_events=True, include_current=False)
                for domain, hist_obj in (history or {}).items()
                if isinstance(hist_obj, dict)
            },
        )
