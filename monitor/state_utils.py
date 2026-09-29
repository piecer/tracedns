from __future__ import annotations

from typing import Dict, Optional, Set, Any

from models import Snapshot
from .runtime_state import clone_current_results, snapshot_current_results_only, state_lock


def collect_active_ip_map(current_results: Dict[str, Any], allowed_domains: Optional[Set[str]] = None,
                          active_providers=None) -> Dict[str, Set[str]]:
    """Build managed IP -> domain-name-set map from current snapshots."""
    allow = None if allowed_domains is None else set(allowed_domains)
    out: Dict[str, Set[str]] = {}
    _, captured = snapshot_current_results_only(current_results)
    for domain, server_map in captured.items():
        if allow is not None and domain not in allow:
            continue
        if not isinstance(server_map, dict):
            continue
        for _srv, snap_obj in server_map.items():
            if active_providers is not None and _srv not in active_providers.get(domain, ()):
                continue
            snap = Snapshot.from_legacy(snap_obj)
            for ip in snap.managed_ips():
                out.setdefault(ip, set()).add(domain)
    return out


def collect_domain_managed_ips(current_results: Dict[str, Any], domain: str, rtype: Optional[str] = None,
                               active_servers=None) -> Set[str]:
    """Collect the current managed IP set for one domain across all DNS servers."""
    name = str(domain or '').strip()
    if not name:
        return set()
    with state_lock():
        server_map = clone_current_results({name: current_results.get(name, {})}).get(name, {})
    if not isinstance(server_map, dict):
        return set()

    prefer = str(rtype or '').upper()
    out: Set[str] = set()
    for _srv, snap_obj in server_map.items():
        if active_servers is not None and _srv not in active_servers:
            continue
        snap = Snapshot.from_legacy(snap_obj)
        use_type = prefer or str(snap.type or '').upper()
        # Force interpretation in case legacy snapshot has mixed fields
        if use_type in ('TXT', 'ENS', 'SNS'):
            for ip in (snap.decoded_ips or []):
                s = str(ip or '').strip()
                if s:
                    out.add(s)
        elif use_type == 'A':
            for ip in (snap.values or []):
                s = str(ip or '').strip()
                if s:
                    out.add(s)
    return out
