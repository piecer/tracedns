from __future__ import annotations

from typing import Dict, Optional, Set, Any

from models import Snapshot


def collect_active_ip_map(current_results: Dict[str, Any], allowed_domains: Optional[Set[str]] = None) -> Dict[str, Set[str]]:
    """Build managed IP -> domain-name-set map from current snapshots."""
    allow = None if allowed_domains is None else set(allowed_domains)
    out: Dict[str, Set[str]] = {}
    for domain, server_map in (current_results or {}).items():
        if allow is not None and domain not in allow:
            continue
        if not isinstance(server_map, dict):
            continue
        for _srv, snap_obj in server_map.items():
            snap = Snapshot.from_legacy(snap_obj)
            for ip in snap.managed_ips():
                out.setdefault(ip, set()).add(domain)
    return out


def collect_domain_managed_ips(current_results: Dict[str, Any], domain: str, rtype: Optional[str] = None) -> Set[str]:
    """Collect the current managed IP set for one domain across all DNS servers."""
    name = str(domain or '').strip()
    if not name:
        return set()
    server_map = current_results.get(name, {})
    if not isinstance(server_map, dict):
        return set()

    prefer = str(rtype or '').upper()
    out: Set[str] = set()
    for _srv, snap_obj in server_map.items():
        snap = Snapshot.from_legacy(snap_obj)
        use_type = prefer or str(snap.type or '').upper()
        # Force interpretation in case legacy snapshot has mixed fields
        if use_type == 'TXT':
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
