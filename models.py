#!/usr/bin/env python3
"""TraceDNS data models.

Goal: replace "anonymous dicts" passed across modules with explicit, typed
structures. Keep these models lightweight and JSON-serializable.

We intentionally avoid pydantic to keep dependencies minimal.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple


RecordType = str  # 'A' | 'TXT' | 'MIXED'


@dataclass(frozen=True)
class DomainSpec:
    name: str
    type: RecordType = 'A'
    txt_decode: Optional[str] = None
    a_decode: Optional[str] = None
    a_xor_key: Optional[str] = None


@dataclass
class Snapshot:
    type: RecordType
    values: List[str] = field(default_factory=list)
    decoded_ips: List[str] = field(default_factory=list)
    ts: int = 0
    txt_decode: Optional[str] = None
    a_decode: Optional[str] = None
    a_xor_key: Optional[str] = None

    def managed_ips(self) -> Set[str]:
        r = str(self.type or '').upper()
        if r == 'TXT':
            return {str(x).strip() for x in (self.decoded_ips or []) if str(x or '').strip()}
        if r == 'A':
            # A-type with post-process enabled stores transformed IPs in values.
            return {str(x).strip() for x in (self.values or []) if str(x or '').strip()}
        return set()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON output / persistence."""
        d = asdict(self)
        # keep output compact and compatible with legacy snapshots
        out = {
            'type': d.get('type'),
            'values': d.get('values') or [],
            'decoded_ips': d.get('decoded_ips') or [],
            'ts': int(d.get('ts') or 0),
        }
        if self.txt_decode:
            out['txt_decode'] = self.txt_decode
        if self.a_decode is not None:
            out['a_decode'] = self.a_decode
        if self.a_xor_key:
            out['a_xor_key'] = self.a_xor_key
        return out

    @staticmethod
    def from_legacy(obj: Any) -> 'Snapshot':
        """Create a Snapshot from legacy dicts used in current_results/history."""
        if not isinstance(obj, dict):
            return Snapshot(type='A')
        snap = Snapshot(
            type=str(obj.get('type') or 'A').upper(),
            values=[str(v) for v in (obj.get('values') or []) if str(v or '').strip()],
            decoded_ips=[str(v) for v in (obj.get('decoded_ips') or []) if str(v or '').strip()],
            ts=int(obj.get('ts') or 0),
            txt_decode=obj.get('txt_decode'),
            a_decode=obj.get('a_decode'),
            a_xor_key=obj.get('a_xor_key'),
        )
        return snap


@dataclass
class HistoryMeta:
    first_seen: int = 0
    last_changed: int = 0

    # NXDOMAIN lifecycle fields
    nxdomain_active: bool = False
    nxdomain_since: int = 0
    nxdomain_first_seen: int = 0
    nxdomain_cleared_ts: int = 0

    # Per-cycle stats
    dns_cycle_total: int = 0
    dns_cycle_success_count: int = 0
    dns_cycle_nxdomain_count: int = 0
    dns_cycle_error_count: int = 0

    dns_error_only_active: bool = False
    dns_last_success_ts: int = 0


@dataclass
class HistoryEvent:
    ts: int
    server: str
    type: RecordType
    old: Dict[str, Any]
    new: Dict[str, Any]


@dataclass
class DomainHistory:
    meta: HistoryMeta = field(default_factory=HistoryMeta)
    events: List[Dict[str, Any]] = field(default_factory=list)  # keep legacy dict events
    current: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # srv -> snapshot dict


@dataclass
class MonitorConfig:
    domains: List[Any] = field(default_factory=list)  # legacy domains list (dict or str)
    servers: List[str] = field(default_factory=list)
    interval: int = 60
    http_port: int = 8000
    max_workers: int = 8  # performance: parallel DNS queries per domain

    custom_decoders: List[Dict[str, Any]] = field(default_factory=list)
    custom_a_decoders: List[Dict[str, Any]] = field(default_factory=list)
    alerts: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CycleStats:
    query_total: int = 0
    success_count: int = 0
    nxdomain_count: int = 0
    error_count: int = 0


@dataclass
class QueryResult:
    server: str
    domain: str
    rtype: RecordType
    status: str
    values: List[str]


@dataclass
class SnapshotChange:
    domain: str
    server: str
    rtype: RecordType
    prev: Optional[Snapshot]
    new: Optional[Snapshot]
    ts: int

    def is_initial(self) -> bool:
        return self.prev is None and self.new is not None

    def is_changed(self) -> bool:
        if self.prev is None or self.new is None:
            return False
        return (
            (self.prev.values or []) != (self.new.values or [])
            or (self.prev.decoded_ips or []) != (self.new.decoded_ips or [])
            or str(self.prev.type).upper() != str(self.new.type).upper()
        )


def coerce_domains(domains: List[Any]) -> List[DomainSpec]:
    """Convert normalize_domains()-like structures into DomainSpec list."""
    out: List[DomainSpec] = []
    for d in domains or []:
        if isinstance(d, DomainSpec):
            out.append(d)
            continue
        if isinstance(d, dict):
            name = str(d.get('name') or '').strip()
            if not name:
                continue
            out.append(
                DomainSpec(
                    name=name,
                    type=str(d.get('type') or 'A').upper(),
                    txt_decode=d.get('txt_decode'),
                    a_decode=d.get('a_decode'),
                    a_xor_key=d.get('a_xor_key'),
                )
            )
        else:
            s = str(d or '').strip()
            if s:
                out.append(DomainSpec(name=s, type='A'))
    # de-dup by name
    seen = set()
    uniq = []
    for ds in out:
        if ds.name in seen:
            continue
        seen.add(ds.name)
        uniq.append(ds)
    return uniq
