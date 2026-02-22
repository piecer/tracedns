from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from a_decoder import decode_a_hidden_ips
from dns_query import query_dns
from models import DomainSpec, Snapshot, QueryResult
from txt_decoder import decode_txt_hidden_ips


@dataclass
class Collected:
    query: QueryResult
    snapshot: Optional[Snapshot]


def collect_snapshot(domain: DomainSpec, server: str) -> Collected:
    """Query DNS for one (domain, server) and decode into a Snapshot.

    - Returns snapshot=None on transport errors (status == 'error'), matching legacy behavior.
    - For A record post-processing, we store transformed managed IPs in snapshot.values.
    """
    name = domain.name
    rtype = str(domain.type or 'A').upper()

    qret = query_dns(server, name, rtype=rtype, with_meta=True)
    status = 'error'
    values: List[str] = []
    if isinstance(qret, dict):
        status = str(qret.get('status') or 'error').lower()
        values = qret.get('values', []) if isinstance(qret.get('values'), list) else []
    query = QueryResult(server=str(server), domain=name, rtype=rtype, status=status, values=[str(v) for v in values])

    if status == 'error':
        return Collected(query=query, snapshot=None)

    ts = int(time.time())

    # decode / post-process
    snap_values = [str(v) for v in (values or []) if str(v or '').strip()]
    decoded: List[str] = []

    if rtype == 'TXT':
        method = domain.txt_decode or 'cafebabe_xor_base64'
        decoded = decode_txt_hidden_ips(snap_values, method=method, domain=name)
        snap = Snapshot(type='TXT', values=snap_values, decoded_ips=decoded, ts=ts, txt_decode=method)
        return Collected(query=query, snapshot=snap)

    # A record
    a_decode = (domain.a_decode or 'none')
    a_decode_active = str(a_decode).strip().lower() not in ('', 'none')
    if a_decode_active:
        transformed = decode_a_hidden_ips(snap_values, method=a_decode, key_hex=domain.a_xor_key, domain=name)
        snap_values = sorted(set([str(v) for v in (transformed or []) if str(v or '').strip()]))
        snap = Snapshot(type='A', values=snap_values, decoded_ips=[], ts=ts, a_decode=a_decode, a_xor_key=domain.a_xor_key)
        return Collected(query=query, snapshot=snap)

    snap = Snapshot(type='A', values=snap_values, decoded_ips=[], ts=ts)
    return Collected(query=query, snapshot=snap)
