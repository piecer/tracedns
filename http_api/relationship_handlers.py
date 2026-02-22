from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Tuple

try:
    from vt_lookup import begin_cache_batch, end_cache_batch, get_ip_report
except Exception:
    begin_cache_batch = None
    end_cache_batch = None
    get_ip_report = None

logger = logging.getLogger(__name__)


def _parse_ip_tokens(raw: Any) -> Tuple[List[str], List[str]]:
    """Return (valid_ips, invalid_tokens). De-dupes while preserving order."""
    import re as _re
    import ipaddress as _ip

    tokens: List[str] = []
    if isinstance(raw, str):
        tokens = [x.strip() for x in _re.split(r'[\s,;|]+', raw) if x and x.strip()]
    elif isinstance(raw, list):
        for item in raw:
            if item is None:
                continue
            s = str(item).strip()
            if not s:
                continue
            parts = [x.strip() for x in _re.split(r'[\s,;|]+', s) if x and x.strip()]
            tokens.extend(parts)
    else:
        return ([], [])

    unique: List[str] = []
    seen = set()
    for t in tokens:
        if t in seen:
            continue
        seen.add(t)
        unique.append(t)

    valid: List[str] = []
    invalid: List[str] = []
    seen_valid = set()
    for tok in unique:
        try:
            ip_s = str(_ip.ip_address(tok))
            if ip_s not in seen_valid:
                seen_valid.add(ip_s)
                valid.append(ip_s)
        except Exception:
            invalid.append(tok)

    return (valid, invalid)


def handle_ip_relationship_analysis(handler, *, gather_ip_map_fn):
    """Analyze relationships among a user-supplied IP list.

    This is intentionally scoped to the provided IP list (A).

    Input JSON:
      - ips: string or list
      - min_shared_domains: int (default 1)
      - top_pairs: int (default 50)
      - include_vt: bool (default false)
      - vt_workers: int (default 8)
      - vt_budget: int (default 200)

    The server uses existing observed domain<->ip mappings from tracedns state.
    """
    length = int(handler.headers.get('Content-Length', '0'))
    body = handler.rfile.read(length) if length > 0 else b''
    try:
        data = json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        return handler._send_json({'error': 'invalid json'}, 400)

    valid_ips, invalid = _parse_ip_tokens(data.get('ips'))
    if not valid_ips:
        return handler._send_json({'error': 'no valid ips', 'invalid_inputs': invalid[:200]}, 400)

    max_ips = 5000
    if len(valid_ips) > max_ips:
        return handler._send_json({'error': f'too many ips (max {max_ips})'}, 400)

    def _to_int(name, default, min_v=None, max_v=None):
        raw = data.get(name, default)
        try:
            n = int(raw)
        except Exception:
            n = int(default)
        if min_v is not None and n < min_v:
            n = min_v
        if max_v is not None and n > max_v:
            n = max_v
        return n

    min_shared = _to_int('min_shared_domains', 1, 1, 999999)
    top_pairs = _to_int('top_pairs', 50, 1, 5000)

    include_vt = bool(data.get('include_vt', False))
    vt_workers = _to_int('vt_workers', 8, 1, 32)
    vt_budget = _to_int('vt_budget', 200, 0, 5000)

    # Build ip->domains map from tracedns observed data (current+history)
    ip_map = gather_ip_map_fn()

    observed = []
    for ip in valid_ips:
        ent = ip_map.get(ip)
        if not ent:
            observed.append({'ip': ip, 'observed': False, 'domains': [], 'count': 0, 'last_ts': 0})
            continue
        domains = sorted(list(ent.get('domains') or []))
        observed.append({
            'ip': ip,
            'observed': True,
            'domains': domains,
            'domain_count': len(domains),
            'count': int(ent.get('count') or 0),
            'last_ts': int(ent.get('last_ts') or 0),
        })

    # Build domain -> list(ips) restricted to input set
    input_set = set(valid_ips)
    domain_to_ips: Dict[str, List[str]] = {}
    ip_to_domains: Dict[str, set] = {}
    for ip in valid_ips:
        doms = set((ip_map.get(ip) or {}).get('domains') or [])
        ip_to_domains[ip] = doms
        for d in doms:
            domain_to_ips.setdefault(d, []).append(ip)

    # Pair weights by shared domains
    pair_shared: Dict[Tuple[str, str], int] = {}
    for d, ips in domain_to_ips.items():
        uniq = sorted(set([ip for ip in ips if ip in input_set]))
        if len(uniq) < 2:
            continue
        for i in range(len(uniq)):
            for j in range(i + 1, len(uniq)):
                a, b = uniq[i], uniq[j]
                pair_shared[(a, b)] = pair_shared.get((a, b), 0) + 1

    pairs = []
    for (a, b), shared in pair_shared.items():
        if shared < min_shared:
            continue
        da = ip_to_domains.get(a, set())
        db = ip_to_domains.get(b, set())
        union = len(da | db) if da or db else 0
        jacc = (shared / union) if union else 0.0
        pairs.append({
            'a': a,
            'b': b,
            'shared_domains': int(shared),
            'jaccard': float(jacc),
        })

    pairs.sort(key=lambda x: (-x['shared_domains'], -x['jaccard'], x['a'], x['b']))
    top_pairs_list = pairs[:top_pairs]

    # Clustering using union-find on shared>=min_shared
    parent: Dict[str, str] = {ip: ip for ip in valid_ips}

    def find(x):
        while parent.get(x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for it in pairs:
        if int(it.get('shared_domains') or 0) >= min_shared:
            union(it['a'], it['b'])

    clusters: Dict[str, List[str]] = {}
    for ip in valid_ips:
        clusters.setdefault(find(ip), []).append(ip)

    cluster_list = []
    for root, ips in clusters.items():
        ips_sorted = sorted(ips)
        dom_union = set()
        for ip in ips_sorted:
            dom_union.update(ip_to_domains.get(ip, set()))
        cluster_list.append({
            'cluster_id': root,
            'size': len(ips_sorted),
            'ips': ips_sorted,
            'domain_count': len(dom_union),
            'domains_sample': sorted(list(dom_union))[:20],
        })

    cluster_list.sort(key=lambda x: (-x['size'], -x['domain_count'], x['cluster_id']))

    # Optional VT enrichment for cluster summary
    vt_enabled = bool(include_vt and get_ip_report)
    if include_vt and not get_ip_report:
        vt_enabled = False

    vt_attempted = 0
    if vt_enabled and vt_budget > 0:
        all_cluster_ips = []
        for c in cluster_list:
            all_cluster_ips.extend(c['ips'])
        # Dedup order
        seen = set()
        all_cluster_ips = [ip for ip in all_cluster_ips if not (ip in seen or seen.add(ip))]
        lookup_ips = all_cluster_ips[:vt_budget]
        vt_attempted = len(lookup_ips)

        reports: Dict[str, Any] = {}
        if begin_cache_batch and end_cache_batch:
            begin_cache_batch()
        try:
            if vt_workers <= 1 or len(lookup_ips) <= 1:
                for ip in lookup_ips:
                    try:
                        reports[ip] = get_ip_report(ip)
                    except Exception:
                        reports[ip] = None
            else:
                from concurrent.futures import ThreadPoolExecutor, as_completed

                def _lookup(ip_str: str):
                    try:
                        return get_ip_report(ip_str)
                    except Exception:
                        return None

                with ThreadPoolExecutor(max_workers=vt_workers) as ex:
                    futs = {ex.submit(_lookup, ip): ip for ip in lookup_ips}
                    for fut in as_completed(futs):
                        ip = futs[fut]
                        reports[ip] = fut.result()
        finally:
            if begin_cache_batch and end_cache_batch:
                end_cache_batch(flush=True)

        # aggregate per cluster
        for c in cluster_list:
            ms = 0
            ss = 0
            asn_freq: Dict[str, int] = {}
            country_freq: Dict[str, int] = {}
            for ip in c['ips']:
                rep = reports.get(ip)
                if not isinstance(rep, dict):
                    continue
                ms += int(rep.get('malicious') or 0)
                ss += int(rep.get('suspicious') or 0)
                asn = rep.get('asn')
                country = rep.get('country')
                if asn is not None and str(asn).strip():
                    key = str(asn).strip()
                    asn_freq[key] = asn_freq.get(key, 0) + 1
                if country is not None and str(country).strip():
                    key = str(country).strip()
                    country_freq[key] = country_freq.get(key, 0) + 1
            top_asn = sorted(asn_freq.items(), key=lambda x: (-x[1], x[0]))[:3]
            top_country = sorted(country_freq.items(), key=lambda x: (-x[1], x[0]))[:3]
            c['vt_summary'] = {
                'malicious_total': ms,
                'suspicious_total': ss,
                'top_asn': top_asn,
                'top_country': top_country,
            }

    return handler._send_json({
        'status': 'ok',
        'submitted_count': len(valid_ips) + len(invalid),
        'valid_count': len(valid_ips),
        'invalid_count': len(invalid),
        'invalid_inputs': invalid[:200],
        'min_shared_domains': min_shared,
        'top_pairs': top_pairs,
        'observed': observed,
        'pair_count': len(pairs),
        'pairs': top_pairs_list,
        'clusters': cluster_list,
        'vt_enabled': vt_enabled,
        'vt_attempted': vt_attempted,
        'vt_budget': vt_budget,
        'vt_workers': vt_workers,
    })
