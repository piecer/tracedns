"""Request-side projections of already-published data; no source-state access."""
import ipaddress
import hashlib
import json
import time
from bisect import bisect_right

from .utils import qs_bool, send_json

MAX_RESPONSE_BYTES = 1024 * 1024


def _number(qs, key, default, minimum=0, maximum=5000):
    try:
        return max(minimum, min(maximum, int(qs.get(key, [default])[0])))
    except (ValueError, TypeError):
        return default


def _report(reports, ip):
    try:
        return reports.get(str(ipaddress.ip_address(ip)))
    except ValueError:
        return None


def _domain_reports(rows, reports):
    out = []
    for row in rows:
        ips = [dict(item, vt=_report(reports, item['ip'])) for item in row['ip_rows']]
        counters = {}
        for item in ips:
            vt = item['vt'] or {}
            asn, owner, country = vt.get('asn'), vt.get('as_owner'), vt.get('country')
            if asn is None and not owner and not country:
                continue
            key = (asn, owner, country)
            counter = counters.setdefault(key, {'asn': asn, 'as_owner': owner, 'country': country, 'count': 0})
            counter['count'] += 1
        summary = sorted(counters.values(), key=lambda value: (-value['count'], str(value['asn'] or '')))
        out.append(dict(row, ip_rows=ips, as_summary=summary))
    return out


def _page(offset, limit, displayed, total, unit):
    return {'offset': offset, 'limit': limit, 'displayed': displayed, 'total': total, 'unit': unit,
            'next_offset': offset + displayed if offset + displayed < total else None,
            'previous_offset': max(0, offset - limit) if offset else None}


def _domain_page(rows, prefix, offset, limit):
    selected = []
    index = max(0, bisect_right(prefix, offset) - 1)
    remaining = limit
    while index < len(rows) and remaining:
        row = rows[index]
        start = max(0, offset - prefix[index])
        count = min(remaining, prefix[index + 1] - prefix[index] - start)
        items = row['ip_rows'][start:start + count]
        selected.append(dict(row, ip_rows=items,
                             resolved_ips=[item['ip'] for item in items if item['role'] == 'resolved'],
                             decoded_ips=[item['ip'] for item in items if item['role'] == 'decoded'],
                             ip_rows_total=len(row['ip_rows']), ip_rows_offset=start,
                             ip_rows_truncated=start > 0 or start + count < len(row['ip_rows'])))
        remaining -= count
        index += 1
    return selected, limit - remaining


def _encode(handler, payload):
    if hasattr(handler, 'sanitize_response'):
        payload = handler.sanitize_response(payload, 200)
    return payload, json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def _send_versioned(handler, payload, qs):
    payload, body = _encode(handler, payload)
    version = hashlib.sha256(body).hexdigest()
    if qs.get('if_version', [''])[0] == version:
        payload = {key: value for key, value in payload.items() if key in ('snapshot', 'page', 'enrichment')}
        payload['unchanged'] = True
    payload['view_version'] = version
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(body) > MAX_RESPONSE_BYTES:
        return send_json(handler, {'error': 'Prepared entry exceeds response limit; download full legacy JSON.'}, 422)
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _project_page(data, metadata, kind, qs, offset, limit):
    payload = {'snapshot': metadata}
    query = str(qs.get('q', [''])[0]).strip().lower()
    if kind == 'results':
        keys = data['result_keys'] if 'result_keys' in data else sorted(data['results']['results_agg'])
        if query:
            keys = [key for key in keys if query in key.lower()]
        total = len(keys)
        keys = keys[offset:offset + limit]
        for field in ('results_agg', 'domain_meta', 'results'):
            if field == 'results' and not qs_bool(qs, 'include_raw', default=not qs_bool(qs, 'aggregate')):
                continue
            payload[field] = {key: data['results'].get(field, {}).get(key, {}) for key in keys}
        payload['results_total_count'] = total
        payload['page'] = _page(offset, limit, len(keys), total, 'domains')
    else:
        include_vt = qs_bool(qs, 'include_vt', default=kind == 'domains')
        if kind == 'ips':
            rows = data['ips']
            if qs_bool(qs, 'valid_only'):
                rows = data['valid_ips'] if 'valid_ips' in data else [row for row in rows if row['valid']]
            if qs.get('since'):
                cutoff = int(time.time()) - _number(qs, 'since', 0, maximum=315360000)
                rows = [row for row in rows if row['last_ts'] >= cutoff]
            total = len(rows)
            page = [dict(row) for row in rows[offset:offset + limit]]
            payload.update(ips=page, ips_total_count=total, ips_displayed_count=len(page),
                           ips_offset=offset, ips_limit=limit, ips_truncated=offset + len(page) < total,
                           include_vt=include_vt, vt_budget=_number(qs, 'vt_budget', limit), vt_workers=4)
            payload['page'] = _page(offset, limit, len(page), total, 'ips')
            payload['all_ips_total_count'] = len(data['ips'])
        else:
            rows = data['domains']
            prefix = data.get('domain_prefix')
            if query:
                rows = [row for row in rows if query in row['domain'].lower()]
                prefix = None
            if prefix is None:
                prefix = [0]
                for row in rows:
                    prefix.append(prefix[-1] + max(1, len(row['ip_rows'])))
            page, displayed = _domain_page(rows, prefix, offset, limit)
            payload.update(domains=page, include_vt=include_vt, domains_total_count=len(rows))
            payload['page'] = _page(offset, limit, displayed, prefix[-1], 'ip_rows')
            payload['page']['domains_total'] = len(rows)
    return payload


def serve_prepared(handler, model, enrichment, kind, qs):
    if qs.get('vt_mode', ['background'])[0] not in ('sync', 'background'):
        return send_json(handler, {'error': 'invalid vt_mode'}, 400)
    if len(str(qs.get('q', [''])[0]).strip()) > 253:
        return send_json(handler, {'error': 'q must contain at most 253 characters'}, 400)
    data, metadata = model.read() if model is not None else (None, {'ready': False, 'stale': True, 'status': 'unavailable'})
    if data is None:
        return send_json(handler, {'snapshot': metadata}, 202)
    offset = _number(qs, 'offset', 0, maximum=10000000)
    limit = _number(qs, 'limit', 100, minimum=1, maximum=200)
    include_vt = kind != 'results' and qs_bool(qs, 'include_vt', default=kind == 'domains')

    def fits(candidate):
        # Reserve compact VT plus AS summary bytes before queue admission.
        # The worker bounds each report below 4096 encoded bytes.
        reserve = 8192 * candidate['page']['displayed'] if include_vt else 0
        return len(_encode(handler, candidate)[1]) + reserve + 4096 <= MAX_RESPONSE_BYTES

    payload = _project_page(data, metadata, kind, qs, offset, limit)
    if not fits(payload):
        low, high, best = 0, payload['page']['displayed'] - 1, None
        while low < high:
            middle = (low + high + 1) // 2
            candidate = _project_page(data, metadata, kind, qs, offset, middle)
            if fits(candidate):
                low, best = middle, candidate
            else:
                high = middle - 1
        if low == 0:
            return send_json(handler, {'error': 'Prepared entry exceeds response limit; download full legacy JSON.'}, 422)
        payload = best
    if kind != 'results':
        page = payload[kind]
        reports, progress = {}, {'status': 'disabled'}
        if include_vt:
            progress = {'status': 'unavailable'}
            ips = ([row['ip'] for row in page] if kind == 'ips'
                   else [item['ip'] for row in page for item in row['ip_rows']])
            if enrichment is not None:
                reports, progress = enrichment.request(
                    ips, budget=_number(qs, 'vt_budget', 200),
                    owner=str((getattr(handler, 'principal', None) or {}).get('id', 'local')))
            if kind == 'ips':
                for row in page:
                    row['vt'] = _report(reports, row['ip'])
            else:
                payload['domains'] = _domain_reports(page, reports)
        payload['enrichment'] = progress
    return _send_versioned(handler, payload, qs)
