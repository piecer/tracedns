from __future__ import annotations

from typing import Any, Dict

from a_decoder import A_DECODE_METHODS
from txt_decoder import TXT_DECODE_METHODS

from .context import HttpContext
from .utils import send_json, qs_bool


def handle_config(ctx: HttpContext, handler) -> None:
    with ctx.config_lock:
        cfg = {
            'domains': list(ctx.shared_config.get('domains', [])),
            'servers': list(ctx.shared_config.get('servers', [])),
            'interval': ctx.shared_config.get('interval'),
            'max_workers': ctx.shared_config.get('max_workers', 8),
        }
        if 'alerts' in ctx.shared_config:
            cfg['alerts'] = ctx.shared_config.get('alerts')
    send_json(handler, cfg)


def handle_results(ctx: HttpContext, handler, qs: Dict[str, Any]) -> None:
    try:
        agg_only = qs_bool(qs, 'aggregate', default=False)
        include_raw = qs_bool(qs, 'include_raw', default=(not agg_only))

        data = {} if include_raw else None
        data_agg: Dict[str, Any] = {}

        for d, m in ctx.current_results.items():
            if include_raw:
                data[d] = {}

            agg_entry = {
                'record_types': set(),
                'values': set(),
                'decoded_ips': set(),
                'servers': set(),
                'ts': 0,
                'txt_decodes': set(),
                'a_decodes': set(),
                'a_xor_keys': set(),
            }

            for srv, info in m.items():
                rtype = str(info.get('type') or 'A').upper()
                values = [str(v) for v in (info.get('values', []) or []) if str(v or '').strip()]
                decoded_ips = [str(v) for v in (info.get('decoded_ips', []) or []) if str(v or '').strip()]

                entry = None
                if include_raw:
                    entry = {'type': rtype, 'values': values, 'decoded_ips': decoded_ips, 'ts': info.get('ts')}

                if rtype == 'TXT' and info.get('txt_decode'):
                    if entry is not None:
                        entry['txt_decode'] = info.get('txt_decode')
                    agg_entry['txt_decodes'].add(str(info.get('txt_decode')))

                if rtype == 'A' and info.get('a_decode'):
                    if entry is not None:
                        entry['a_decode'] = info.get('a_decode')
                    agg_entry['a_decodes'].add(str(info.get('a_decode')))

                if rtype == 'A' and info.get('a_xor_key'):
                    if entry is not None:
                        entry['a_xor_key'] = info.get('a_xor_key')
                    agg_entry['a_xor_keys'].add(str(info.get('a_xor_key')))

                if include_raw:
                    data[d][srv] = entry

                agg_entry['record_types'].add(rtype)
                agg_entry['values'].update(values)
                agg_entry['decoded_ips'].update(decoded_ips)
                agg_entry['servers'].add(str(srv))
                try:
                    agg_entry['ts'] = max(int(agg_entry['ts']), int(info.get('ts') or 0))
                except Exception:
                    pass

            record_types = sorted(list(agg_entry['record_types']))
            if len(record_types) == 1:
                domain_type = record_types[0]
            elif not record_types:
                domain_type = 'A'
            else:
                domain_type = 'MIXED'

            method_parts = []
            if agg_entry['txt_decodes']:
                method_parts.append('TXT:' + ','.join(sorted(agg_entry['txt_decodes'])))
            if agg_entry['a_decodes']:
                a_method = 'A:' + ','.join(sorted(agg_entry['a_decodes']))
                if agg_entry['a_xor_keys']:
                    a_method += f" ({','.join(sorted(agg_entry['a_xor_keys']))})"
                method_parts.append(a_method)

            data_agg[d] = {
                'type': domain_type,
                'record_types': record_types,
                'values': sorted(list(agg_entry['values'])),
                'decoded_ips': sorted(list(agg_entry['decoded_ips'])),
                'servers': sorted(list(agg_entry['servers'])),
                'server_count': len(agg_entry['servers']),
                'ts': int(agg_entry['ts'] or 0),
                'txt_decodes': sorted(list(agg_entry['txt_decodes'])),
                'a_decodes': sorted(list(agg_entry['a_decodes'])),
                'a_xor_keys': sorted(list(agg_entry['a_xor_keys'])),
                'method_summary': ' / '.join(method_parts) if method_parts else '-',
            }

        domain_meta = {}
        for d, h in (ctx.history or {}).items():
            if not isinstance(h, dict):
                continue
            meta = h.get('meta', {}) if isinstance(h.get('meta', {}), dict) else {}
            if not meta:
                continue
            domain_meta[d] = {
                'nxdomain_active': bool(meta.get('nxdomain_active', False)),
                'nxdomain_since': int(meta.get('nxdomain_since') or 0) if meta.get('nxdomain_since') else 0,
                'nxdomain_first_seen': int(meta.get('nxdomain_first_seen') or 0) if meta.get('nxdomain_first_seen') else 0,
                'nxdomain_cleared_ts': int(meta.get('nxdomain_cleared_ts') or 0) if meta.get('nxdomain_cleared_ts') else 0,
            }

        payload = {'results_agg': data_agg, 'domain_meta': domain_meta}
        if include_raw:
            payload['results'] = data
        send_json(handler, payload)
    except Exception as e:
        send_json(handler, {'error': str(e)}, 500)


def handle_decoders(ctx: HttpContext, handler) -> None:
    try:
        names = sorted(list(TXT_DECODE_METHODS.keys()))
        a_names = sorted(list(A_DECODE_METHODS.keys()))
        txt_custom = list(ctx.shared_config.get('custom_decoders', []) or [])
        a_custom = list(ctx.shared_config.get('custom_a_decoders', []) or [])
        custom_all = []
        for c in txt_custom:
            item = dict(c) if isinstance(c, dict) else {}
            if item and 'decoder_type' not in item:
                item['decoder_type'] = 'TXT'
            if item:
                custom_all.append(item)
        for c in a_custom:
            item = dict(c) if isinstance(c, dict) else {}
            if item and 'decoder_type' not in item:
                item['decoder_type'] = 'A'
            if item:
                custom_all.append(item)
        send_json(handler, {
            'decoders': names,
            'custom': txt_custom,
            'custom_a': a_custom,
            'custom_all': custom_all,
            'a_decoders': a_names,
        })
    except Exception as e:
        send_json(handler, {'error': str(e)}, 500)
