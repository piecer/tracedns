#!/usr/bin/env python3
"""HTTP API handler attachment utilities.

This module contains the web API handler methods extracted from http_server.py.
"""

import json
import mimetypes
import os
import time
from urllib.parse import parse_qs, urlparse

from a_decoder import A_DECODE_METHODS, decode_a_hidden_ips
from config_manager import normalize_domains, read_config, write_config
from dns_query import query_dns
from txt_decoder import TXT_DECODE_METHODS, analyze_domain_decoding, decode_txt_hidden_ips

# Refactor: move common handlers into smaller modules.
from http_api.context import HttpContext
from http_api.basic_handlers import handle_config as _handle_config_basic
from http_api.basic_handlers import handle_results as _handle_results_basic
from http_api.basic_handlers import handle_decoders as _handle_decoders_basic
from http_api.utils import send_json as _send_json_basic
from http_api.settings_handlers import handle_settings_get as _handle_settings_get_basic
from http_api.settings_handlers import handle_settings_post as _handle_settings_post_basic
from http_api.relationship_handlers import handle_ip_relationship_analysis as _handle_ip_relationship_analysis


try:
    from vt_lookup import (
        get_ip_report,
        begin_cache_batch,
        end_cache_batch,
        set_cache_ttl_days,
        get_cache_ttl_days,
    )
except Exception:
    get_ip_report = None

    def begin_cache_batch():
        return 0

    def end_cache_batch(flush=True):
        return False

    def set_cache_ttl_days(days):
        return None

    def get_cache_ttl_days():
        return 1


ALLOWED_STATIC_FILES = {
    "dns_frontend.html",
    "dns_dashboard.html",
    "settings.html",
    "dns_frontend.css",
    "dns_frontend.js",
    "country_centroids.json",
}


def attach_api_handlers(
    handler_cls,
    *,
    frontend_html,
    shared_config,
    config_lock,
    config_path,
    history_dir,
    current_results,
    history,
    purge_removed_domains_state,
):
    ctx = HttpContext(
        frontend_html=frontend_html,
        shared_config=shared_config,
        config_lock=config_lock,
        config_path=config_path,
        history_dir=history_dir,
        current_results=current_results,
        history=history,
        purge_removed_domains_state=purge_removed_domains_state,
    )

    # Expose shared_config on the handler instance for specialized endpoints
    # (e.g. GeoIP mmdb path used by relationship/similarity analysis).
    try:
        handler_cls.shared_config = shared_config
    except Exception:
        pass

    def _send_json(self, obj, code=200):
        return _send_json_basic(self, obj, code=code)

    # ---- Handlers extracted for readability ----
    def _handle_config(self):
        return _handle_config_basic(ctx, self)

    def _handle_results(self, qs=None):
        return _handle_results_basic(ctx, self, qs or {})

    def _handle_decoders(self):
        return _handle_decoders_basic(ctx, self)

    # (Other handlers remain in this module for now; they will be moved in follow-up refactors.)

    def _handle_settings_get(self):
        return _handle_settings_get_basic(ctx, self)

    def _handle_settings_post(self):
        return _handle_settings_post_basic(ctx, self)
    
    def _gather_ip_map(self):
        ip_map = {}
        # current results
        for d, m in current_results.items():
            for srv, info in m.items():
                for ip in info.get('values', []) if info.get('type') == 'A' else []:
                    ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                    ent['domains'].add(d)
                    ent['count'] += 1
                    ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
                for ip in info.get('decoded_ips', []):
                    ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                    ent['domains'].add(d)
                    ent['count'] += 1
                    ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
    
        # history events
        for d, hist_obj in history.items():
            events = hist_obj.get('events', []) if isinstance(hist_obj, dict) else (hist_obj or [])
            for ev in events:
                ts = ev.get('ts', 0)
                if 'new' in ev or 'old' in ev:
                    for side in ('new', 'old'):
                        side_obj = ev.get(side, {})
                        for ip in side_obj.get('values', []) if ev.get('type', 'A') == 'A' else []:
                            ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                            ent['domains'].add(d)
                            ent['count'] += 1
                            ent['last_ts'] = max(ent['last_ts'], ts)
                        for ip in side_obj.get('decoded_ips', []) if ev.get('type', 'A') in ('TXT', 'A') else []:
                            ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                            ent['domains'].add(d)
                            ent['count'] += 1
                            ent['last_ts'] = max(ent['last_ts'], ts)
                elif 'values' in ev:
                    if ev.get('type', 'A') == 'A':
                        for ip in ev.get('values', []):
                            ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                            ent['domains'].add(d)
                            ent['count'] += 1
                            ent['last_ts'] = max(ent['last_ts'], ts)
                    if ev.get('type', 'A') in ('TXT', 'A'):
                        for ip in ev.get('decoded_ips', []):
                            ent = ip_map.setdefault(ip, {'domains': set(), 'count': 0, 'last_ts': 0})
                            ent['domains'].add(d)
                            ent['count'] += 1
                            ent['last_ts'] = max(ent['last_ts'], ts)
        return ip_map
    
    def _handle_domains(self):
        """Return configured domains with a lightweight resolving status and last-seen info.
    
        Uses `current_results` and `history` to determine whether a domain is currently resolving.
        """
        try:
            domains = []
            # shared_config stores domains as list (name or dict)
            cfg_domains = shared_config.get('domains', []) or []
            seen_map = {}
            lifecycle_map = {}
            # determine last_ts per domain from current_results
            for d, m in current_results.items():
                maxts = 0
                servers = []
                samples = []
                for srv, info in m.items():
                    servers.append(srv)
                    ts = info.get('ts', 0) or 0
                    maxts = max(maxts, ts)
                    if info.get('type') == 'A':
                        samples.extend(info.get('values', []) or [])
                    elif info.get('type') == 'TXT':
                        samples.extend(info.get('decoded_ips', []) or [])
                seen_map[d] = {'last_ts': maxts, 'servers': servers, 'samples': samples}
    
            # also check history meta last_changed/first_seen
            for d, hist_obj in history.items():
                try:
                    meta = hist_obj.get('meta', {}) if isinstance(hist_obj, dict) else {}
                    last_changed = meta.get('last_changed') or meta.get('first_seen') or 0
                    entry = seen_map.setdefault(d, {'last_ts': 0, 'servers': [], 'samples': []})
                    entry['last_ts'] = max(entry.get('last_ts', 0), int(last_changed or 0))
                    lifecycle_map[d] = {
                        'nxdomain_active': bool(meta.get('nxdomain_active', False)),
                        'nxdomain_since': int(meta.get('nxdomain_since') or 0) if meta.get('nxdomain_since') else 0,
                        'nxdomain_first_seen': int(meta.get('nxdomain_first_seen') or 0) if meta.get('nxdomain_first_seen') else 0,
                        'nxdomain_cleared_ts': int(meta.get('nxdomain_cleared_ts') or 0) if meta.get('nxdomain_cleared_ts') else 0,
                    }
                except Exception:
                    continue
    
            for d in cfg_domains:
                name = d.get('name') if isinstance(d, dict) else d
                name = name or ''
                info = seen_map.get(name, {'last_ts': 0, 'servers': [], 'samples': []})
                life = lifecycle_map.get(name, {})
                # resolving if there is a non-empty sample or last_ts present
                resolving = False
                if info.get('samples'):
                    resolving = True
                elif info.get('last_ts', 0) and info.get('last_ts', 0) > 0:
                    resolving = True
                domains.append({
                    'name': name,
                    'type': (d.get('type') if isinstance(d, dict) else 'A'),
                    'resolving': bool(resolving),
                    'last_ts': info.get('last_ts', 0),
                    'servers': info.get('servers', []),
                    'samples': info.get('samples', []),
                    'nxdomain_active': bool(life.get('nxdomain_active', False)),
                    'nxdomain_since': int(life.get('nxdomain_since', 0) or 0),
                })
    
            # also include any domains present in current_results but not in config (likely ephemeral)
            for d, v in seen_map.items():
                if d and not any(x['name'] == d for x in domains):
                    life = lifecycle_map.get(d, {})
                    domains.append({
                        'name': d,
                        'type': 'A',
                        'resolving': bool(v.get('samples') or v.get('last_ts')),
                        'last_ts': v.get('last_ts', 0),
                        'servers': v.get('servers', []),
                        'samples': v.get('samples', []),
                        'nxdomain_active': bool(life.get('nxdomain_active', False)),
                        'nxdomain_since': int(life.get('nxdomain_since', 0) or 0),
                    })
    
            # sort domains by resolving (resolving first) then newest last_ts
            domains.sort(key=lambda x: (not x.get('resolving', False), -(x.get('last_ts') or 0)))
            self._send_json({'domains': domains})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_domain_analysis(self, qs):
        """Return per-domain resolving/decoded IP view with optional AS context."""
        try:
            import ipaddress as _ip
            include_vt = True
            if qs.get('include_vt') is not None:
                try:
                    include_vt = bool(int(qs.get('include_vt', ['1'])[0]))
                except Exception:
                    include_vt = True
    
            cfg_domains = shared_config.get('domains', []) or []
            cfg_type_map = {}
            lifecycle_map = {}
            for d in cfg_domains:
                if isinstance(d, dict):
                    name = str(d.get('name') or '').strip()
                    typ = str(d.get('type') or 'A').upper()
                else:
                    name = str(d or '').strip()
                    typ = 'A'
                if name:
                    cfg_type_map[name] = typ
    
            for d, hist_obj in (history or {}).items():
                try:
                    meta = hist_obj.get('meta', {}) if isinstance(hist_obj, dict) else {}
                    lifecycle_map[d] = {
                        'nxdomain_active': bool(meta.get('nxdomain_active', False)),
                        'nxdomain_since': int(meta.get('nxdomain_since') or 0) if meta.get('nxdomain_since') else 0,
                        'dns_error_only_active': bool(meta.get('dns_error_only_active', False)),
                    }
                except Exception:
                    continue
    
            domain_map = {}
            # seed with configured domains
            for name, typ in cfg_type_map.items():
                life = lifecycle_map.get(name, {})
                domain_map[name] = {
                    'domain': name,
                    'record_types': {typ},
                    'resolved_ips': set(),
                    'decoded_ips': set(),
                    'last_ts': 0,
                    'nxdomain_active': bool(life.get('nxdomain_active', False)),
                    'nxdomain_since': int(life.get('nxdomain_since') or 0),
                    'dns_error_only_active': bool(life.get('dns_error_only_active', False)),
                }
    
            for d, m in current_results.items():
                life = lifecycle_map.get(d, {})
                ent = domain_map.setdefault(d, {
                    'domain': d,
                    'record_types': set(),
                    'resolved_ips': set(),
                    'decoded_ips': set(),
                    'last_ts': 0,
                    'nxdomain_active': bool(life.get('nxdomain_active', False)),
                    'nxdomain_since': int(life.get('nxdomain_since') or 0),
                    'dns_error_only_active': bool(life.get('dns_error_only_active', False)),
                })
                for _srv, info in (m or {}).items():
                    rtype = str(info.get('type') or 'A').upper()
                    ent['record_types'].add(rtype)
                    ts = int(info.get('ts') or 0)
                    ent['last_ts'] = max(ent['last_ts'], ts)
    
                    if rtype == 'A':
                        for ip in (info.get('values') or []):
                            ip_s = str(ip or '').strip()
                            if not ip_s:
                                continue
                            try:
                                _ip.ip_address(ip_s)
                                ent['resolved_ips'].add(ip_s)
                            except Exception:
                                continue
    
                    for ip in (info.get('decoded_ips') or []):
                        ip_s = str(ip or '').strip()
                        if not ip_s:
                            continue
                        try:
                            _ip.ip_address(ip_s)
                            ent['decoded_ips'].add(ip_s)
                        except Exception:
                            continue
    
            vt_cache = {}
    
            def _vt_brief(ip):
                if not include_vt or not get_ip_report:
                    return None
                if ip in vt_cache:
                    return vt_cache[ip]
                rep = None
                try:
                    rep = get_ip_report(ip)
                except Exception:
                    rep = None
                brief = None
                if isinstance(rep, dict):
                    brief = {
                        'asn': rep.get('asn'),
                        'as_owner': rep.get('as_owner'),
                        'country': rep.get('country'),
                        'malicious': int(rep.get('malicious', 0) or 0),
                        'suspicious': int(rep.get('suspicious', 0) or 0),
                    }
                vt_cache[ip] = brief
                return brief
    
            out = []
            vt_batch_started = False
            if include_vt and get_ip_report:
                begin_cache_batch()
                vt_batch_started = True
            try:
                for d in sorted(domain_map.keys()):
                    ent = domain_map[d]
                    resolved_ips = sorted(list(ent['resolved_ips']))
                    decoded_ips = sorted(list(ent['decoded_ips']))
    
                    ip_rows = []
                    for ip in resolved_ips:
                        ip_rows.append({'role': 'resolved', 'ip': ip, 'vt': _vt_brief(ip)})
                    for ip in decoded_ips:
                        ip_rows.append({'role': 'decoded', 'ip': ip, 'vt': _vt_brief(ip)})
    
                    as_counter = {}
                    for row in ip_rows:
                        vt = row.get('vt') or {}
                        asn = vt.get('asn')
                        owner = vt.get('as_owner')
                        country = vt.get('country')
                        if asn is None and not owner and not country:
                            continue
                        key = f"{asn}|{owner}|{country}"
                        e = as_counter.setdefault(key, {'asn': asn, 'as_owner': owner, 'country': country, 'count': 0})
                        e['count'] += 1
                    as_summary = sorted(as_counter.values(), key=lambda x: (-x['count'], str(x.get('asn') or '')))
    
                    out.append({
                        'domain': d,
                        'record_types': sorted(list(ent['record_types'])),
                        'resolved_ips': resolved_ips,
                        'decoded_ips': decoded_ips,
                        'ip_rows': ip_rows,
                        'as_summary': as_summary,
                        'resolving': bool(resolved_ips or decoded_ips),
                        'last_ts': ent.get('last_ts', 0),
                        'nxdomain_active': bool(ent.get('nxdomain_active', False)),
                        'nxdomain_since': int(ent.get('nxdomain_since') or 0),
                        'dns_error_only_active': bool(ent.get('dns_error_only_active', False)),
                    })
            finally:
                if vt_batch_started:
                    end_cache_batch(flush=True)
    
            self._send_json({'domains': out, 'include_vt': include_vt})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_domain_precheck(self):
        """Validate one domain before adding it to config."""
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length > 0 else b''
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except Exception:
            return self._send_json({'error': 'invalid json'}, 400)

        import ipaddress as _ip

        def _is_ipv4(value):
            try:
                addr = _ip.ip_address(str(value or '').strip())
                return bool(addr.version == 4)
            except Exception:
                return False

        domain = str(data.get('domain') or '').strip().rstrip('.')
        if not domain:
            return self._send_json({'error': 'domain required'}, 400)

        requested_type = str(data.get('type') or 'AUTO').strip().upper()
        if requested_type not in ('AUTO', 'A', 'TXT'):
            return self._send_json({'error': 'type must be one of AUTO/A/TXT'}, 400)

        txt_decode = str(data.get('txt_decode') or 'cafebabe_xor_base64').strip() or 'cafebabe_xor_base64'
        a_decode = str(data.get('a_decode') or 'none').strip() or 'none'
        a_xor_key = str(data.get('a_xor_key') or '').strip()
        a_decode_active = a_decode.lower() not in ('', 'none')
        if requested_type in ('AUTO', 'TXT') and txt_decode not in TXT_DECODE_METHODS:
            return self._send_json({'error': f'unknown txt_decode: {txt_decode}'}, 400)
        if requested_type in ('AUTO', 'A') and a_decode_active and a_decode not in A_DECODE_METHODS:
            return self._send_json({'error': f'unknown a_decode: {a_decode}'}, 400)

        include_vt_raw = data.get('include_vt', True)
        if isinstance(include_vt_raw, str):
            include_vt = include_vt_raw.strip().lower() not in ('0', 'false', 'off', 'no', 'n')
        else:
            include_vt = bool(include_vt_raw)

        analyze_decoders = bool(data.get('analyze_decoders', False))
        try:
            decoder_top_n = int(data.get('decoder_top_n', 8))
        except Exception:
            decoder_top_n = 8
        decoder_top_n = max(1, min(50, decoder_top_n))

        try:
            vt_lookup_budget = int(data.get('vt_lookup_budget', 200))
        except Exception:
            vt_lookup_budget = 200
        vt_lookup_budget = max(0, min(5000, vt_lookup_budget))

        try:
            vt_workers = int(data.get('vt_workers', 8))
        except Exception:
            vt_workers = 8
        vt_workers = max(1, min(32, vt_workers))

        req_servers = data.get('servers')
        if isinstance(req_servers, list):
            servers = [str(x).strip() for x in req_servers if str(x).strip()]
        elif isinstance(req_servers, str):
            servers = [s.strip() for s in req_servers.split(',') if s.strip()]
        else:
            with config_lock:
                servers = [str(x).strip() for x in (shared_config.get('servers', []) or []) if str(x).strip()]
        if not servers:
            servers = ['8.8.8.8', '1.1.1.1']

        probe_types = ['TXT', 'A'] if requested_type == 'AUTO' else [requested_type]
        type_scores = {t: 0 for t in probe_types}
        type_value_counts = {t: 0 for t in probe_types}
        type_managed_counts = {t: 0 for t in probe_types}
        type_resolved_ip_sets = {t: set() for t in probe_types}
        type_managed_ip_sets = {t: set() for t in probe_types}
        detected_types = set()
        by_server = []

        for srv in servers:
            for rtype in probe_types:
                qret = query_dns(srv, domain, rtype=rtype, with_meta=True)
                if isinstance(qret, dict):
                    vals = qret.get('values') if isinstance(qret.get('values'), list) else []
                    qstatus = str(qret.get('status') or 'error').lower()
                else:
                    vals = qret if isinstance(qret, list) else []
                    qstatus = 'ok' if isinstance(qret, list) else 'error'
                values = sorted({str(v).strip() for v in vals if str(v).strip()})
                managed_ips = []
                method = '-'

                if rtype == 'TXT':
                    method = f"TXT:{txt_decode}"
                    try:
                        managed_ips = decode_txt_hidden_ips(values, method=txt_decode, domain=domain) or []
                    except Exception:
                        managed_ips = []
                elif rtype == 'A':
                    if a_decode_active:
                        method = f"A:{a_decode}" + (f" ({a_xor_key})" if a_xor_key else '')
                        try:
                            managed_ips = decode_a_hidden_ips(values, method=a_decode, key_hex=a_xor_key, domain=domain) or []
                        except Exception:
                            managed_ips = []
                    else:
                        method = "A:none"
                        managed_ips = list(values)

                managed_ips = sorted({str(v).strip() for v in managed_ips if _is_ipv4(v)})

                score = 0
                if qstatus == 'ok':
                    score += 3 if values else 1
                elif qstatus == 'nxdomain':
                    score -= 2
                elif qstatus == 'error':
                    score -= 1
                if managed_ips:
                    score += 2
                type_scores[rtype] = type_scores.get(rtype, 0) + score
                type_value_counts[rtype] = type_value_counts.get(rtype, 0) + len(values)
                type_managed_counts[rtype] = type_managed_counts.get(rtype, 0) + len(managed_ips)

                if qstatus == 'ok' and values:
                    detected_types.add(rtype)
                if rtype == 'A':
                    for ip in values:
                        if _is_ipv4(ip):
                            type_resolved_ip_sets[rtype].add(ip)
                for ip in managed_ips:
                    type_managed_ip_sets[rtype].add(ip)

                by_server.append({
                    'server': srv,
                    'type': rtype,
                    'status': qstatus,
                    'values': values,
                    'managed_ips': managed_ips,
                    'method': method,
                })

        if requested_type == 'AUTO':
            ranked_types = sorted(
                probe_types,
                key=lambda t: (
                    int(type_scores.get(t, 0)),
                    int(type_managed_counts.get(t, 0)),
                    int(type_value_counts.get(t, 0)),
                    1 if t == 'A' else 0
                ),
                reverse=True
            )
            selected_type = ranked_types[0] if ranked_types else 'A'
        else:
            selected_type = requested_type

        resolved_ips = sorted(type_resolved_ip_sets.get(selected_type, set()))
        managed_ips = sorted(type_managed_ip_sets.get(selected_type, set()))

        role_map = {}
        for ip in resolved_ips:
            role_map.setdefault(ip, set()).add('resolved')
        for ip in managed_ips:
            role_map.setdefault(ip, set()).add('managed')

        vt_enabled = bool(include_vt and get_ip_report)
        vt_unavailable_reason = None
        if include_vt and not get_ip_report:
            vt_unavailable_reason = 'vt_lookup_not_available'

        ip_rows = []
        vt_batch_started = False
        if vt_enabled:
            begin_cache_batch()
            vt_batch_started = True
        try:
            for ip in sorted(role_map.keys()):
                vt = None
                if vt_enabled:
                    try:
                        rep = get_ip_report(ip)
                    except Exception:
                        rep = None
                    if isinstance(rep, dict):
                        vt = {
                            'asn': rep.get('asn'),
                            'as_owner': rep.get('as_owner'),
                            'country': rep.get('country'),
                            'malicious': int(rep.get('malicious', 0) or 0),
                            'suspicious': int(rep.get('suspicious', 0) or 0),
                        }
                ip_rows.append({
                    'ip': ip,
                    'role': '+'.join(sorted(list(role_map.get(ip) or []))),
                    'vt': vt,
                })
        finally:
            if vt_batch_started:
                end_cache_batch(flush=True)

        domain_obj = {'name': domain, 'type': selected_type}
        if selected_type == 'TXT':
            if txt_decode:
                domain_obj['txt_decode'] = txt_decode
        elif selected_type == 'A':
            if a_decode_active:
                domain_obj['a_decode'] = a_decode
            if a_xor_key:
                if 'a_decode' not in domain_obj:
                    domain_obj['a_decode'] = 'xor32_ipv4'
                domain_obj['a_xor_key'] = a_xor_key

        notes = []
        if requested_type == 'AUTO':
            notes.append(f"Auto-selected type: {selected_type}")
        if selected_type == 'A' and a_decode_active:
            notes.append("A decode enabled: managed IPs are transformed IPs only.")
        if selected_type == 'TXT' and not managed_ips:
            notes.append("TXT values were found but decoder did not produce IPv4 outputs.")
        if not managed_ips and not resolved_ips:
            notes.append("No IPv4 candidate found from current DNS responses.")
        if vt_unavailable_reason:
            notes.append("VT lookup module is unavailable in this runtime.")

        can_add = bool(managed_ips or resolved_ips or detected_types)

        # Optional: analyze all decoder methods (TXT/A) and surface candidates.
        decoder_candidates = []
        try:
            if analyze_decoders:
                # TXT decoder analysis (use existing analyzer on a combined sample)
                try:
                    sample_txt = ''
                    for item in by_server:
                        if str(item.get('type') or '').upper() == 'TXT':
                            vals = item.get('values') or []
                            if isinstance(vals, list) and vals:
                                sample_txt += ('|' if sample_txt else '') + '|'.join([str(v) for v in vals[:20]])
                    if sample_txt:
                        analysis = analyze_domain_decoding(domain, sample_txt) or {}
                        items = analysis.get('analysis') if isinstance(analysis, dict) else None
                        if isinstance(items, dict):
                            ranked = sorted(items.items(), key=lambda kv: (-(kv[1] or {}).get('score', 0), kv[0]))
                            ranked = ranked[:decoder_top_n]

                            # 1) Deduplicated VT lookups across candidates (budget shared)
                            candidate_ips = {}
                            all_ips = []
                            for name, info in ranked:
                                ips = [ip for ip in (info.get('ips') or []) if _is_ipv4(ip)]
                                ips = ips[:200]
                                candidate_ips[name] = ips
                                all_ips.extend(ips)

                            # stable de-dup order
                            seen_ip = set()
                            uniq_ips = []
                            for ip in all_ips:
                                if ip in seen_ip:
                                    continue
                                seen_ip.add(ip)
                                uniq_ips.append(ip)

                            vt_reports = {}
                            vt_attempted = 0
                            if vt_enabled and vt_lookup_budget > 0 and uniq_ips:
                                lookup_ips = uniq_ips[:vt_lookup_budget]
                                vt_attempted = len(lookup_ips)
                                try:
                                    # best effort parallelization (IO-bound)
                                    if vt_workers <= 1 or len(lookup_ips) <= 1:
                                        for ip in lookup_ips:
                                            try:
                                                vt_reports[ip] = get_ip_report(ip)
                                            except Exception:
                                                vt_reports[ip] = None
                                    else:
                                        import concurrent.futures as _cf

                                        def _lookup(ip_str):
                                            try:
                                                return get_ip_report(ip_str)
                                            except Exception:
                                                return None

                                        with _cf.ThreadPoolExecutor(max_workers=vt_workers) as ex:
                                            futs = {ex.submit(_lookup, ip): ip for ip in lookup_ips}
                                            for fut in _cf.as_completed(futs):
                                                ip = futs[fut]
                                                vt_reports[ip] = fut.result()
                                except Exception:
                                    pass

                            # 2) Per-decoder anomaly signals/score
                            def _topn(freq, n=3):
                                return sorted(freq.items(), key=lambda x: (-x[1], x[0]))[:n]

                            def _calc_anomaly(vt_rows, total_ip_count):
                                """Return (score:int, signals:dict)"""
                                if total_ip_count <= 0:
                                    return (0, {'reason': 'no_ips'})
                                mal_ips = 0
                                sus_ips = 0
                                mal_total = 0
                                sus_total = 0
                                asn_freq = {}
                                ctry_freq = {}
                                for rep in vt_rows:
                                    if not isinstance(rep, dict):
                                        continue
                                    m = int(rep.get('malicious', 0) or 0)
                                    s = int(rep.get('suspicious', 0) or 0)
                                    mal_total += m
                                    sus_total += s
                                    if m > 0:
                                        mal_ips += 1
                                    if s > 0:
                                        sus_ips += 1
                                    asn = rep.get('asn')
                                    ctry = rep.get('country')
                                    if asn is not None and str(asn).strip():
                                        k = str(asn).strip(); asn_freq[k] = asn_freq.get(k, 0) + 1
                                    if ctry is not None and str(ctry).strip():
                                        k = str(ctry).strip(); ctry_freq[k] = ctry_freq.get(k, 0) + 1

                                # ratios use total_ip_count (not vt_rows count) to penalize low coverage
                                mal_ratio = mal_ips / max(1, total_ip_count)
                                sus_ratio = sus_ips / max(1, total_ip_count)
                                top_asn = _topn(asn_freq, 3)
                                top_country = _topn(ctry_freq, 3)
                                top_asn_share = (top_asn[0][1] / max(1, sum(asn_freq.values()))) if top_asn else 0
                                top_ctry_share = (top_country[0][1] / max(1, sum(ctry_freq.values()))) if top_country else 0

                                # Simple composite score (interpretable, not ML):
                                score = 0
                                score += int(100 * mal_ratio) * 2
                                score += int(100 * sus_ratio)
                                score += int(mal_total) * 5
                                score += int(sus_total) * 2
                                score += int(10 * top_asn_share)
                                score += int(8 * top_ctry_share)

                                signals = {
                                    'malicious_ratio': round(mal_ratio, 3),
                                    'suspicious_ratio': round(sus_ratio, 3),
                                    'malicious_total': mal_total,
                                    'suspicious_total': sus_total,
                                    'unique_asn': len(asn_freq),
                                    'unique_country': len(ctry_freq),
                                    'top_asn': top_asn,
                                    'top_country': top_country,
                                }
                                return (int(score), signals)

                            for name, info in ranked:
                                ips = candidate_ips.get(name, [])
                                vt_rows = []
                                if vt_enabled and vt_reports:
                                    for ip in ips:
                                        rep = vt_reports.get(ip)
                                        if isinstance(rep, dict):
                                            # Normalize keys used elsewhere
                                            vt_rows.append({
                                                'asn': rep.get('asn'),
                                                'country': rep.get('country'),
                                                'malicious': int(rep.get('malicious', 0) or 0),
                                                'suspicious': int(rep.get('suspicious', 0) or 0),
                                            })
                                anomaly_score, signals = _calc_anomaly(vt_rows, len(ips))
                                vt_summary = None
                                if vt_enabled:
                                    vt_summary = {
                                        'malicious_total': signals.get('malicious_total', 0),
                                        'suspicious_total': signals.get('suspicious_total', 0),
                                        'top_asn': signals.get('top_asn', []),
                                        'top_country': signals.get('top_country', []),
                                        'malicious_ratio': signals.get('malicious_ratio', 0),
                                        'suspicious_ratio': signals.get('suspicious_ratio', 0),
                                        'unique_asn': signals.get('unique_asn', 0),
                                        'unique_country': signals.get('unique_country', 0),
                                        'vt_attempted_total': vt_attempted,
                                    }

                                decoder_candidates.append({
                                    'decoder_type': 'TXT',
                                    'name': name,
                                    'score': (info or {}).get('score', 0),
                                    'ip_count': len(ips),
                                    'sample_ips': ips[:8],
                                    'vt_summary': vt_summary,
                                    'anomaly_score': anomaly_score,
                                })
                except Exception:
                    pass

                # A decoder quick sweep (only decoders that don't require extra params besides provided key)
                try:
                    if selected_type in ('AUTO', 'A') or requested_type in ('AUTO', 'A'):
                        resolved_set = set(type_resolved_ip_sets.get('A', set()))
                        resolved_list = sorted([ip for ip in resolved_set if _is_ipv4(ip)])
                        if resolved_list:
                            a_names = sorted(list(A_DECODE_METHODS.keys()))
                            # keep it small
                            a_names = [n for n in a_names if n in ('none', 'xor32_ipv4')] + [n for n in a_names if n not in ('none', 'xor32_ipv4')]
                            a_names = a_names[:min(10, len(a_names))]
                            for name in a_names:
                                if name == 'none':
                                    ips = resolved_list
                                else:
                                    try:
                                        ips = decode_a_hidden_ips(resolved_list, method=name, key_hex=a_xor_key, domain=domain) or []
                                    except Exception:
                                        ips = []
                                ips = sorted({ip for ip in ips if _is_ipv4(ip)})
                                decoder_candidates.append({
                                    'decoder_type': 'A',
                                    'name': name,
                                    'score': len(ips),
                                    'ip_count': len(ips),
                                    'sample_ips': ips[:8],
                                    'vt_summary': None,
                                })
                except Exception:
                    pass

                # Sort candidates: prefer anomaly_score (if present), then decoder score/ip_count.
                decoder_candidates.sort(key=lambda x: (
                    -int(x.get('anomaly_score') or 0),
                    -int(x.get('score') or 0),
                    -int(x.get('ip_count') or 0),
                    str(x.get('decoder_type') or ''),
                    str(x.get('name') or ''),
                ))
                decoder_candidates = decoder_candidates[:max(1, decoder_top_n * 2)]
        except Exception:
            decoder_candidates = []

        return self._send_json({
            'status': 'ok',
            'domain': domain,
            'requested_type': requested_type,
            'selected_type': selected_type,
            'detected_types': sorted(list(detected_types)),
            'servers': servers,
            'include_vt': include_vt,
            'decoder_candidates': decoder_candidates,
            'vt_enabled': vt_enabled,
            'vt_unavailable_reason': vt_unavailable_reason,
            'resolved_ips': resolved_ips,
            'managed_ips': managed_ips,
            'by_server': by_server,
            'ip_rows': ip_rows,
            'domain_object': domain_obj,
            'notes': notes,
            'can_add': can_add,
        })
    
    def _handle_ip_list_analysis(self):
        """Analyze an arbitrary IP list (VT/AS/Country summaries + heuristics)."""
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length > 0 else b''
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except Exception:
            return self._send_json({'error': 'invalid json'}, 400)
    
        raw_ips = data.get('ips')
        include_vt_raw = data.get('include_vt', True)
        if isinstance(include_vt_raw, str):
            include_vt = include_vt_raw.strip().lower() not in ('0', 'false', 'off', 'no', 'n')
        else:
            include_vt = bool(include_vt_raw)
    
        raw_row_limit = data.get('row_limit', 1500)
        try:
            row_limit = int(raw_row_limit)
        except Exception:
            row_limit = 1500
        if row_limit < 100:
            row_limit = 100
        if row_limit > 5000:
            row_limit = 5000
    
        raw_vt_budget = data.get('vt_lookup_budget', 1200)
        try:
            vt_lookup_budget = int(raw_vt_budget)
        except Exception:
            vt_lookup_budget = 1200
        if vt_lookup_budget < 0:
            vt_lookup_budget = 0
        if vt_lookup_budget > 5000:
            vt_lookup_budget = 5000

        raw_vt_workers = data.get('vt_workers', 8)
        try:
            vt_workers = int(raw_vt_workers)
        except Exception:
            vt_workers = 8
        if vt_workers < 1:
            vt_workers = 1
        if vt_workers > 32:
            vt_workers = 32
    
        import re as _re
        import ipaddress as _ip
    
        max_input_tokens = 20000
        max_valid_ips = 10000
        as_summary_limit = 800
        country_summary_limit = 400
        as_country_summary_limit = 800
    
        def _classify_csp(as_owner):
            owner_txt = str(as_owner or '').strip()
            ltxt = owner_txt.lower()
            if not ltxt:
                return {'csp': 'other', 'csp_label': 'Other/Unknown', 'csp_major': False}
    
            csp_rules = [
                ('amazon', 'Amazon AWS', True, ('amazon', 'amazon.com', 'aws')),
                ('google', 'Google Cloud', True, ('google', 'gcp', 'google cloud')),
                ('microsoft', 'Microsoft Azure', True, ('microsoft', 'azure')),
                ('cloudflare', 'Cloudflare', True, ('cloudflare',)),
                ('oracle', 'Oracle Cloud', True, ('oracle', 'oci')),
                ('alibaba', 'Alibaba Cloud', True, ('alibaba', 'aliyun')),
                ('tencent', 'Tencent Cloud', True, ('tencent',)),
                ('akamai', 'Akamai/Linode', False, ('akamai', 'linode')),
                ('digitalocean', 'DigitalOcean', False, ('digitalocean',)),
                ('ovh', 'OVHcloud', False, ('ovh', 'ovhcloud')),
            ]
            for csp_id, label, major, needles in csp_rules:
                if any(n in ltxt for n in needles):
                    return {'csp': csp_id, 'csp_label': label, 'csp_major': bool(major)}
            return {'csp': 'other', 'csp_label': 'Other/Unknown', 'csp_major': False}
    
        tokens = []
        if isinstance(raw_ips, str):
            tokens = [x.strip() for x in _re.split(r'[\s,;|]+', raw_ips) if x and x.strip()]
        elif isinstance(raw_ips, list):
            for item in raw_ips:
                if item is None:
                    continue
                s = str(item).strip()
                if not s:
                    continue
                parts = [x.strip() for x in _re.split(r'[\s,;|]+', s) if x and x.strip()]
                tokens.extend(parts)
        else:
            return self._send_json({'error': 'ips must be a string or list'}, 400)
    
        submitted_count = len(tokens)
        if submitted_count == 0:
            return self._send_json({'error': 'no ip inputs'}, 400)
        if submitted_count > max_input_tokens:
            return self._send_json({'error': f'too many inputs (max {max_input_tokens} tokens)'}, 400)
    
        # de-duplicate while preserving input order
        unique_tokens = []
        seen_tokens = set()
        for t in tokens:
            if t not in seen_tokens:
                seen_tokens.add(t)
                unique_tokens.append(t)
    
        valid_ips = []
        invalid_inputs = []
        seen_valid = set()
        for tok in unique_tokens:
            try:
                ip_s = str(_ip.ip_address(tok))
                if ip_s not in seen_valid:
                    seen_valid.add(ip_s)
                    valid_ips.append(ip_s)
            except Exception:
                invalid_inputs.append(tok)
    
        if len(valid_ips) > max_valid_ips:
            return self._send_json({'error': f'too many valid IPs (max {max_valid_ips})'}, 400)
    
        vt_enabled = bool(include_vt and get_ip_report)
        vt_unavailable_reason = None
        if include_vt and not get_ip_report:
            vt_unavailable_reason = 'vt_lookup_not_available'
    
        rows = []
        as_map = {}
        country_map = {}
        as_country_map = {}
        csp_map = {}
        vt_missing_count = 0
        vt_lookup_attempted = 0
        vt_budget_limited = False

        vt_batch_started = False
        if vt_enabled:
            begin_cache_batch()
            vt_batch_started = True
        try:
            vt_reports = {}
            if vt_enabled:
                vt_lookup_ips = []
                vt_cache_only_ips = []
                for idx, ip in enumerate(valid_ips):
                    if idx >= vt_lookup_budget:
                        vt_budget_limited = True
                        vt_cache_only_ips.append(ip)
                    else:
                        vt_lookup_ips.append(ip)
                vt_lookup_attempted = len(vt_lookup_ips)

                # Use cache-only path for budget-exceeded tail first.
                for ip in vt_cache_only_ips:
                    try:
                        try:
                            vt_reports[ip] = get_ip_report(ip, cache_only=True)
                        except TypeError:
                            # Backward compatibility with older vt_lookup signature.
                            vt_reports[ip] = None
                    except Exception:
                        vt_reports[ip] = None

                # Parallelize live VT lookups (IO-bound) for faster large-list analysis.
                if vt_lookup_ips:
                    if vt_workers <= 1 or len(vt_lookup_ips) <= 1:
                        for ip in vt_lookup_ips:
                            try:
                                vt_reports[ip] = get_ip_report(ip)
                            except Exception:
                                vt_reports[ip] = None
                    else:
                        try:
                            import concurrent.futures as _cf
                            with _cf.ThreadPoolExecutor(max_workers=vt_workers) as executor:
                                future_map = {executor.submit(get_ip_report, ip): ip for ip in vt_lookup_ips}
                                for fut in _cf.as_completed(future_map):
                                    ip = future_map.get(fut)
                                    if not ip:
                                        continue
                                    try:
                                        vt_reports[ip] = fut.result()
                                    except Exception:
                                        vt_reports[ip] = None
                        except Exception:
                            # Fallback to sequential mode if thread-pool path fails.
                            for ip in vt_lookup_ips:
                                if ip in vt_reports:
                                    continue
                                try:
                                    vt_reports[ip] = get_ip_report(ip)
                                except Exception:
                                    vt_reports[ip] = None

            for ip in valid_ips:
                rep = vt_reports.get(ip) if vt_enabled else None
                if vt_enabled and not isinstance(rep, dict):
                    vt_missing_count += 1
    
                asn = rep.get('asn') if isinstance(rep, dict) else None
                as_owner = rep.get('as_owner') if isinstance(rep, dict) else None
                country = rep.get('country') if isinstance(rep, dict) else None
                malicious = int(rep.get('malicious', 0) or 0) if isinstance(rep, dict) else 0
                suspicious = int(rep.get('suspicious', 0) or 0) if isinstance(rep, dict) else 0
                csp_info = _classify_csp(as_owner)
    
                row = {
                    'ip': ip,
                    'asn': str(asn) if asn is not None else '-',
                    'as_owner': str(as_owner) if as_owner else '-',
                    'csp': csp_info.get('csp', 'other'),
                    'csp_label': csp_info.get('csp_label', 'Other/Unknown'),
                    'csp_major': bool(csp_info.get('csp_major', False)),
                    'country': str(country) if country else '-',
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'vt': {
                        'asn': asn,
                        'as_owner': as_owner,
                        'country': country,
                        'malicious': malicious,
                        'suspicious': suspicious,
                    } if isinstance(rep, dict) else None
                }
                rows.append(row)
    
                # Summaries are based on entries with at least one VT context field.
                if not isinstance(rep, dict):
                    continue
                asn_key = str(asn) if asn is not None else 'N/A'
                owner_key = str(as_owner) if as_owner else '-'
                country_key = str(country) if country else 'N/A'
    
                as_k = f"{asn_key}|{owner_key}"
                as_ent = as_map.setdefault(as_k, {
                    'asn': asn_key,
                    'as_owner': owner_key,
                    'csp': csp_info.get('csp', 'other'),
                    'csp_label': csp_info.get('csp_label', 'Other/Unknown'),
                    'csp_major': bool(csp_info.get('csp_major', False)),
                    'ip_count': 0,
                    'malicious_ips': 0,
                    'suspicious_ips': 0,
                    'countries': set()
                })
                as_ent['ip_count'] += 1
                if malicious > 0:
                    as_ent['malicious_ips'] += 1
                if suspicious > 0:
                    as_ent['suspicious_ips'] += 1
                as_ent['countries'].add(country_key)
    
                c_ent = country_map.setdefault(country_key, {
                    'country': country_key,
                    'ip_count': 0,
                    'malicious_ips': 0,
                    'suspicious_ips': 0,
                    'asns': set()
                })
                c_ent['ip_count'] += 1
                if malicious > 0:
                    c_ent['malicious_ips'] += 1
                if suspicious > 0:
                    c_ent['suspicious_ips'] += 1
                c_ent['asns'].add(asn_key)
    
                ac_k = f"{asn_key}|{country_key}|{owner_key}"
                ac_ent = as_country_map.setdefault(ac_k, {
                    'asn': asn_key,
                    'country': country_key,
                    'as_owner': owner_key,
                    'csp': csp_info.get('csp', 'other'),
                    'csp_label': csp_info.get('csp_label', 'Other/Unknown'),
                    'csp_major': bool(csp_info.get('csp_major', False)),
                    'ip_count': 0,
                    'malicious_ips': 0,
                    'suspicious_ips': 0
                })
                ac_ent['ip_count'] += 1
                if malicious > 0:
                    ac_ent['malicious_ips'] += 1
                if suspicious > 0:
                    ac_ent['suspicious_ips'] += 1
    
                csp_k = csp_info.get('csp', 'other')
                csp_ent = csp_map.setdefault(csp_k, {
                    'csp': csp_k,
                    'csp_label': csp_info.get('csp_label', 'Other/Unknown'),
                    'csp_major': bool(csp_info.get('csp_major', False)),
                    'ip_count': 0,
                    'malicious_ips': 0,
                    'suspicious_ips': 0,
                    'asns': set(),
                    'countries': set()
                })
                csp_ent['ip_count'] += 1
                if malicious > 0:
                    csp_ent['malicious_ips'] += 1
                if suspicious > 0:
                    csp_ent['suspicious_ips'] += 1
                csp_ent['asns'].add(asn_key)
                csp_ent['countries'].add(country_key)
        finally:
            if vt_batch_started:
                end_cache_batch(flush=True)
    
        as_summary = []
        for v in as_map.values():
            as_summary.append({
                'asn': v['asn'],
                'as_owner': v['as_owner'],
                'csp': v.get('csp', 'other'),
                'csp_label': v.get('csp_label', 'Other/Unknown'),
                'csp_major': bool(v.get('csp_major', False)),
                'ip_count': v['ip_count'],
                'malicious_ips': v['malicious_ips'],
                'suspicious_ips': v['suspicious_ips'],
                'countries': sorted(list(v['countries']))
            })
        as_summary.sort(key=lambda x: (-x['ip_count'], -x['malicious_ips'], x['asn']))
    
        country_summary = []
        for v in country_map.values():
            country_summary.append({
                'country': v['country'],
                'ip_count': v['ip_count'],
                'malicious_ips': v['malicious_ips'],
                'suspicious_ips': v['suspicious_ips'],
                'asn_count': len(v['asns'])
            })
        country_summary.sort(key=lambda x: (-x['ip_count'], -x['malicious_ips'], x['country']))
    
        as_country_summary = list(as_country_map.values())
        as_country_summary.sort(key=lambda x: (-x['ip_count'], -x['malicious_ips'], x['asn'], x['country']))
    
        csp_summary = []
        for v in csp_map.values():
            csp_summary.append({
                'csp': v['csp'],
                'csp_label': v['csp_label'],
                'csp_major': bool(v['csp_major']),
                'ip_count': v['ip_count'],
                'malicious_ips': v['malicious_ips'],
                'suspicious_ips': v['suspicious_ips'],
                'asn_count': len(v['asns']),
                'country_count': len(v['countries'])
            })
        csp_summary.sort(key=lambda x: (-x['ip_count'], -x['malicious_ips'], (0 if x.get('csp_major') else 1), x['csp_label']))
    
        hints = []
    
        def _add_hint(level, title, detail):
            hints.append({'level': level, 'title': title, 'detail': detail})
    
        valid_count = len(valid_ips)
        if valid_count == 0:
            _add_hint('high', 'No Valid IP', 'All submitted values are invalid IP format.')
        else:
            if not include_vt:
                _add_hint('info', 'VT Disabled', 'AS/Country enrichment is disabled by request.')
            elif vt_unavailable_reason:
                _add_hint('warn', 'VT Unavailable', 'VT lookup module is not available in this runtime.')
            elif vt_missing_count == valid_count:
                _add_hint('warn', 'No VT Coverage', 'No VT context was returned for submitted valid IPs.')
    
            known_rows = [r for r in rows if r.get('asn') not in ('-', 'N/A') or r.get('country') not in ('-', 'N/A')]
            known_n = len(known_rows)
            if known_n > 0:
                as_counter = {}
                country_counter = {}
                mal_n = 0
                susp_n = 0
                for r in known_rows:
                    asn = r.get('asn')
                    country = r.get('country')
                    if asn and asn not in ('-', 'N/A'):
                        as_counter[asn] = as_counter.get(asn, 0) + 1
                    if country and country not in ('-', 'N/A'):
                        country_counter[country] = country_counter.get(country, 0) + 1
                    if int(r.get('malicious', 0) or 0) > 0:
                        mal_n += 1
                    if int(r.get('suspicious', 0) or 0) > 0:
                        susp_n += 1
    
                if as_counter:
                    top_asn, top_as_count = max(as_counter.items(), key=lambda kv: kv[1])
                    top_as_ratio = top_as_count / max(1, known_n)
                    if top_as_ratio >= 0.60:
                        _add_hint('high', 'AS Concentration', f'Top ASN {top_asn} accounts for {top_as_ratio:.0%} of enriched IPs.')
                    elif top_as_ratio <= 0.25 and len(as_counter) >= 4:
                        _add_hint('mid', 'AS Distribution', f'IPs are distributed across many ASNs ({len(as_counter)}).')
    
                if country_counter:
                    top_country, top_country_count = max(country_counter.items(), key=lambda kv: kv[1])
                    top_country_ratio = top_country_count / max(1, known_n)
                    if top_country_ratio >= 0.60:
                        _add_hint('mid', 'Country Concentration', f'Top country {top_country} accounts for {top_country_ratio:.0%} of enriched IPs.')
                    if len(country_counter) >= 5 and (len(country_counter) / max(1, known_n)) >= 0.35:
                        _add_hint('mid', 'Multi-country Spread', f'IPs span many countries ({len(country_counter)}).')
    
                mal_ratio = mal_n / max(1, known_n)
                if mal_ratio >= 0.30:
                    _add_hint('high', 'High Malicious Ratio', f'{mal_ratio:.0%} of enriched IPs have malicious detections.')
                elif mal_n > 0:
                    _add_hint('mid', 'Malicious Presence', f'{mal_n}/{known_n} enriched IPs have malicious detections.')
                elif susp_n > 0:
                    _add_hint('mid', 'Suspicious Presence', f'{susp_n}/{known_n} enriched IPs have suspicious detections.')
    
                as_diversity = len(as_counter) / max(1, known_n) if known_n else 0
                if as_diversity >= 0.70:
                    _add_hint('mid', 'High AS Diversity', f'AS diversity ratio is {as_diversity:.0%}, suggesting distributed infrastructure.')
    
                major_csp_entries = [x for x in csp_summary if x.get('csp_major')]
                if major_csp_entries:
                    major_total = sum(int(x.get('ip_count', 0) or 0) for x in major_csp_entries)
                    major_ratio = major_total / max(1, known_n)
                    if major_ratio >= 0.40:
                        _add_hint('warn', 'Major CSP Footprint', f'{major_total}/{known_n} enriched IPs are on major CSP infrastructure. Scope blocking carefully.')
                    else:
                        _add_hint('info', 'CSP Footprint', f'{major_total}/{known_n} enriched IPs map to major CSP providers.')
            else:
                if include_vt and not vt_unavailable_reason:
                    _add_hint('warn', 'Limited Context', 'No ASN/Country fields available to profile infrastructure.')
    
        if vt_enabled and vt_budget_limited:
            _add_hint('warn', 'VT Lookup Budget Applied', f'Live VT lookups were limited to {vt_lookup_budget}; remaining IPs were processed in cache-only mode.')
    
        rows_total = len(rows)
        shown_rows = rows[:row_limit]
        rows_truncated = rows_total > len(shown_rows)
        if rows_truncated:
            _add_hint('info', 'UI Row Limit Applied', f'Per-IP details are limited to {len(shown_rows)} rows for UI performance.')
    
        as_summary_total = len(as_summary)
        country_summary_total = len(country_summary)
        as_country_summary_total = len(as_country_summary)
    
        shown_as_summary = as_summary[:as_summary_limit]
        shown_country_summary = country_summary[:country_summary_limit]
        shown_as_country_summary = as_country_summary[:as_country_summary_limit]
    
        if as_summary_total > len(shown_as_summary):
            _add_hint('info', 'AS Summary Limited', f'AS summary output is limited to top {len(shown_as_summary)} rows.')
        if country_summary_total > len(shown_country_summary):
            _add_hint('info', 'Country Summary Limited', f'Country summary output is limited to top {len(shown_country_summary)} rows.')
        if as_country_summary_total > len(shown_as_country_summary):
            _add_hint('info', 'AS×Country Summary Limited', f'AS×Country summary output is limited to top {len(shown_as_country_summary)} rows.')
    
        return self._send_json({
            'submitted_count': submitted_count,
            'unique_input_count': len(unique_tokens),
            'valid_count': len(valid_ips),
            'invalid_count': len(invalid_inputs),
            'invalid_inputs': invalid_inputs[:200],
            'include_vt': include_vt,
            'vt_enabled': vt_enabled,
            'vt_missing_count': vt_missing_count,
            'vt_lookup_budget': vt_lookup_budget,
            'vt_lookup_attempted': vt_lookup_attempted,
            'vt_workers': vt_workers,
            'ips_total_count': rows_total,
            'ips_displayed_count': len(shown_rows),
            'ips_truncated': rows_truncated,
            'row_limit': row_limit,
            'as_summary_total': as_summary_total,
            'as_summary_displayed_count': len(shown_as_summary),
            'as_summary_truncated': as_summary_total > len(shown_as_summary),
            'country_summary_total': country_summary_total,
            'country_summary_displayed_count': len(shown_country_summary),
            'country_summary_truncated': country_summary_total > len(shown_country_summary),
            'as_country_summary_total': as_country_summary_total,
            'as_country_summary_displayed_count': len(shown_as_country_summary),
            'as_country_summary_truncated': as_country_summary_total > len(shown_as_country_summary),
            'ips': shown_rows,
            'as_summary': shown_as_summary,
            'country_summary': shown_country_summary,
            'as_country_summary': shown_as_country_summary,
            'csp_summary': csp_summary,
            'hints': hints
        })
    
    def _handle_misp_event_ips(self):
        """Load ip-src attributes from a MISP event."""
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length > 0 else b''
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except Exception:
            return self._send_json({'error': 'invalid json'}, 400)
    
        event_id = data.get('event_id')
        if event_id in (None, ''):
            with config_lock:
                alerts_cfg = shared_config.get('alerts', {}) if isinstance(shared_config, dict) else {}
            if isinstance(alerts_cfg, dict):
                event_id = alerts_cfg.get('push_event_id')
    
        if event_id in (None, ''):
            return self._send_json({'error': 'event_id required (or configure alerts.push_event_id)'}, 400)
    
        try:
            event_id_int = int(str(event_id).strip())
        except Exception:
            return self._send_json({'error': 'invalid event_id'}, 400)
    
        # Prefer already-initialized MISP client from alerts runtime.
        misp_client = None
        misp_mod = None
        try:
            import mispupdate_code as _misp_mod
            misp_mod = _misp_mod
            misp_client = getattr(_misp_mod, 'misp', None)
        except Exception:
            misp_mod = None
    
        if misp_client is None:
            # Try runtime re-init from current alerts config.
            try:
                from alerts import init_from_alerts as _alerts_init_from_dict
                with config_lock:
                    alerts_cfg = shared_config.get('alerts', {}) if isinstance(shared_config, dict) else {}
                if isinstance(alerts_cfg, dict) and alerts_cfg:
                    _alerts_init_from_dict(alerts_cfg)
                    if misp_mod is None:
                        import mispupdate_code as _misp_mod2
                        misp_mod = _misp_mod2
                    misp_client = getattr(misp_mod, 'misp', None) if misp_mod else None
            except Exception:
                misp_client = None
    
        if misp_client is None:
            return self._send_json({'error': 'misp client not initialized; check MISP URL/API key settings'}, 400)
    
        try:
            evt = misp_client.get_event(event_id_int)
        except Exception as e:
            return self._send_json({'error': f'failed to fetch event: {e}'}, 500)
    
        event_obj = evt.get('Event', {}) if isinstance(evt, dict) else {}
        attrs = event_obj.get('Attribute', []) if isinstance(event_obj, dict) else []
        if not isinstance(attrs, list):
            attrs = []
    
        import ipaddress as _ip
        ips = []
        invalid_values = []
        seen = set()
        for a in attrs:
            if not isinstance(a, dict):
                continue
            if str(a.get('type', '')).lower() != 'ip-src':
                continue
            v = str(a.get('value', '')).strip()
            if not v:
                continue
            try:
                _ip.ip_address(v)
            except Exception:
                invalid_values.append(v)
                continue
            if v not in seen:
                seen.add(v)
                ips.append(v)
    
        return self._send_json({
            'status': 'ok',
            'event_id': event_id_int,
            'event_info': event_obj.get('info') if isinstance(event_obj, dict) else None,
            'attribute_count': len(attrs),
            'count': len(ips),
            'ips': ips,
            'invalid_values': invalid_values[:200]
        })
    
    def _handle_ips(self, qs):
        """Return IP list aggregated from current+history.

        Performance notes:
        - Supports pagination so VT lookups only run on the visible page.
        - VT lookups can be parallelized via vt_workers.
        """
        try:
            ip_map = self._gather_ip_map()

            # apply 'since' filter if requested (seconds)
            since_val = qs.get('since', [None])[0]
            cutoff = None
            if since_val is not None:
                try:
                    s = int(since_val)
                    cutoff = int(time.time()) - s
                except Exception:
                    cutoff = None

            def _qs_int(name, default, min_v=None, max_v=None):
                raw = qs.get(name, [None])[0]
                if raw is None:
                    return default
                try:
                    n = int(str(raw).strip())
                except Exception:
                    return default
                if min_v is not None and n < min_v:
                    n = min_v
                if max_v is not None and n > max_v:
                    n = max_v
                return n

            include_vt = bool(int(qs.get('include_vt', ['0'])[0]) if qs.get('include_vt') else False)
            limit = _qs_int('limit', 500, 1, 5000)
            offset = _qs_int('offset', 0, 0, 10_000_000)
            vt_workers = _qs_int('vt_workers', 8, 1, 32)
            vt_budget = _qs_int('vt_budget', limit, 0, 5000)

            out = []
            for ip, v in ip_map.items():
                # validate IP syntax
                valid = True
                try:
                    import ipaddress as _ip
                    _ip.ip_address(ip)
                except Exception:
                    valid = False
                if cutoff is not None and v.get('last_ts', 0) < cutoff:
                    continue
                out.append({
                    'ip': ip,
                    'domains': sorted(list(v['domains'])),
                    'count': v['count'],
                    'last_ts': v['last_ts'],
                    'valid': valid,
                })

            out.sort(key=lambda x: (-x['count'], -x['last_ts']))

            total = len(out)
            page = out[offset: offset + limit]
            truncated = (offset + limit) < total

            # VT enrichment only for the visible page (bounded + optionally parallel)
            if include_vt and get_ip_report and vt_budget > 0 and page:
                begin_cache_batch()
                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    budgeted = page[: min(len(page), vt_budget)]
                    if vt_workers <= 1 or len(budgeted) <= 1:
                        for row in budgeted:
                            try:
                                row['vt'] = get_ip_report(row['ip'])
                            except Exception:
                                row['vt'] = None
                    else:
                        def _lookup(ip_str):
                            try:
                                return get_ip_report(ip_str)
                            except Exception:
                                return None

                        with ThreadPoolExecutor(max_workers=vt_workers) as ex:
                            futs = {ex.submit(_lookup, row['ip']): row for row in budgeted}
                            for fut in as_completed(futs):
                                row = futs[fut]
                                row['vt'] = fut.result()
                finally:
                    end_cache_batch(flush=True)

            self._send_json({
                'ips': page,
                'ips_total_count': total,
                'ips_displayed_count': len(page),
                'ips_offset': offset,
                'ips_limit': limit,
                'ips_truncated': bool(truncated),
                'include_vt': bool(include_vt),
                'vt_budget': vt_budget,
                'vt_workers': vt_workers,
            })
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_history(self, domain):
        if not domain:
            return self._send_json({'error': 'domain required'}, 400)
        h_obj = history.get(domain, {'meta': {}, 'events': [], 'current': {}})
        return self._send_json({'domain': domain, 'history': h_obj})
    
    def _handle_ip_query(self, ip):
        if not ip:
            return self._send_json({'error': 'ip required'}, 400)
        matches = []
        # current results
        for d, m in current_results.items():
            for srv, info in m.items():
                if info.get('type') == 'A' and ip in info.get('values', []):
                    matches.append({
                        'domain': d,
                        'server': srv,
                        'type': 'current',
                        'rtype': 'A',
                        'ts': info.get('ts'),
                        'values': list(info.get('values', []))
                    })
                if info.get('decoded_ips') and ip in info.get('decoded_ips', []):
                    matches.append({
                        'domain': d,
                        'server': srv,
                        'type': 'current',
                        'rtype': f"{info.get('type', 'A')}-derived",
                        'ts': info.get('ts'),
                        'decoded_ips': list(info.get('decoded_ips', [])),
                        'values': list(info.get('values', []))
                    })
    
        # history
        for d, hist_obj in history.items():
            events = hist_obj.get('events', []) if isinstance(hist_obj, dict) else (hist_obj or [])
            for ev in events:
                rtype = ev.get('type', 'A')
                ts = ev.get('ts', 0)
                if 'new' in ev:
                    if rtype == 'A' and (ip in ev.get('new', {}).get('values', []) or ip in ev.get('old', {}).get('values', [])):
                        matches.append({
                            'domain': d,
                            'server': ev.get('server'),
                            'type': 'history',
                            'rtype': rtype,
                            'ts': ts,
                            'old': ev.get('old'),
                            'new': ev.get('new')
                        })
                    if rtype in ('TXT', 'A') and (ip in ev.get('new', {}).get('decoded_ips', []) or ip in ev.get('old', {}).get('decoded_ips', [])):
                        matches.append({
                            'domain': d,
                            'server': ev.get('server'),
                            'type': 'history',
                            'rtype': rtype,
                            'ts': ts,
                            'old': ev.get('old'),
                            'new': ev.get('new')
                        })
                elif 'values' in ev:
                    if rtype == 'A' and ip in ev.get('values', []):
                        matches.append({
                            'domain': d,
                            'server': ev.get('server'),
                            'type': 'history',
                            'rtype': rtype,
                            'ts': ts,
                            'values': ev.get('values')
                        })
                    if rtype in ('TXT', 'A') and ip in ev.get('decoded_ips', []):
                        matches.append({
                            'domain': d,
                            'server': ev.get('server'),
                            'type': 'history',
                            'rtype': rtype,
                            'ts': ts,
                            'values': ev.get('values'),
                            'decoded_ips': ev.get('decoded_ips')
                        })
        return self._send_json({'ip': ip, 'matches': matches})
    
    def do_GET(self):
        """Handle GET requests (simple routing)."""
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
    
        if parsed.path == '/config':
            return self._handle_config()
        if parsed.path == '/results':
            return self._handle_results(qs)
        if parsed.path == '/decoders':
            return self._handle_decoders()
        if parsed.path == '/settings':
            return self._handle_settings_get()
        if parsed.path == '/decoders/custom':
            # simple GET support to list allowed ops
            try:
                ops = ['regex', 'base64', 'urlsafe_b64', 'xor_hex', 'xor32_ipv4', 'extract_ip_prefix', 'ascii']
                return self._send_json({'allowed_ops': ops, 'decoder_types': ['TXT', 'A']})
            except Exception:
                return self._send_json({'error': 'unable to list ops'}, 500)
        if parsed.path == '/history':
            domain = qs.get('domain', [None])[0]
            return self._handle_history(domain)
        if parsed.path == '/ip':
            ip = qs.get('ip', [None])[0]
            return self._handle_ip_query(ip)
        if parsed.path == '/ips':
            return self._handle_ips(qs)
        if parsed.path == '/domains':
            return self._handle_domains()
        if parsed.path == '/domain-analysis':
            return self._handle_domain_analysis(qs)
        if parsed.path == '/':
            b = frontend_html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
    
        # Serve only a strict allowlist of static frontend files from this package directory.
        try:
            base = os.path.dirname(__file__)
            rel = parsed.path.lstrip('/')
            # allow only simple filenames from ALLOWED_STATIC_FILES
            if rel and rel == os.path.basename(rel) and rel in ALLOWED_STATIC_FILES:
                fs_path = os.path.join(base, rel)
                if not os.path.isfile(fs_path):
                    raise FileNotFoundError(fs_path)
                ctype, _ = mimetypes.guess_type(fs_path)
                if not ctype:
                    ctype = 'application/octet-stream'
                with open(fs_path, 'rb') as fh:
                    data = fh.read()
                self.send_response(200)
                self.send_header('Content-Type', ctype + ('; charset=utf-8' if ctype.startswith('text/') else ''))
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        except Exception:
            # fall through to 404
            pass
    
        self.send_response(404)
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests (simple routing)."""
        parsed = urlparse(self.path)

        if parsed.path == '/domain-precheck':
            return self._handle_domain_precheck()
        
        if parsed.path == '/config':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
    
            with config_lock:
                # Handle domains update: preserve existing decoder settings
                if 'domains' in data:
                    def _canon_domain_name(value):
                        return str(value or '').strip().rstrip('.').lower()

                    new_domains_raw = data['domains']
                    # Get current domains for reference (to preserve decoder options)
                    current_domains = shared_config.get('domains', [])
                    current_map = {d['name']: d for d in current_domains if isinstance(d, dict)}
                    prev_names = {d.get('name', '').strip() for d in normalize_domains(current_domains) if d.get('name')}
                    
                    # Normalize new domains but preserve decode settings from current.
                    new_domains_normalized = normalize_domains(new_domains_raw)
                    for d in new_domains_normalized:
                        prev = current_map.get(d.get('name'), {})
                        typ = str(d.get('type', 'A')).upper()
                        if typ == 'TXT':
                            if 'txt_decode' not in d and prev.get('txt_decode'):
                                d['txt_decode'] = prev.get('txt_decode')
                            d.pop('a_decode', None)
                            d.pop('a_xor_key', None)
                        elif typ == 'A':
                            if 'a_decode' not in d and prev.get('a_decode') is not None:
                                d['a_decode'] = prev.get('a_decode')
                            if 'a_xor_key' not in d and prev.get('a_xor_key') is not None:
                                d['a_xor_key'] = prev.get('a_xor_key')
                            d.pop('txt_decode', None)
                        else:
                            d.pop('txt_decode', None)
                            d.pop('a_decode', None)
                            d.pop('a_xor_key', None)
                    next_names = {d.get('name', '').strip() for d in new_domains_normalized if d.get('name')}
                    removed_names = sorted(prev_names - next_names)
                    if removed_names:
                        purge_removed_domains_state(current_results, history, history_dir, removed_names)
                        print(f"[DEBUG] /config POST: Purged removed domain state: {removed_names}")

                    shared_config['domains'] = new_domains_normalized
                    print(f"[DEBUG] /config POST: Updated domains to {[d['name'] for d in new_domains_normalized]}")

                    # Safety purge: remove any orphan in-memory/disk state not present in current config.
                    # This prevents stale history/current rows from surviving due naming mismatches.
                    configured_canon = {
                        _canon_domain_name(d.get('name', ''))
                        for d in new_domains_normalized
                        if d.get('name')
                    }
                    orphan_names = set()
                    try:
                        if isinstance(current_results, dict):
                            for nm in list(current_results.keys()):
                                if _canon_domain_name(nm) not in configured_canon:
                                    orphan_names.add(str(nm))
                    except Exception:
                        pass
                    try:
                        if isinstance(history, dict):
                            for nm in list(history.keys()):
                                if _canon_domain_name(nm) not in configured_canon:
                                    orphan_names.add(str(nm))
                    except Exception:
                        pass
                    if orphan_names:
                        purge_removed_domains_state(
                            current_results,
                            history,
                            history_dir,
                            sorted(orphan_names)
                        )
                        print(f"[DEBUG] /config POST: Purged orphan domain state: {sorted(orphan_names)}")
                
                if 'servers' in data:
                    sv = data['servers']
                    if isinstance(sv, list):
                        shared_config['servers'] = [str(x).strip() for x in sv if str(x).strip()]
                    elif isinstance(sv, str):
                        shared_config['servers'] = [s.strip() for s in sv.split(',') if s.strip()]
                if 'interval' in data:
                    try:
                        iv = int(data['interval'])
                        shared_config['interval'] = max(1, iv)
                    except Exception:
                        pass
    
                if config_path:
                    to_write = {
                        'domains': shared_config.get('domains', []),
                        'servers': shared_config.get('servers', []),
                        'interval': shared_config.get('interval'),
                        'alerts': shared_config.get('alerts', {}),
                        'custom_decoders': shared_config.get('custom_decoders', []),
                        'custom_a_decoders': shared_config.get('custom_a_decoders', []),
                    }
                    try:
                        write_config(config_path, to_write)
                        print(f"[DEBUG] /config POST: Saved config to {config_path}")
                    except Exception as e:
                        print(f"[ERROR] /config POST: Failed to save config: {e}")
    
                resp = {
                    'status': 'ok',
                    'domains': shared_config.get('domains'),
                    'servers': shared_config.get('servers'),
                    'interval': shared_config.get('interval'),
                    'alerts': shared_config.get('alerts', {})
                }
            return self._send_json(resp)
    
        if parsed.path == '/settings':
            return self._handle_settings_post()
    
        if parsed.path == '/resolve':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                data = {}
    
            with config_lock:
                req = {}
                if 'domains' in data:
                    req['domains'] = normalize_domains(data['domains'])
                elif 'domain' in data:
                    req['domains'] = normalize_domains(data['domain'])
                if 'servers' in data:
                    sv = data['servers']
                    if isinstance(sv, list):
                        req['servers'] = [str(x).strip() for x in sv if str(x).strip()]
                    elif isinstance(sv, str):
                        req['servers'] = [s.strip() for s in sv.split(',') if s.strip()]
                shared_config['_force_resolve'] = req
            return self._send_json({'status': 'ok', 'requested': True})
    
        if parsed.path == '/ip':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
            ip = data.get('ip')
            if not ip:
                return self._send_json({'error': 'ip required'}, 400)
            matches = []
            for d, m in current_results.items():
                for srv, info in m.items():
                    if info.get('type') == 'A' and ip in info.get('values', []):
                        matches.append({
                            'domain': d,
                            'server': srv,
                            'type': 'current',
                            'rtype': 'A',
                            'ts': info.get('ts'),
                            'values': list(info.get('values', []))
                        })
            for d, hist_obj in history.items():
                events = hist_obj.get('events', []) if isinstance(hist_obj, dict) else (hist_obj or [])
                for ev in events:
                    rtype = ev.get('type', 'A')
                    if 'new' in ev:
                        if rtype == 'A' and (ip in ev.get('new', {}).get('values', []) or ip in ev.get('old', {}).get('values', [])):
                            matches.append({'domain': d, 'server': ev.get('server'), 'type': 'history', 'rtype': rtype, 'ts': ev.get('ts'), 'old': ev.get('old'), 'new': ev.get('new')})
                    elif 'values' in ev:
                        if rtype == 'A' and ip in ev.get('values', []):
                            matches.append({'domain': d, 'server': ev.get('server'), 'type': 'history', 'rtype': rtype, 'ts': ev.get('ts'), 'values': ev.get('values')})
            return self._send_json({'ip': ip, 'matches': matches})
    
        if parsed.path == '/analyze':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
            domain = data.get('domain')
            txt = data.get('txt') or data.get('sample')
            if not domain or not txt:
                return self._send_json({'error': 'domain and txt required'}, 400)
            try:
                res = analyze_domain_decoding(domain, txt)
                # res is already a structured object with analysis and best
                payload = {'domain': domain, 'sample': txt}
                payload.update(res)
                return self._send_json(payload)
            except Exception as e:
                return self._send_json({'error': str(e)}, 500)
    
        if parsed.path == '/verify':
            # verify decoders for a list of domains (or all configured domains)
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
    
            domains = None
            if 'domains' in data and isinstance(data['domains'], list):
                domains = [d.get('name') if isinstance(d, dict) else d for d in data['domains']]
            else:
                # fallback to shared_config domains
                with config_lock:
                    domains = [d.get('name') if isinstance(d, dict) else d for d in shared_config.get('domains', [])]
    
            results = {}
            vt_batch_started = False
            if get_ip_report:
                begin_cache_batch()
                vt_batch_started = True
            try:
                for dom in domains:
                    if not dom:
                        continue
                    # gather a sample TXT value from current_results if available
                    sample_vals = []
                    for srv, info in (current_results.get(dom) or {}).items():
                        if info.get('type') == 'TXT':
                            sample_vals.extend(info.get('values', []) or [])
                    sample = '|'.join(sample_vals) if sample_vals else ''
                    try:
                        analysis = analyze_domain_decoding(dom, sample)
                    except Exception as e:
                        results[dom] = {'error': str(e)}
                        continue
    
                    # attach VT reports per decoded ip if available
                    for name, info in (analysis.get('analysis') or {}).items():
                        ips = info.get('ips', [])
                        detailed = []
                        for ip in ips:
                            valid = True
                            try:
                                import ipaddress as _ip
                                _ip.ip_address(ip)
                            except Exception:
                                valid = False
                            vt = None
                            if get_ip_report:
                                try:
                                    vt = get_ip_report(ip)
                                except Exception:
                                    vt = None
                            detailed.append({'ip': ip, 'valid': valid, 'vt': vt})
                        info['detailed_ips'] = detailed
    
                    results[dom] = analysis
            finally:
                if vt_batch_started:
                    end_cache_batch(flush=True)
    
            return self._send_json({'results': results})
    
        if parsed.path == '/ip-list-analysis':
            return self._handle_ip_list_analysis()

        if parsed.path == '/ip-relationship-analysis':
            return _handle_ip_relationship_analysis(self, gather_ip_map_fn=self._gather_ip_map)
    
        if parsed.path == '/misp/event-ips':
            return self._handle_misp_event_ips()
    
        if parsed.path == '/decoders/custom' and self.command == 'POST':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
    
            name = data.get('name')
            steps = data.get('steps')
            decoder_type = str(data.get('decoder_type', 'TXT')).upper()
            if decoder_type not in ('TXT', 'A'):
                return self._send_json({'error': 'decoder_type must be TXT or A'}, 400)
            if not name or not isinstance(steps, list):
                return self._send_json({'error': 'name and steps required'}, 400)
            try:
                # server-side validation: limit steps and sizes
                if not isinstance(steps, list) or len(steps) == 0 or len(steps) > 12:
                    return self._send_json({'error': 'steps must be a non-empty list with <=12 steps'}, 400)
                total_chars = 0
                import re as _re
                for s in steps:
                    if not isinstance(s, dict) or 'op' not in s:
                        return self._send_json({'error': 'each step must be a dict with op field'}, 400)
                    total_chars += sum(len(str(v)) for v in s.values())
                    if total_chars > 2000:
                        return self._send_json({'error': 'steps too large'}, 400)
                    op = s.get('op')
                    if op == 'regex':
                        pat = s.get('pattern','')
                        if not isinstance(pat, str) or len(pat) > 300:
                            return self._send_json({'error': 'regex pattern too long'}, 400)
                        try:
                            _re.compile(pat)
                        except Exception as e:
                            return self._send_json({'error': 'invalid regex: '+str(e)}, 400)
                    if op == 'xor_hex':
                        key = s.get('key','')
                        if not isinstance(key, str) or len(key) > 128:
                            return self._send_json({'error': 'xor_hex key too long'}, 400)
                    if op == 'xor32_ipv4':
                        key = s.get('key', s.get('key_hex', ''))
                        if key is not None and len(str(key)) > 64:
                            return self._send_json({'error': 'xor32_ipv4 key too long'}, 400)
    
                if decoder_type == 'TXT':
                    from txt_decoder import register_custom_decoder
                    ok = register_custom_decoder(name, steps)
                    list_key = 'custom_decoders'
                else:
                    from a_decoder import register_custom_a_decoder
                    ok = register_custom_a_decoder(name, steps)
                    list_key = 'custom_a_decoders'
                if not ok:
                    return self._send_json({'error': 'failed to register (name conflict or invalid steps)'}, 400)
    
                with config_lock:
                    lst = shared_config.setdefault(list_key, [])
                    exists = any(x.get('name') == name for x in lst)
                    if not exists:
                        lst.append({'name': name, 'steps': steps, 'decoder_type': decoder_type})
                    if config_path:
                        try:
                            cfg = read_config(config_path) or {}
                            cfg['domains'] = cfg.get('domains', shared_config.get('domains', []))
                            cfg['servers'] = cfg.get('servers', shared_config.get('servers', []))
                            cfg['interval'] = cfg.get('interval', shared_config.get('interval'))
                            cfg['custom_decoders'] = shared_config.get('custom_decoders', [])
                            cfg['custom_a_decoders'] = shared_config.get('custom_a_decoders', [])
                            write_config(config_path, cfg)
                        except Exception:
                            pass
                return self._send_json({'status': 'ok', 'registered': name, 'decoder_type': decoder_type})
            except Exception as e:
                return self._send_json({'error': str(e)}, 500)
    
        if parsed.path == '/decoders/custom' and self.command == 'DELETE':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
            name = data.get('name')
            decoder_type = str(data.get('decoder_type', 'TXT')).upper()
            if decoder_type not in ('TXT', 'A'):
                return self._send_json({'error': 'decoder_type must be TXT or A'}, 400)
            if not name:
                return self._send_json({'error': 'name required'}, 400)
            try:
                if decoder_type == 'TXT':
                    from txt_decoder import unregister_custom_decoder
                    ok = unregister_custom_decoder(name)
                    list_key = 'custom_decoders'
                else:
                    from a_decoder import unregister_custom_a_decoder
                    ok = unregister_custom_a_decoder(name)
                    list_key = 'custom_a_decoders'
                if not ok:
                    return self._send_json({'error': 'not removed (builtin or not found)'}, 400)
                with config_lock:
                    lst = shared_config.get(list_key, [])
                    newlst = [x for x in lst if x.get('name') != name]
                    shared_config[list_key] = newlst
                    if config_path:
                        try:
                            cfg = read_config(config_path) or {}
                            cfg['custom_decoders'] = shared_config.get('custom_decoders', [])
                            cfg['custom_a_decoders'] = shared_config.get('custom_a_decoders', [])
                            cfg['domains'] = cfg.get('domains', shared_config.get('domains', []))
                            cfg['servers'] = cfg.get('servers', shared_config.get('servers', []))
                            cfg['interval'] = cfg.get('interval', shared_config.get('interval'))
                            write_config(config_path, cfg)
                        except Exception:
                            pass
                return self._send_json({'status': 'ok', 'removed': name, 'decoder_type': decoder_type})
            except Exception as e:
                return self._send_json({'error': str(e)}, 500)
    
        if parsed.path == '/decoders/custom' and self.command == 'PUT':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
            name = data.get('name')
            steps = data.get('steps')
            decoder_type = str(data.get('decoder_type', 'TXT')).upper()
            if decoder_type not in ('TXT', 'A'):
                return self._send_json({'error': 'decoder_type must be TXT or A'}, 400)
            if not name or not isinstance(steps, list):
                return self._send_json({'error': 'name and steps required'}, 400)
            try:
                if not isinstance(steps, list) or len(steps) == 0 or len(steps) > 12:
                    return self._send_json({'error': 'steps must be a non-empty list with <=12 steps'}, 400)
                import re as _re
                total_chars = 0
                for s in steps:
                    if not isinstance(s, dict) or 'op' not in s:
                        return self._send_json({'error': 'each step must be a dict with op field'}, 400)
                    total_chars += sum(len(str(v)) for v in s.values())
                    if total_chars > 2000:
                        return self._send_json({'error': 'steps too large'}, 400)
                    if s.get('op') == 'regex':
                        pat = s.get('pattern','')
                        if not isinstance(pat, str) or len(pat) > 300:
                            return self._send_json({'error': 'regex pattern too long'}, 400)
                        try:
                            _re.compile(pat)
                        except Exception as e:
                            return self._send_json({'error': 'invalid regex: '+str(e)}, 400)
                    if s.get('op') == 'xor32_ipv4':
                        key = s.get('key', s.get('key_hex', ''))
                        if key is not None and len(str(key)) > 64:
                            return self._send_json({'error': 'xor32_ipv4 key too long'}, 400)
    
                if decoder_type == 'TXT':
                    from txt_decoder import unregister_custom_decoder, register_custom_decoder
                    unregister_custom_decoder(name)
                    ok = register_custom_decoder(name, steps)
                    list_key = 'custom_decoders'
                else:
                    from a_decoder import unregister_custom_a_decoder, register_custom_a_decoder
                    unregister_custom_a_decoder(name)
                    ok = register_custom_a_decoder(name, steps)
                    list_key = 'custom_a_decoders'
                if not ok:
                    return self._send_json({'error': 'failed to register updated decoder'}, 400)
    
                with config_lock:
                    lst = shared_config.setdefault(list_key, [])
                    replaced = False
                    for i, x in enumerate(lst):
                        if x.get('name') == name:
                            lst[i] = {'name': name, 'steps': steps, 'decoder_type': decoder_type}
                            replaced = True
                            break
                    if not replaced:
                        lst.append({'name': name, 'steps': steps, 'decoder_type': decoder_type})
                    if config_path:
                        try:
                            cfg = read_config(config_path) or {}
                            cfg['custom_decoders'] = shared_config.get('custom_decoders', [])
                            cfg['custom_a_decoders'] = shared_config.get('custom_a_decoders', [])
                            cfg['domains'] = cfg.get('domains', shared_config.get('domains', []))
                            cfg['servers'] = cfg.get('servers', shared_config.get('servers', []))
                            cfg['interval'] = cfg.get('interval', shared_config.get('interval'))
                            write_config(config_path, cfg)
                        except Exception:
                            pass
                return self._send_json({'status': 'ok', 'updated': name, 'decoder_type': decoder_type})
            except Exception as e:
                return self._send_json({'error': str(e)}, 500)
    
        if parsed.path == '/decoders/custom/preview' and self.command == 'POST':
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)
            steps = data.get('steps')
            sample = data.get('sample')
            decoder_type = str(data.get('decoder_type', 'TXT')).upper()
            if decoder_type not in ('TXT', 'A'):
                return self._send_json({'error': 'decoder_type must be TXT or A'}, 400)
            if not isinstance(steps, list) or sample is None:
                return self._send_json({'error': 'steps(list) and sample required'}, 400)
            try:
                # validate steps similar to register path (but lighter)
                if not isinstance(steps, list) or len(steps) == 0 or len(steps) > 12:
                    return self._send_json({'error': 'steps must be a non-empty list with <=12 steps'}, 400)
                import re as _re
                total_chars = 0
                for s in steps:
                    if not isinstance(s, dict) or 'op' not in s:
                        return self._send_json({'error': 'each step must be a dict with op field'}, 400)
                    total_chars += sum(len(str(v)) for v in s.values())
                    if total_chars > 2000:
                        return self._send_json({'error': 'steps too large'}, 400)
                    if s.get('op') == 'regex':
                        pat = s.get('pattern','')
                        if not isinstance(pat, str) or len(pat) > 300:
                            return self._send_json({'error': 'regex pattern too long'}, 400)
                        try:
                            _re.compile(pat)
                        except Exception as e:
                            return self._send_json({'error': 'invalid regex: '+str(e)}, 400)
                    if s.get('op') == 'xor32_ipv4':
                        key = s.get('key', s.get('key_hex', ''))
                        if key is not None and len(str(key)) > 64:
                            return self._send_json({'error': 'xor32_ipv4 key too long'}, 400)
    
                if decoder_type == 'TXT':
                    from txt_decoder import create_custom_decoder
                else:
                    from a_decoder import create_custom_a_decoder as create_custom_decoder
                dec = create_custom_decoder(steps)
                if not dec:
                    return self._send_json({'error': 'invalid steps'}, 400)
                res = dec([sample])
                return self._send_json({'sample': sample, 'decoded': res, 'decoder_type': decoder_type})
            except Exception as e:
                return self._send_json({'error': str(e)}, 500)
    
        self.send_response(404)
        self.end_headers()
    

    handler_cls._send_json = _send_json
    handler_cls._handle_config = _handle_config
    handler_cls._handle_results = _handle_results
    handler_cls._handle_decoders = _handle_decoders
    handler_cls._handle_settings_get = _handle_settings_get
    handler_cls._handle_settings_post = _handle_settings_post
    handler_cls._gather_ip_map = _gather_ip_map
    handler_cls._handle_domains = _handle_domains
    handler_cls._handle_domain_analysis = _handle_domain_analysis
    handler_cls._handle_domain_precheck = _handle_domain_precheck
    handler_cls._handle_ip_list_analysis = _handle_ip_list_analysis
    handler_cls._handle_misp_event_ips = _handle_misp_event_ips
    handler_cls._handle_ips = _handle_ips
    handler_cls._handle_history = _handle_history
    handler_cls._handle_ip_query = _handle_ip_query
    handler_cls.do_GET = do_GET
    handler_cls.do_POST = do_POST
    return handler_cls
