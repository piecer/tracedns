#!/usr/bin/env python3
"""
HTTP server and web UI module.
Provides a lightweight HTTP API and static frontend serving used by the DNS monitor.
"""
import os
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

from config_manager import normalize_domains, write_config, read_config
import time
import mimetypes
from txt_decoder import TXT_DECODE_METHODS, analyze_domain_decoding
from a_decoder import A_DECODE_METHODS
try:
    from vt_lookup import get_ip_report, begin_cache_batch, end_cache_batch
except Exception:
    # vt_lookup optional; if missing or import fails, get_ip_report will be treated as unavailable
    get_ip_report = None
    def begin_cache_batch():
        return 0
    def end_cache_batch(flush=True):
        return False


def purge_removed_domains_state(current_results, history, history_dir, removed_domains):
    """Purge in-memory and on-disk history state for removed domains."""
    removed = [str(d or '').strip() for d in (removed_domains or []) if str(d or '').strip()]
    if not removed:
        return
    for domain in removed:
        try:
            if isinstance(current_results, dict):
                current_results.pop(domain, None)
        except Exception:
            pass
        try:
            if isinstance(history, dict):
                history.pop(domain, None)
        except Exception:
            pass
        try:
            if history_dir:
                fp = os.path.join(history_dir, f"{domain}.json")
                if os.path.isfile(fp):
                    os.remove(fp)
        except Exception:
            pass


def load_frontend_html():
    """
    프론트엔드 HTML을 로드합니다.
    기본 파일이 있으면 사용, 없으면 내장 폴백(간단)을 사용합니다.
    
    Returns:
        str: HTML 콘텐츠
    """
    # Use dns_frontend.html as the primary UI. Keep dashboard as legacy fallback.
    base = os.path.dirname(__file__)
    dashboard_path = os.path.join(base, "dns_dashboard.html")
    frontend_path = os.path.join(base, "dns_frontend.html")
    for p in (frontend_path, dashboard_path):
        try:
            with open(p, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            continue
    return "<html><body>Frontend missing</body></html>"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server (each request handled in its own thread)."""
    daemon_threads = True


def make_handler(shared_config, config_lock, config_path, history_dir, current_results, history):
    """
    Create a configured HTTP request handler class bound to shared runtime state.

    Args:
        shared_config (dict): shared configuration dictionary
        config_lock (threading.Lock): lock protecting shared_config
        config_path (str): path to JSON config file for persistence
        history_dir (str): path to history directory
        current_results (dict): in-memory current DNS query results
        history (dict): in-memory history object

    Returns:
        class: a BaseHTTPRequestHandler subclass configured with closures
    """
    frontend_html = load_frontend_html()

    class ConfigHandler(BaseHTTPRequestHandler):
        def _send_json(self, obj, code=200):
            """Send a JSON response with proper UTF-8 headers."""
            b = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        # ---- Handlers extracted for readability ----
        def _handle_config(self):
            with config_lock:
                cfg = {
                    'domains': list(shared_config.get('domains', [])),
                    'servers': list(shared_config.get('servers', [])),
                    'interval': shared_config.get('interval')
                }
                # include alert settings if present
                if 'alerts' in shared_config:
                    cfg['alerts'] = shared_config.get('alerts')
            self._send_json(cfg)

        def _handle_results(self):
            try:
                data = {}
                for d, m in current_results.items():
                    data[d] = {}
                    for srv, info in m.items():
                        entry = {
                            'type': info.get('type'),
                            'values': list(info.get('values', [])),
                            'decoded_ips': list(info.get('decoded_ips', [])),
                            'ts': info.get('ts')
                        }
                        if info.get('type') == 'TXT' and info.get('txt_decode'):
                            entry['txt_decode'] = info.get('txt_decode')
                        if info.get('type') == 'A' and info.get('a_decode'):
                            entry['a_decode'] = info.get('a_decode')
                        if info.get('type') == 'A' and info.get('a_xor_key'):
                            entry['a_xor_key'] = info.get('a_xor_key')
                        data[d][srv] = entry
                self._send_json({'results': data})
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        def _handle_decoders(self):
            try:
                names = sorted(list(TXT_DECODE_METHODS.keys()))
                a_names = sorted(list(A_DECODE_METHODS.keys()))
                # include any registered custom decoder metadata from shared_config
                txt_custom = list(shared_config.get('custom_decoders', []) or [])
                a_custom = list(shared_config.get('custom_a_decoders', []) or [])
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
                self._send_json({
                    'decoders': names,
                    'custom': txt_custom,
                    'custom_a': a_custom,
                    'custom_all': custom_all,
                    'a_decoders': a_names
                })
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        def _handle_settings_get(self):
            try:
                # prefer in-memory shared_config alerts, fallback to config file
                with config_lock:
                    alerts = shared_config.get('alerts', None)
                if alerts is None and config_path:
                    cfg = read_config(config_path) or {}
                    alerts = cfg.get('alerts', {})
                self._send_json({'settings': {'alerts': alerts or {}}})
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        def _handle_settings_post(self):
            # update alerts settings and persist to config_path
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length) if length > 0 else b''
            try:
                data = json.loads(body.decode('utf-8')) if body else {}
            except Exception:
                return self._send_json({'error': 'invalid json'}, 400)

            alerts = data.get('alerts')
            if alerts is None or not isinstance(alerts, dict):
                return self._send_json({'error': 'alerts object required'}, 400)

            # Validate VirusTotal API key if provided (basic checks)
            try:
                import re as _re
                vt = alerts.get('vt_api_key')
                if vt is not None and str(vt).strip() != '':
                    vts = str(vt).strip()
                    # simple validation: no whitespace and reasonable length
                    if _re.search(r"\s", vts) or len(vts) < 20 or len(vts) > 128:
                        return self._send_json({'error': 'invalid vt_api_key (bad format or length)'}, 400)
                    # allow common VT formats (hex or base64-like); prefer hex64 but not required
                    if not (_re.fullmatch(r'[A-Fa-f0-9]{64}', vts) or _re.fullmatch(r'[A-Za-z0-9\-_=]+', vts)):
                        return self._send_json({'error': 'invalid vt_api_key (unexpected characters)'}, 400)
                    # store back cleaned value
                    alerts['vt_api_key'] = vts
                    # Apply VT API key to vt_lookup module
                    try:
                        from vt_lookup import set_api_key
                        set_api_key(vts)
                    except Exception:
                        pass
            except Exception:
                return self._send_json({'error': 'vt_api_key validation error'}, 400)

            with config_lock:
                shared_config['alerts'] = alerts
                # persist into config_path preserving other top-level keys
                if config_path:
                    try:
                        cfg = read_config(config_path) or {}
                        cfg['alerts'] = alerts
                        # keep existing domains/servers/interval/custom_decoders if present
                        if 'domains' not in cfg:
                            cfg['domains'] = shared_config.get('domains', [])
                        if 'servers' not in cfg:
                            cfg['servers'] = shared_config.get('servers', [])
                        if 'interval' not in cfg:
                            cfg['interval'] = shared_config.get('interval')
                        if 'custom_decoders' not in cfg:
                            cfg['custom_decoders'] = shared_config.get('custom_decoders', [])
                        write_config(config_path, cfg)
                        import sys
                        print(f"[DEBUG] Settings saved to {config_path}: {alerts}", file=sys.stderr)
                    except Exception as e:
                        import sys
                        print(f"[ERROR] Failed to save settings to {config_path}: {e}", file=sys.stderr)
            # apply alert runtime immediately (best effort)
            try:
                from alerts import init_from_alerts as _init_alerts_runtime
                _init_alerts_runtime(alerts)
            except Exception as e:
                import sys
                print(f"[WARN] Failed to apply runtime alert settings: {e}", file=sys.stderr)
            return self._send_json({'status': 'ok', 'alerts': alerts})

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
                    except Exception:
                        continue

                for d in cfg_domains:
                    name = d.get('name') if isinstance(d, dict) else d
                    name = name or ''
                    info = seen_map.get(name, {'last_ts': 0, 'servers': [], 'samples': []})
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
                        'samples': info.get('samples', [])
                    })

                # also include any domains present in current_results but not in config (likely ephemeral)
                for d, v in seen_map.items():
                    if d and not any(x['name'] == d for x in domains):
                        domains.append({'name': d, 'type': 'A', 'resolving': bool(v.get('samples') or v.get('last_ts')), 'last_ts': v.get('last_ts', 0), 'servers': v.get('servers', []), 'samples': v.get('samples', [])})

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
                for d in cfg_domains:
                    if isinstance(d, dict):
                        name = str(d.get('name') or '').strip()
                        typ = str(d.get('type') or 'A').upper()
                    else:
                        name = str(d or '').strip()
                        typ = 'A'
                    if name:
                        cfg_type_map[name] = typ

                domain_map = {}
                # seed with configured domains
                for name, typ in cfg_type_map.items():
                    domain_map[name] = {
                        'domain': name,
                        'record_types': {typ},
                        'resolved_ips': set(),
                        'decoded_ips': set(),
                        'last_ts': 0
                    }

                for d, m in current_results.items():
                    ent = domain_map.setdefault(d, {
                        'domain': d,
                        'record_types': set(),
                        'resolved_ips': set(),
                        'decoded_ips': set(),
                        'last_ts': 0
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
                        })
                finally:
                    if vt_batch_started:
                        end_cache_batch(flush=True)

                self._send_json({'domains': out, 'include_vt': include_vt})
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

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
                for idx, ip in enumerate(valid_ips):
                    rep = None
                    if vt_enabled:
                        use_cache_only = idx >= vt_lookup_budget
                        if use_cache_only:
                            vt_budget_limited = True
                        else:
                            vt_lookup_attempted += 1
                        try:
                            if use_cache_only:
                                try:
                                    rep = get_ip_report(ip, cache_only=True)
                                except TypeError:
                                    # Backward compatibility with older vt_lookup signature.
                                    rep = None
                            else:
                                rep = get_ip_report(ip)
                        except Exception:
                            rep = None
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

                include_vt = bool(int(qs.get('include_vt', ['0'])[0]) if qs.get('include_vt') else False)
                out = []
                vt_batch_started = False
                if include_vt and get_ip_report:
                    begin_cache_batch()
                    vt_batch_started = True
                try:
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
                        row = {
                            'ip': ip,
                            'domains': sorted(list(v['domains'])),
                            'count': v['count'],
                            'last_ts': v['last_ts'],
                            'valid': valid
                        }
                        # optionally include VirusTotal reputation info (requires env var VIRUSTOTAL_API_KEY)
                        if include_vt and get_ip_report:
                            try:
                                rep = get_ip_report(ip)
                                row['vt'] = rep
                            except Exception:
                                row['vt'] = None

                        out.append(row)
                finally:
                    if vt_batch_started:
                        end_cache_batch(flush=True)
                out.sort(key=lambda x: (-x['count'], -x['last_ts']))
                self._send_json({'ips': out})
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
                return self._handle_results()
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

            # Attempt to serve static files from this package directory (allow direct access
            # to dns_frontend.html, dns_dashboard.html, settings.html, etc.)
            try:
                base = os.path.dirname(__file__)
                # strip leading slash
                rel = parsed.path.lstrip('/')
                fs_path = os.path.join(base, rel)
                if os.path.isfile(fs_path):
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

    return ConfigHandler
