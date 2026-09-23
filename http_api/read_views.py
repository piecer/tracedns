"""Pure projections over owned snapshots; no I/O or shared-state locks."""
import ipaddress as _ip
from config_manager import domain_storage_name


def build_ip_rows(current_snapshot, history_snapshot):
    ip_map = {}

    def _ip_entry(ip):
        return ip_map.setdefault(ip, {
            'domains': set(),
            'record_types': set(),
            'decoders': set(),
            'change_timestamps': set(),
            'count': 0,
            'last_ts': 0,
        })

    def _add_dns_provenance(entry, source, record_type=None):
        if not isinstance(source, dict):
            source = {}
        rtype = str(record_type or source.get('type') or '').strip().upper()
        if rtype:
            entry['record_types'].add(rtype)
        decoder_field = {
            'TXT': 'txt_decode',
            'A': 'a_decode',
            'ENS': 'ens_decode',
            'SNS': 'sns_decode',
        }.get(rtype)
        decoder = str(source.get(decoder_field) or '').strip() if decoder_field else ''
        if decoder and decoder.lower() != 'none':
            entry['decoders'].add(f'{rtype}:{decoder}')

    for d, m in current_snapshot.items():
        for _srv, info in m.items():
            for ip in info.get('values', []) if info.get('type') == 'A' else []:
                ent = _ip_entry(ip)
                ent['domains'].add(d)
                ent['count'] += 1
                ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
                _add_dns_provenance(ent, {}, 'A')
            for ip in info.get('decoded_ips', []):
                ent = _ip_entry(ip)
                ent['domains'].add(d)
                ent['count'] += 1
                ent['last_ts'] = max(ent['last_ts'], info.get('ts', 0))
                _add_dns_provenance(ent, info)

    for d, hist_obj in history_snapshot.items():
        events = hist_obj.get('events', []) if isinstance(hist_obj, dict) else []
        for ev in events:
            ts = ev.get('ts', 0)
            if 'new' in ev or 'old' in ev:
                changed_ips = set()
                for side in ('new', 'old'):
                    side_obj = ev.get(side, {})
                    for ip in side_obj.get('values', []) if ev.get('type', 'A') == 'A' else []:
                        changed_ips.add(ip)
                        ent = _ip_entry(ip)
                        ent['domains'].add(d)
                        ent['count'] += 1
                        ent['last_ts'] = max(ent['last_ts'], ts)
                        _add_dns_provenance(ent, {}, ev.get('type', 'A'))
                    for ip in side_obj.get('decoded_ips', []) if ev.get('type', 'A') in ('TXT', 'A', 'ENS', 'SNS') else []:
                        changed_ips.add(ip)
                        ent = _ip_entry(ip)
                        ent['domains'].add(d)
                        ent['count'] += 1
                        ent['last_ts'] = max(ent['last_ts'], ts)
                        _add_dns_provenance(ent, side_obj, ev.get('type', 'A'))
                if int(ts or 0) > 0:
                    for ip in changed_ips:
                        _ip_entry(ip)['change_timestamps'].add(int(ts))
            elif 'values' in ev:
                if ev.get('type', 'A') == 'A':
                    for ip in ev.get('values', []):
                        ent = _ip_entry(ip)
                        ent['domains'].add(d)
                        ent['count'] += 1
                        ent['last_ts'] = max(ent['last_ts'], ts)
                        _add_dns_provenance(ent, {}, ev.get('type', 'A'))
                if ev.get('type', 'A') in ('TXT', 'A', 'ENS', 'SNS'):
                    for ip in ev.get('decoded_ips', []):
                        ent = _ip_entry(ip)
                        ent['domains'].add(d)
                        ent['count'] += 1
                        ent['last_ts'] = max(ent['last_ts'], ts)
                        _add_dns_provenance(ent, ev, ev.get('type', 'A'))

    rows = []
    for ip, v in ip_map.items():
        valid = True
        try:
            import ipaddress as _ip

            _ip.ip_address(ip)
        except Exception:
            valid = False
        rows.append({
            'ip': ip,
            'domains': sorted(list(v['domains'])),
            'record_types': sorted(list(v['record_types'])),
            'decoders': sorted(list(v['decoders'])),
            'change_timestamps': sorted(v['change_timestamps'], reverse=True)[:16],
            'count': v['count'],
            'last_ts': v['last_ts'],
            'valid': valid,
        })

    rows.sort(key=lambda x: (-x['count'], -x['last_ts']))
    return rows


def build_domain_rows(current_snapshot, history_meta_snapshot, cfg_domains, report_for=None):
    _vt_brief = report_for or (lambda ip: None)
    cfg_type_map = {}
    lifecycle_map = {}
    for d in cfg_domains:
        if isinstance(d, dict):
            name = domain_storage_name(d)
            typ = str(d.get('type') or 'A').upper()
        else:
            name = str(d or '').strip()
            typ = 'A'
        if name:
            cfg_type_map[name] = typ

    for d, meta in history_meta_snapshot.items():
        try:
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

    for d, m in current_snapshot.items():
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

    out = []
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
    return out
