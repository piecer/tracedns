#!/usr/bin/env python3
"""
Small helper to probe DNS record types for domains in `dns_config.json`.

Usage:
  python3 -m tracedns.detect_types            # probes domains marked UNKNOWN in config
  python3 -m tracedns.detect_types domain1 domain2 ...   # probe specific domains

Behavior:
- Loads `dns_config.json` from the module directory.
- For each domain to probe, attempts queries for types in priority order: TXT, A, AAAA, CNAME, MX, NS.
- If a record is found, sets the domain's `type` accordingly and writes back the config (creates a backup).
"""
import json
import os
import sys
import time
from dns import resolver, exception

HERE = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(HERE, 'dns_config.json')
TYPES_PRIORITY = ['TXT', 'A', 'AAAA', 'CNAME', 'MX', 'NS']


def load_config(path=CONFIG_PATH):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def write_config(path, data):
    bak = path + '.bak.' + time.strftime('%Y%m%d%H%M%S')
    try:
        if os.path.exists(path):
            os.rename(path, bak)
    except Exception:
        pass
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def probe_domain(domain, nameserver=None, timeout=3.0):
    """Return first matching type from TYPES_PRIORITY or None."""
    r = resolver.Resolver()
    if nameserver:
        r.nameservers = [nameserver]
    r.lifetime = timeout
    for t in TYPES_PRIORITY:
        try:
            answers = r.resolve(domain, t)
            if answers:
                return t
        except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers, exception.Timeout):
            continue
        except Exception:
            continue
    return None


def find_entry(config, name):
    for entry in config.get('domains', []) + config.get('additional_imported', []):
        if entry.get('name') == name:
            return entry
    return None


def main(argv=None):
    argv = argv or sys.argv[1:]
    cfg = load_config()
    to_probe = []
    if argv:
        to_probe = list(argv)
    else:
        # collect UNKNOWN entries
        for entry in cfg.get('domains', []) + cfg.get('additional_imported', []):
            if entry.get('type', '').upper() in ('UNKNOWN', '', 'AUTO'):
                to_probe.append(entry.get('name'))
    if not to_probe:
        print('No domains to probe.')
        return 0

    print('Probing', len(to_probe), 'domains...')
    changed = False
    for d in to_probe:
        print('\nProbing', d)
        t = probe_domain(d)
        print('  detected type:', t)
        entry = find_entry(cfg, d)
        if entry is None:
            # add to additional_imported
            arr = cfg.setdefault('additional_imported', [])
            entry = {'name': d}
            arr.append(entry)
        if t:
            old = entry.get('type')
            entry['type'] = t
            if old != t:
                changed = True
                print('  updated type', old, '->', t)
        else:
            print('  no type detected; leaving as-is')

    if changed:
        write_config(CONFIG_PATH, cfg)
        print('\nConfig updated and backup saved.')
    else:
        print('\nNo changes made to config.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
