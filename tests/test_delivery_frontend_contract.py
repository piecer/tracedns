"""Closed health schema parity through the shipped JavaScript parser/renderer."""
import copy
import json
from pathlib import Path
import re
import subprocess

from http_api.delivery_health import HEALTH_SCHEMA, REASONS
from test_delivery_frontend_fixture import delivery_fixture

ROOT = Path(__file__).resolve().parents[1]


def test_shipped_health_required_types_closed_enums_and_precision(tmp_path):
    store = delivery_fixture(tmp_path / 'health', 'backlog')
    try:
        health = store.health_snapshot()
    finally:
        store.close(clean=True)
    valid = [health]
    invalid = []

    def walk(schema, value, trail=()):
        if schema['type'] == 'object':
            for key, child in schema['properties'].items():
                missing = copy.deepcopy(health)
                target = missing
                for part in trail:
                    target = target[part]
                del target[key]
                invalid.append(missing)
                walk(child, value[key], (*trail, key))
            extra = copy.deepcopy(health)
            target = extra
            for part in trail:
                target = target[part]
            target['PRIVATE-CANARY'] = '<img onerror=alert(1)>'
            invalid.append(extra)
            return
        choices = [None, '', [], {}, -1, 0.5, '0', True]
        if 'enum' in schema:
            for choice in schema['enum']:
                candidate = copy.deepcopy(health)
                target = candidate
                for part in trail[:-1]:
                    target = target[part]
                target[trail[-1]] = choice
                valid.append(candidate)
            choices = ['PRIVATE-CANARY<img onerror=alert(1)>', 1, False, [], {}]
        else:
            types = schema['type'] if isinstance(schema['type'], list) else [schema['type']]
            choices = [choice for choice in choices if not (
                choice is None and 'null' in types or
                type(choice) is bool and 'boolean' in types)]
        for choice in choices:
            candidate = copy.deepcopy(health)
            target = candidate
            for part in trail[:-1]:
                target = target[part]
            target[trail[-1]] = choice
            invalid.append(candidate)

    walk(HEALTH_SCHEMA, health)
    result = subprocess.run(['node', 'tests/test_delivery_frontend_contract.js'], cwd=ROOT,
        input=json.dumps({'valid': valid, 'invalid': invalid}), text=True,
        capture_output=True, timeout=20, check=True)
    assert json.loads(result.stdout) == {'valid': len(valid), 'invalid': len(invalid), 'precision': True}


def test_shipped_health_reason_registry_matches_backend():
    source = (ROOT / 'dns_frontend.js').read_text()
    registry = source.split('const reasons = new Set([', 1)[1].split(']);', 1)[0]
    assert set(re.findall(r"'([a-z_]+)'", registry)) == set(REASONS)
