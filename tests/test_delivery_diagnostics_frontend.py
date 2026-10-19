"""Node executes the shipped diagnostics parser/renderer/lifecycle, no providers."""
import copy
import json
from pathlib import Path
import subprocess

from http_api.delivery_diagnostics import DIAGNOSTICS_SCHEMA
from test_delivery_diagnostics_http import diagnostics_payload

ROOT = Path(__file__).resolve().parents[1]


def test_diagnostics_frontend():
    base = diagnostics_payload()
    valid, invalid = [base], []

    def variant(trail, value, delete=False):
        candidate = copy.deepcopy(base)
        target = candidate
        for key in trail[:-1]:
            target = target[key]
        if delete:
            del target[trail[-1]]
        else:
            target[trail[-1]] = value
        return candidate

    def walk(schema, value, trail=()):
        kind = schema['type']
        if isinstance(kind, list):
            valid.append(variant(trail, None))
            kind = kind[0]
        if kind == 'object':
            for key, child in schema['properties'].items():
                invalid.append(variant((*trail, key), None, delete=True))
                walk(child, value[key], (*trail, key))
            invalid.append(variant((*trail, 'PRIVATE-CANARY'), '<img onerror=alert(1)>'))
        elif kind == 'array':
            valid.append(variant(trail, []))
            valid.append(variant(trail, [value[0]] * schema['maxItems']))
            invalid.append(variant(trail, [value[0]] * (schema['maxItems'] + 1)))
            walk(schema['items'], value[0], (*trail, 0))
        else:
            choices = ['PRIVATE-CANARY', [], {}]
            if 'enum' in schema:
                for item in schema['enum']:
                    valid.append(variant(trail, item))
                choices += [False, 1]
            elif kind == 'integer':
                for item in (schema['minimum'], schema['maximum']):
                    valid.append(variant(trail, item))
                choices += [True, -1, 2**63, 1.5]
                if schema['maximum'] < 2**63 - 1:
                    choices += [schema['maximum'] + 1]
            elif kind == 'boolean':
                valid.extend([variant(trail, True), variant(trail, False)])
                choices += [0, 1]
            for item in choices:
                invalid.append(variant(trail, item))
    walk(DIAGNOSTICS_SCHEMA, base)
    result = subprocess.run(['node', 'tests/test_delivery_diagnostics_frontend.js'],
                            cwd=ROOT, input=json.dumps(dict(fixture=base, valid=[json.dumps(v) for v in valid],
                                                  invalid=[json.dumps(v) for v in invalid])),
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
