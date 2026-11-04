"""Versioned closed schema: real serializer bytes through shipped JS decoder."""
import copy
import http.client
import json
import os
from pathlib import Path
import subprocess

from jsonschema import Draft7Validator

from http_api.delivery_health import HEALTH_SCHEMA, MAX_COUNTER, PROGRESS_SCHEMA, _project
from test_stage3_core_runtime import app_factory

import test_delivery_health_http

delivery_app = test_delivery_health_http.delivery_app


def test_extended_wire_mutations_and_maximum(delivery_app, tmp_path):
    client, cached = delivery_app
    app = app_factory(tmp_path / 'ledger')
    try:
        baseline = app.delivery.health_snapshot(include_progress=True)
    finally:
        app.delivery.stop()
    cached.return_value = baseline
    assert client.login()[0] == 200
    code, actual = client.call('GET', '/api/v1/delivery-health?progress=1')
    assert code == 200
    assert actual == baseline
    Draft7Validator(PROGRESS_SCHEMA).validate(actual)
    cached.assert_called_with(include_progress=True)
    corpus = [{'wire': json.dumps(actual), 'accept': True}]
    def mutated(trail, value=None, delete=False):
        candidate = copy.deepcopy(actual)
        target = candidate
        for name in trail[:-1]:
            target = target[name]
        if delete:
            del target[trail[-1]]
        else:
            target[trail[-1]] = value
        return candidate
    def walk(schema, trail=()):
        if schema['type'] == 'object':
            extra = mutated((*trail, 'foreign'), 'PRIVATE-CANARY')
            corpus.append({'wire': json.dumps(extra), 'accept': False})
            for name, child in schema['properties'].items():
                corpus.append({'wire': json.dumps(mutated((*trail,name), delete=True)), 'accept': False})
                walk(child, (*trail,name))
        else:
            for value in (None, True, False, -1, 0.5, 'PRIVATE-CANARY', [], {}, MAX_COUNTER + 1):
                candidate = mutated(trail, value)
                accepted = Draft7Validator(PROGRESS_SCHEMA).is_valid(candidate)
                corpus.append({'wire': json.dumps(candidate), 'accept': accepted})
            for value in schema.get('enum', []):
                corpus.append({'wire': json.dumps(mutated(trail,value)), 'accept': True})
    walk(PROGRESS_SCHEMA)
    for item in corpus:
        try:
            _project(json.loads(item['wire']), PROGRESS_SCHEMA, strict=True)
            accepted = True
        except (ValueError, KeyError, TypeError):
            accepted = False
        assert accepted == item['accept'], item['wire']
    def maximum(schema):
        if schema['type'] == 'object':
            return {name: maximum(child) for name,child in schema['properties'].items()}
        if 'enum' in schema:
            return max(schema['enum'], key=lambda v: len(str(v)))
        if schema['type'] == 'boolean':
            return False
        return MAX_COUNTER
    extreme = maximum(PROGRESS_SCHEMA)
    cached.return_value = extreme
    connection = http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)
    try:
        connection.request('GET', '/delivery-health?progress=1', headers={
            'Cookie': '; '.join(f'{k}={v}' for k,v in client.cookies.items())})
        response = connection.getresponse()
        wire = response.read()
        assert response.status == 200 and len(wire) <= 4096
        assert int(response.getheader('Content-Length')) == len(wire)
        assert json.loads(wire) == extreme
        corpus.append({'wire': wire.decode(), 'accept': True, 'contains': ['precision unavailable']})
    finally:
        connection.close()
    result = subprocess.run(['node', 'tests/test_delivery_progress_frontend.js'],
        cwd=Path(__file__).resolve().parents[1], input=json.dumps(corpus), text=True,
        capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['cases'] == len(corpus)
    evidence = Path(os.environ.get('STAGE4_EVIDENCE_OUT', str(tmp_path / 'evidence')))
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / 'producer-corpus.json').write_text(json.dumps(corpus, indent=2) + '\n')
    (evidence / 'maximum-wire.json').write_bytes(wire)
    (evidence / 'contract.json').write_text(json.dumps({'cases': len(corpus), 'maximum_bytes': len(wire), 'node': json.loads(result.stdout)}) + '\n')
    # The real serializer must also reject a wrong integer version, not just JS.
    cached.return_value = {**baseline, 'progress_version': 2}
    assert client.call('GET', '/delivery-health?progress=1')[0] == 503
    for path in ('/delivery-health', '/api/v1/delivery-health'):
        for selector in ('progress=', 'progress=0', 'progress=2', 'progress=true', 'progress=1&progress=1'):
            assert client.call('GET', path + '?' + selector)[0] == 400
    cached.return_value = {**baseline, 'private_extra': 'PRIVATE-CANARY'}
    assert client.call('GET', '/delivery-health?progress=1')[0] == 503
    assert _project(baseline, HEALTH_SCHEMA) == {k: baseline[k] for k in HEALTH_SCHEMA['properties']}
    _, document = client.call('GET', '/api/v1/openapi.json')
    operation = document['paths']['/delivery-health']['get']
    assert operation['responses']['200']['content']['application/json']['schema'] == {'oneOf': [HEALTH_SCHEMA, PROGRESS_SCHEMA]}
    assert any(p['name'] == 'progress' for p in operation['parameters'])
