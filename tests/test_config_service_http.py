"""Authenticated legacy/v1 mutation parity through a real local HTTP server."""
import json
from unittest.mock import patch

import pytest

import decoder_registry
from test_http_auth_integration import app as http_app

app = http_app


@pytest.fixture(autouse=True)
def restore_registry():
    view = decoder_registry.snapshot_registry()
    yield
    decoder_registry.publish(view)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_authenticated_decoder_cas_and_config_settings_share_revision(app, prefix, kind):
    store, client, config = app
    assert client.login()[0] == 200
    path = prefix + '/decoders/custom'
    data = {'name': 'http_atomic', 'decoder_type': kind, 'steps': [{'op': 'ascii'}]}
    for method in ('POST', 'PUT', 'DELETE'):
        for revision in (None, '0', False, -1, 9):
            body = dict(data)
            if revision is not None:
                body['revision'] = revision
            code, result = client.call(method, path, body)
            assert code == 409, (method, revision, result)
            assert result['revision'] == 0
    assert client.call('POST', path, {**data, 'revision': 0}, csrf=False)[0] == 403
    code, created = client.call('POST', path, {**data, 'revision': 0})
    assert code == 200 and created['revision'] == created['catalog']['revision'] == 1
    assert client.call('POST', path, {**data, 'revision': 1})[0] == 400
    code, catalog = client.call('GET', prefix + '/decoders')
    assert code == 200 and catalog == created['catalog']
    code, preview = client.call('POST', path + '/preview', {**data, 'sample': '1.2.3.4'})
    assert code == 200 and preview['status'] == 'ok'
    assert config['_config_revision'] == 1
    with patch('alerts.init_from_alerts'), patch('http_api.settings_handlers.set_api_key'):
        code, settings = client.call('POST', prefix + '/settings', {'revision': 1, 'alerts': {}})
    assert code == 200 and settings['revision'] == 2
    assert client.call('PUT', path, {**data, 'revision': 1})[0] == 409
    code, updated = client.call('PUT', path, {**data, 'revision': 2})
    assert code == 200 and updated['revision'] == 3
    code, saved = client.call('POST', prefix + '/config', {'revision': 3, 'interval': 99})
    assert code == 200 and saved['revision'] == 4
    # DELETE requires revision, but no steps.
    code, deleted = client.call('DELETE', path, {'name': data['name'], 'decoder_type': kind, 'revision': 4})
    assert code == 200 and deleted['revision'] == 5
    assert all(d['name'] != data['name'] for d in deleted['catalog']['custom_all'])
    assert client.call('GET', '/config')[1]['revision'] == 5
    assert config['_config_revision'] == config['config_revision'] == 5
    events = store.audit_list(limit=100)['events']
    assert any(e['outcome'] == 'success' for e in events)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
def test_decoder_http_write_failure_is_sanitized_and_keeps_catalog(app, tmp_path, prefix):
    _, client, config = app
    assert client.login()[0] == 200
    config['_config_service'].config_path = str(tmp_path / 'committed.json')
    data = {'name': 'persisted', 'steps': [{'op': 'ascii'}], 'revision': 0}
    assert client.call('POST', prefix + '/decoders/custom', data)[0] == 200
    before = client.call('GET', prefix + '/decoders')[1]
    with patch('config_manager.os.replace', side_effect=OSError('private filesystem path')):
        code, result = client.call('PUT', prefix + '/decoders/custom',
            {**data, 'revision': 1, 'steps': [{'op': 'base64'}]})
    # Preserve the existing security envelope for all server-side failures.
    assert code == 500 and result['error'] == 'Service unavailable'
    assert result['request_id']
    assert 'private filesystem path' not in json.dumps(result)
    assert client.call('GET', prefix + '/decoders')[1] == before



def test_decoder_openapi_requires_revision_in_mutations_but_not_preview():
    from http_api.openapi import openapi_document
    schema = openapi_document()['paths']
    for method in ('post', 'put', 'delete'):
        operation = schema['/decoders/custom'][method]
        body = operation['requestBody']['content']['application/json']['schema']
        assert 'revision' in body['required']
        assert ('steps' in body['required']) == (method != 'delete')
        response = operation['responses']['200']['content']['application/json']['schema']
        assert {'revision', 'catalog', 'warnings'} <= set(response['required'])
    preview = schema['/decoders/custom/preview']['post']['requestBody']['content']['application/json']['schema']
    assert 'revision' not in preview['required']
    catalog = schema['/decoders']['get']['responses']['200']['content']['application/json']['schema']
    assert 'revision' in catalog['required']
