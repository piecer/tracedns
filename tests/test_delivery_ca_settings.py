"""Private CA settings stay private and reject invalid local paths atomically."""
import json
from pathlib import Path

import pytest
from requests.certs import where

from test_http_auth_integration import app as http_app

app = http_app


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('value', [False, 'private-missing-ca.pem'])
def test_invalid_ca_settings_preserve_revision_and_config(app, prefix, value):
    _, client, config = app
    assert client.login()[0] == 200
    before = dict(config.get('alerts', {}))
    code, result = client.call('POST', prefix + '/settings',
                              {'revision': 0, 'alerts': {'misp_ca_bundle': value}})
    assert code == 400, result
    assert config.get('alerts', {}) == before
    assert config.get('_config_revision', 0) == 0
    assert 'private-missing-ca' not in json.dumps(result)


def test_ca_is_redacted_preserved_when_blank_and_explicitly_clearable(app, tmp_path):
    _, client, config = app
    bundle = tmp_path / 'private-ca-path-marker.pem'
    bundle.write_bytes(Path(where()).read_bytes())
    assert client.login()[0] == 200
    code, result = client.call('POST', '/settings',
                              {'revision': 0, 'alerts': {'misp_ca_bundle': str(bundle)}})
    assert code == 200, result
    assert 'private-ca-path-marker' not in json.dumps(result)
    for path in ('/settings', '/api/v1/settings', '/config', '/api/v1/config'):
        code, result = client.call('GET', path)
        assert code == 200
        assert 'private-ca-path-marker' not in json.dumps(result)
    assert client.call('POST', '/settings',
                       {'revision': 1, 'alerts': {'misp_ca_bundle': ''}})[0] == 200
    assert config['alerts']['misp_ca_bundle'] == str(bundle)
    assert client.call('POST', '/settings',
                       {'revision': 2, 'alerts': {}, 'clear_fields': ['misp_ca_bundle']})[0] == 200
    assert 'misp_ca_bundle' not in config['alerts']
