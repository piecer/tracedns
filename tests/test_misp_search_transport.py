"""MISP transport contracts through authenticated HTTP; no provider traffic."""
from unittest.mock import Mock
from pathlib import Path

import pytest
import requests
from requests.certs import where

from test_http_auth_integration import app as http_app

app = http_app


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('method', ['GET', 'POST'])
@pytest.mark.parametrize('ca', ['default', 'private', 'invalid'])
def test_misp_search_verifies_tls_on_every_route(app, monkeypatch, tmp_path, prefix, method, ca):
    _, client, config = app
    config['alerts'] = {'misp_url': 'https://misp.invalid', 'api_key': 'fixture-key'}
    expected_verify = True
    if ca != 'default':
        bundle = tmp_path / 'private-ca-marker.pem'
        if ca == 'private':
            bundle.write_bytes(Path(where()).read_bytes())
        config['alerts']['misp_ca_bundle'] = str(bundle)
        expected_verify = str(bundle)
    response = Mock(status_code=200, ok=True, content=b'{}')
    response.json.return_value = {'response': {'Attribute': []}}
    upstream = Mock(return_value=response)
    monkeypatch.setattr(requests, 'post', upstream)
    assert client.login()[0] == 200
    path = prefix + '/misp/search'
    if method == 'GET':
        code, result = client.call(method, path + '?value=192.0.2.1')
    else:
        code, result = client.call(method, path, {'value': '192.0.2.1'})
    if ca == 'invalid':
        assert code == 500, result
        assert 'private-ca-marker' not in str(result)
        upstream.assert_not_called()
        return
    assert code == 200, result
    assert upstream.call_count == 1
    assert upstream.call_args.kwargs['verify'] == expected_verify


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('method', ['GET', 'POST'])
@pytest.mark.parametrize('failure', ['exception', 'http', 'non_json', 'redirect'])
def test_misp_search_failures_do_not_expose_upstream_details(
        app, monkeypatch, capsys, caplog, prefix, method, failure):
    _, client, config = app
    config['alerts'] = {'misp_url': 'https://misp.invalid/endpoint-private-marker',
                        'api_key': 'fixture-key'}
    response = Mock(status_code=200, ok=True, text='private-upstream-detail', content=b'private-upstream-detail')
    response.json.return_value = {'response': {'Attribute': []}}
    upstream = Mock(return_value=response)
    if failure == 'exception':
        upstream.side_effect = requests.exceptions.SSLError('private-upstream-detail')
    elif failure == 'http':
        response.status_code, response.ok = 503, False
    elif failure == 'non_json':
        response.json.side_effect = ValueError('private-upstream-detail')
    else:
        response.status_code = 302
    monkeypatch.setattr(requests, 'post', upstream)
    assert client.login()[0] == 200
    value = 'analyst-query-marker.example'
    path = prefix + '/misp/search'
    code, result = client.call(method, path + ('?value=' + value if method == 'GET' else ''),
                               {'value': value} if method == 'POST' else None)
    assert code == 500, result
    captured = capsys.readouterr()
    surfaced = str(result) + captured.out + captured.err + caplog.text
    for marker in ('private-upstream-detail', 'endpoint-private-marker', value):
        assert marker not in surfaced
    assert upstream.call_args.kwargs['allow_redirects'] is False
