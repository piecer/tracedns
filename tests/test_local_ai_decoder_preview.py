"""Custom preview must execute the same single-record contract as saved decoders."""
import base64
import copy
import io
import json
import threading

import pytest

import a_decoder
import decoder_registry
import txt_decoder
from http_api.context import HttpContext
from http_api.decoder_crud import handle_decoders_custom_preview


class PreviewResponse:
    def __init__(self, payload):
        raw = json.dumps(payload).encode('utf-8')
        self.headers = {'Content-Length': str(len(raw))}
        self.rfile = io.BytesIO(raw)
        self.wfile = io.BytesIO()
        self.status = None

    def send_response(self, code):
        self.status = code

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass


@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_preview_matches_real_single_record_factory_without_mutation(tmp_path, kind):
    expected = '192.0.2.10'
    if kind == 'TXT':
        sample = base64.b64encode(expected.encode('ascii')).decode('ascii')
        steps = [{'op': 'base64'}, {'op': 'ascii'}]
        factory = txt_decoder.create_custom_decoder
    else:
        sample = expected
        steps = [{'op': 'xor32_ipv4', 'key': '00000000'}]
        factory = a_decoder.create_custom_a_decoder
    decoder = factory(steps)
    assert decoder is not None
    reference = decoder([sample])
    assert reference == [expected], 'positive control must reach the real decoder'
    config = {'custom_decoders': [], 'custom_a_decoders': [], '_config_revision': 7}
    original_config = copy.deepcopy(config)
    original_registry = decoder_registry.snapshot_registry()
    config_path = tmp_path / 'config.json'
    context = HttpContext(
        frontend_html='', shared_config=config, config_lock=threading.RLock(),
        config_path=str(config_path), history_dir=str(tmp_path),
        current_results={}, history={}, purge_removed_domains_state=lambda *args: None,
    )
    response = PreviewResponse({'decoder_type': kind, 'steps': steps, 'sample': sample})
    handle_decoders_custom_preview(context, response)
    result = json.loads(response.wfile.getvalue())
    assert response.status == 200
    assert result['decoded'] == reference
    assert result['decoded_count'] == len(reference)
    assert config == original_config
    assert not config_path.exists()
    current_registry = decoder_registry.snapshot_registry()
    assert dict(current_registry.txt) == dict(original_registry.txt)
    assert dict(current_registry.a) == dict(original_registry.a)


@pytest.fixture
def preview_context(tmp_path):
    return HttpContext(
        frontend_html='', shared_config={'_config_revision': 7}, config_lock=threading.RLock(),
        config_path=str(tmp_path / 'unchanged.json'), history_dir=str(tmp_path),
        current_results={}, history={}, purge_removed_domains_state=lambda *args: None,
    )


@pytest.mark.parametrize('payload,code', [
    ([], 400), (None, 400),
    ({'sample': 123}, 400), ({'sample': None}, 400), ({'sample': ['192.0.2.1']}, 400),
    ({'sample': 'x' * 2049}, 413), ({'sample': '\u00e9' * 1025}, 413),
    ({'sample': '\ud800'}, 400),
    ({'decoder_type': 'ENS', 'sample': ''}, 400),
    ({'decoder_type': None, 'sample': ''}, 400),
    ({'decoder_type': 123, 'sample': ''}, 400),
    ({'steps': [{'op': 'ascii'}] * 13, 'sample': ''}, 400),
    ({'steps': [{'op': 'made_up'}], 'sample': ''}, 400),
    ({'steps': [{'op': 'regex', 'pattern': '(a+)+$'}], 'sample': ''}, 400),
    ({'steps': [{'op': 'xor_hex', 'key': 'ab' * 65}], 'sample': ''}, 400),
])
def test_preview_rejects_without_config_or_registry_mutation(preview_context, payload, code):
    if isinstance(payload, dict):
        payload = {'steps': [{'op': 'ascii'}], **payload}
    before = decoder_registry.snapshot_registry()
    original = copy.deepcopy(preview_context.shared_config)
    response = PreviewResponse(payload)
    handle_decoders_custom_preview(preview_context, response)
    assert response.status == code
    assert json.loads(response.wfile.getvalue())['decoded'] == []
    assert preview_context.shared_config == original
    assert decoder_registry.snapshot_registry() == before
    from pathlib import Path
    assert not Path(preview_context.config_path).exists()


@pytest.mark.parametrize('sample', ['', '   ', '\u00e9' * 1024])
def test_preview_preserves_raw_input_and_valid_empty_behavior(preview_context, monkeypatch, sample):
    seen = []
    def factory(steps):
        def decode(values):
            seen.append(values)
            return []
        return decode
    monkeypatch.setattr(txt_decoder, 'create_custom_decoder', factory)
    response = PreviewResponse({'steps': [{'op': 'ascii'}], 'sample': sample})
    handle_decoders_custom_preview(preview_context, response)
    assert response.status == 200
    assert seen == ([] if sample == '' else [[sample]])


def test_preview_sanitizes_factory_exception(preview_context, monkeypatch):
    def factory(steps):
        raise RuntimeError('private source /secret/path')
    monkeypatch.setattr(txt_decoder, 'create_custom_decoder', factory)
    response = PreviewResponse({'steps': [{'op': 'ascii'}], 'sample': '192.0.2.1'})
    handle_decoders_custom_preview(preview_context, response)
    assert response.status == 400
    assert b'private source' not in response.wfile.getvalue()


@pytest.fixture
def http_preview_app(tmp_path):
    # Real route/security/REST adapters, private loopback server and account DB.
    from test_http_auth_integration import app
    yield from app.__wrapped__(tmp_path)


@pytest.mark.parametrize('prefix', ['', '/api/v1'])
@pytest.mark.parametrize('kind', ['TXT', 'A'])
def test_real_legacy_and_versioned_preview_keeps_catalog_and_revision(http_preview_app, tmp_path, prefix, kind):
    _, client, config = http_preview_app
    assert client.login()[0] == 200
    before = client.call('GET', prefix + '/decoders')[1]
    service = config['_config_service']
    service.config_path = str(tmp_path / 'must-not-be-written.json')
    view = decoder_registry.snapshot_registry()
    if kind == 'TXT':
        sample = base64.b64encode(b'192.0.2.10:443').decode()
        # Retained manual/legacy ignored fields, not the strict generated DSL.
        steps = [{'op': 'base64', 'key': 'data'}, {'op': 'extract_ip_prefix', 'key': 'expected_ip'}]
        factory = txt_decoder.create_custom_decoder
    else:
        sample = '192.0.2.10'
        steps = [{'op': 'xor32_ipv4', 'key_hex': 0}]
        factory = a_decoder.create_custom_a_decoder
    reference = factory(steps)([sample])
    assert reference == ['192.0.2.10']
    code, result = client.call('POST', prefix + '/decoders/custom/preview',
                               {'decoder_type': kind, 'steps': steps, 'sample': sample})
    assert code == 200 and result['decoded'] == reference and result['decoded_count'] == 1
    for invalid in ({'sample': None}, {'sample': 'x' * 2049}, {'sample': '', 'steps': [{'op': 'exec'}]}):
        code, _ = client.call('POST', prefix + '/decoders/custom/preview',
                              {'decoder_type': kind, 'steps': steps, **invalid})
        assert code == (413 if invalid.get('sample') == 'x' * 2049 else 400)
    assert client.call('GET', prefix + '/decoders')[1] == before
    assert decoder_registry.snapshot_registry() == view
    assert not (tmp_path / 'must-not-be-written.json').exists()
