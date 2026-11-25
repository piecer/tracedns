"""Published examples stay bound to actual parser/config/CLI contracts; no I/O."""
import base64
import json
from pathlib import Path
import re

import pytest

from local_ai.contracts import AIError, load_request
from local_ai.service import LocalAIService

ROOT = Path(__file__).resolve().parents[1]


def examples():
    text = (ROOT / 'docs/LOCAL_AI.md').read_text()
    return [json.loads(block) for block in re.findall(r'```json\n(.*?)\n```', text, re.S)]


def test_all_documented_requests_pass_actual_closed_parser_and_sample_encodings():
    values = [value for value in examples() if 'kind' in value]
    assert {value['kind'] for value in values} == {'decoder_suggest', 'relationship_pair', 'delivery'}
    for value in values:
        assert load_request(json.dumps(value).encode()) == value
        if value['kind'] == 'decoder_suggest':
            for sample in value['samples']:
                assert base64.b64decode(sample['data'], validate=True).decode() == sample['expected_ips'][0]


def test_documented_disabled_startup_needs_no_model_or_network(monkeypatch):
    from local_ai import provider
    monkeypatch.setattr(provider.socket, 'socket', lambda *a, **k: pytest.fail('configuration caused network I/O'))
    settings = next(value['local_ai'] for value in examples() if value.get('local_ai', {}).get('enabled') is False)
    service = LocalAIService(settings, object(), object())
    service.start()
    with pytest.raises(AIError, match='disabled'):
        service.submit({'kind': 'delivery', 'language': 'en'}, {})
    assert service.close()['complete']
    placeholder = next(value['local_ai'] for value in examples() if value.get('local_ai', {}).get('enabled') is True)
    with pytest.raises(AIError, match='invalid_request'):
        LocalAIService(placeholder, object(), object())


def test_documented_recovery_flags_exist_without_opening_a_database(monkeypatch, capsys):
    from local_ai import recover
    monkeypatch.setattr(recover, 'SecurityStore', lambda *a, **k: pytest.fail('help opened a database'))
    with pytest.raises(SystemExit) as exited:
        recover.main(['--help'])
    assert exited.value.code == 0
    help_text = capsys.readouterr().out
    guide = (ROOT / 'docs/LOCAL_AI.md').read_text()
    for flag in ('--security-db', '--job-id', '--confirm-tracedns-stopped', '--confirm-provider-stopped'):
        assert flag in help_text and flag in guide


def test_bilingual_readmes_preserve_identical_executable_examples():
    pattern = r'```(?:bash|json|python)\n(.*?)\n```'
    english = re.findall(pattern, (ROOT / 'README.md').read_text(), re.S)
    korean = re.findall(pattern, (ROOT / 'README.ko.md').read_text(), re.S)
    assert english and english == korean
    for name in ('README.md', 'README.ko.md'):
        assert 'docs/LOCAL_AI.md' in (ROOT / name).read_text()


def test_documented_compatible_settings_patch_is_pure_and_key_is_write_only(monkeypatch):
    import socket
    import jsonschema
    from http_api.ai_settings_schema import REQUEST_SCHEMA
    from local_ai.provider_settings import merge_settings, public_settings
    monkeypatch.setattr(socket, 'socket', lambda *a, **k: pytest.fail('documentation caused network I/O'))
    requests = [v for v in examples() if 'settings' in v]
    assert len(requests) == 1
    request = requests[0]
    jsonschema.Draft202012Validator(REQUEST_SCHEMA).validate(request)
    settings = merge_settings(None, request['settings'])
    assert settings['provider'] == 'openai_compatible'
    assert settings['endpoint_policy'] == 'public_https'
    assert settings['token_limit_field'] == 'max_completion_tokens'
    public = public_settings(settings)
    assert public['configured']['api_key'] is True and 'api_key' not in public
    assert settings['api_key'] not in json.dumps(public)
    guide = (ROOT / 'docs/LOCAL_AI.md').read_text()
    for token in ('/ai/settings', '#settings-ai', 'clear_fields', 'config_revision_conflict',
                  'provider_auth_failed', 'provider_request_rejected', 'provider_rate_limited',
                  'requested_model', 'reported_model', 'store=false'):
        assert token in guide
    assert 'settings are startup-only' not in guide
