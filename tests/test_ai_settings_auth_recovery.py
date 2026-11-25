"""Real auth recovery must restore explicit Load, not load or save a draft."""
import importlib
import json
from pathlib import Path
import subprocess

import pytest

from ai_settings_ui_fixture import produce
from test_ai_settings_api import app as app

ROOT = Path(__file__).resolve().parents[1]
BROWSER = Path(__file__).with_name('ai_settings_auth_recovery_browser.js')


def test_ai_settings_auth_recovery(app, tmp_path):
    origins = {}
    for name in ('http_server', 'http_api_handlers', 'http_api.ai_settings',
                 'local_ai.service', 'security.http', 'security.store'):
        source = Path(importlib.import_module(name).__file__).resolve()
        assert source == ROOT / (name.replace('.', '/') + '.py')
        origins[name] = str(source)
    command = ['node', str(BROWSER), 'browser', str(ROOT),
               f'http://127.0.0.1:{app.client.port}', str(tmp_path)]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=80)
    (tmp_path / 'execution.json').write_text(json.dumps({
        'command': command, 'exit': result.returncode, 'origins': origins,
        'stdout': result.stdout, 'stderr': result.stderr,
    }, indent=2))
    assert result.returncode == 0, result.stdout + result.stderr
    assert app.config['config_revision'] == 0
    assert not Path(app.core.service.config_path).exists()
    assert not app.native_requests


def test_ai_settings_auth_readiness_subscribers():
    result = subprocess.run(['node', str(BROWSER), 'subscribers', str(ROOT)],
                            cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('owner', ['viewer', 'operator', 'unknown', 'password',
                                  'invalidated', 'logout', 'retired', 'disconnected',
                                  'draft-pending-save', 'malformed-receipt'])
def test_ai_settings_recovery_owner_fences(owner):
    """Extracted shipped panel, controlled auth events, real pure receipt producer."""
    stored = {'enabled': False, 'provider': 'openai_compatible',
              'base_url': 'http://127.0.0.1:9/v1', 'model': 'fixture-model',
              'endpoint_policy': 'loopback', 'api_key': 'SYNTHETIC-RECOVERY-SAVED'}
    submitted = {**stored, 'model': 'submitted-model', 'api_key': 'SYNTHETIC-RECOVERY-A'}
    receipts = {'get': json.loads(produce({'stored': stored, 'revision': 7})['wire']),
                'post': json.loads(produce({'stored': stored, 'revision': 7,
                                           'patch': submitted})['wire'])}
    result = subprocess.run(['node', str(BROWSER), 'owner-' + owner, str(ROOT)],
                            input=json.dumps(receipts), cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
