"""Post-replacement AI owner publication must fail closed before unlock."""
import json
from pathlib import Path

from test_ai_settings_api import app as app_fixture
from test_local_ai_application import wait_job

app = app_fixture


def test_owner_publication_failure_cannot_admit_after_persisted_disable(app, monkeypatch):
    code, first = app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})
    assert code == 200
    owner = app.handler.local_ai
    workers = (owner._worker, owner._maintenance_worker)
    calls = []

    def fail_publication(*args):
        calls.append(True)
        raise RuntimeError('SYNTHETIC owner publication fault')

    monkeypatch.setattr(owner, 'configuration_committed', fail_publication)
    code, saved = app.client.call('POST', '/ai/settings',
                                  {'revision': first['revision'], 'settings': {'enabled': False}})
    persisted = json.loads(Path(app.core.service.config_path).read_text())
    assert calls == [True] and persisted['local_ai']['enabled'] is False
    get_code, loaded = app.client.call('GET', '/ai/settings')
    status_code, status = app.client.call('GET', '/ai/status')
    admitted, job = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
    if admitted == 202:  # Observe predecessor's complete real controlled effect before refusing it.
        wait_job(app.client, '/ai/jobs/' + job['job_id'])
    assert app.native_requests == [], 'persisted disable lost its admission fence after publication failure'
    assert admitted == 503 and job['code'] == 'disabled'
    assert status_code == 200 and not status['accepting']
    assert get_code == 200 and loaded['runtime'] == {'applied': False, 'state': 'unavailable'}
    assert code == 200 and saved['warnings'] == ['ai_runtime_apply_failed']
    assert saved['revision'] == persisted['config_revision'] == loaded['revision']
    assert 'SYNTHETIC' not in json.dumps(saved)
    assert (owner._worker, owner._maintenance_worker) == workers
