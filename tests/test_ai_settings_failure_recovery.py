"""Persistence and retirement failures through the authenticated application.

Promoted reviewer schedules; real tasks, leases, persistence and native peer.
"""
import json
from pathlib import Path
import threading

import pytest

from test_ai_settings_api import app as app_fixture
from test_http_auth_integration import Client
from test_local_ai_application import wait_job

app = app_fixture


def record(tmp_path, name, value):
    (tmp_path / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


@pytest.mark.parametrize('phase', ['before_replace', 'after_replace'])
def test_persistence_failure_keeps_disable_truthful_and_fenced(app, monkeypatch, tmp_path, phase):
    import config_manager
    original = config_manager.write_config
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    previous = Path(app.core.service.config_path).read_bytes()

    def write(path, candidate):
        if phase == 'after_replace':
            original(path, candidate)
        raise OSError('SYNTHETIC write acknowledgement failure')

    monkeypatch.setattr(config_manager, 'write_config', write)
    code, saved = app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})
    disk = json.loads(Path(app.core.service.config_path).read_text())
    read_code, loaded = app.client.call('GET', '/ai/settings')
    admission, job = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
    result = wait_job(app.client, '/ai/jobs/' + job['job_id']) if admission == 202 else job
    observed = {'phase': phase, 'post_status': code, 'post': saved,
                'disk_revision': disk['config_revision'], 'disk_enabled': disk['local_ai']['enabled'],
                'read_status': read_code, 'read_revision': loaded.get('revision'),
                'read_enabled': loaded.get('settings', {}).get('enabled'), 'runtime': loaded.get('runtime'),
                'admission_status': admission, 'job_status': result.get('status'), 'job_error': result.get('code'),
                'native_paths': [r['path'] for r in app.native_requests]}
    record(tmp_path, 'persistence-' + phase, observed)
    if phase == 'before_replace':
        assert Path(app.core.service.config_path).read_bytes() == previous
        assert code == 500 and saved['code'] == 'config_save_failed'
        assert loaded['revision'] == 1 and loaded['settings']['enabled'] is True
        assert admission == 202 and result['status'] == 'completed'
    else:
        assert disk['config_revision'] == 2 and disk['local_ai']['enabled'] is False
        assert admission != 202 and not app.native_requests, observed
        assert loaded['revision'] == 2 and loaded['settings']['enabled'] is False, observed
        assert saved.get('code') != 'config_save_failed', observed


def new_operator(app, name):
    password = 'review-fixture-password'
    assert app.client.call('POST', '/admin/users', {'username': name, 'password': password, 'role': 'operator'})[0] == 201
    client = Client(app.client.port)
    assert client.login(name, password)[0] == 200
    assert client.call('POST', '/auth/password', {'current_password': password, 'new_password': password + '-changed'})[0] == 200
    assert client.login(name, password + '-changed')[0] == 200
    return client


@pytest.mark.parametrize('fault', [False, True])
def test_one_dispose_fault_cannot_lose_retired_queue_ownership(app, monkeypatch, tmp_path, fault):
    from local_ai.engine import PreparedTask
    from local_ai.service import LocalAIService
    owner = app.handler.local_ai
    worker_gate, maintenance_gate = threading.Event(), threading.Event()
    entered_worker, entered_maintenance = threading.Event(), threading.Event()
    work, maintenance, dispose = LocalAIService._work, LocalAIService._maintenance, PreparedTask.dispose
    calls = []

    def blocked_work(self):
        entered_worker.set()
        assert worker_gate.wait(20), 'review must release actual worker'
        return work(self)

    def blocked_maintenance(self):
        entered_maintenance.set()
        assert maintenance_gate.wait(20), 'review must release actual maintenance'
        return maintenance(self)

    def one_dispose_error(self):
        calls.append(type(self).__name__)
        if fault and len(calls) == 1:
            raise OSError('SYNTHETIC one-shot task cleanup callback failure')
        return dispose(self)

    monkeypatch.setattr(LocalAIService, '_work', blocked_work)
    monkeypatch.setattr(LocalAIService, '_maintenance', blocked_maintenance)
    clients = [app.client, new_operator(app, 'reviewop1'), new_operator(app, 'reviewop2')]
    jobs = []
    try:
        assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
        assert entered_worker.wait(2) and entered_maintenance.wait(2)
        for client in clients:
            status, body = client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
            assert status == 202, body
            assert body['status'] == 'queued'
            jobs.append(body)
        monkeypatch.setattr(PreparedTask, 'dispose', one_dispose_error)
        code, disabled = app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})
        assert code == 200, disabled
        # A subsequent ordinary successful save is NOT permitted to clear
        # durable quarantine, but should not strand never-dispatched jobs.
        code, enabled = app.client.call('POST', '/ai/settings', {'revision': 2, 'settings': {'enabled': True}})
        assert code == 200, enabled
        worker_gate.set()
        maintenance_gate.set()
        status_code, status = app.client.call('GET', '/ai/status')
        admission, next_job = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
        next_terminal = wait_job(app.client, '/ai/jobs/' + next_job['job_id']) if admission == 202 else next_job
        events = app.store.audit_list(action='llm.lifecycle', limit=1000)['events']
        phases = [[e['outcome'] for e in reversed(events) if e['job_id'] == job['job_id']] for job in jobs]
        with owner._lock:
            retained_users = len(owner._users)
            old_pending = [j.job_id for j in owner._jobs.values() if j.job_id in {j['job_id'] for j in jobs}
                           and j.audit_status == 'pending']
        closed = owner.close()
        observed = {'fault': fault, 'dispose_callback_count': len(calls), 'disabled_receipt': disabled,
                    'reenabled_receipt': enabled, 'status_http': status_code, 'status': status,
                    'successor_admission': admission, 'successor_outcome': next_terminal.get('status'),
                    'successor_error': next_terminal.get('code'), 'original_audit_phases': phases,
                    'retained_users': retained_users, 'old_pending_jobs': old_pending,
                    'close': closed, 'native_paths': [r['path'] for r in app.native_requests]}
        record(tmp_path, 'retirement-dispose-' + str(fault).lower(), observed)
        assert all(p == ['started', 'failed'] for p in phases), observed
        assert admission == 202 and next_terminal['status'] == 'completed', observed
        assert retained_users == 0 and not old_pending, observed
    finally:
        worker_gate.set()
        maintenance_gate.set()
        monkeypatch.setattr(PreparedTask, 'dispose', dispose)
        assert owner.close()['complete']
