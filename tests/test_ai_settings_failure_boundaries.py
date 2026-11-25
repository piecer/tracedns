"""Failure boundaries around real application persistence and task ownership."""
import json
import os
from contextlib import contextmanager
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from test_ai_settings_api import app as app_fixture
from test_ai_settings_failure_recovery import new_operator
from test_http_auth_integration import Client
from test_local_ai_provider import DIGEST, MODEL, envelope, http_response, peer
from test_stage3_core_runtime import app_factory
from test_local_ai_application import wait_job
from test_local_ai_service import wait_for

app = app_fixture


@pytest.fixture(scope='session', autouse=True)
def source_origins(tmp_path_factory):
    import hashlib
    import importlib
    root = Path(__file__).resolve().parents[1]
    origins = {}
    for name in ('config_manager', 'monitor.config_service', 'local_ai.service', 'local_ai.engine',
                 'local_ai.sources', 'http_api.ai_settings', 'http_server', 'security.store'):
        module = importlib.import_module(name)
        path = Path(module.__file__).resolve()
        assert path == root / (name.replace('.', '/') + '.py')
        origins[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    (tmp_path_factory.mktemp('source-origins') / 'source-origins.json').write_text(json.dumps(origins, indent=2))


@contextmanager
def parked_jobs(app, monkeypatch):
    from local_ai.service import LocalAIService
    gate, entered_worker, entered_maintenance = threading.Event(), threading.Event(), threading.Event()
    work, maintenance = LocalAIService._work, LocalAIService._maintenance

    def blocked_work(self):
        entered_worker.set()
        assert gate.wait(20)
        return work(self)

    def blocked_maintenance(self):
        entered_maintenance.set()
        assert gate.wait(20)
        return maintenance(self)

    with monkeypatch.context() as patch:
        patch.setattr(LocalAIService, '_work', blocked_work)
        patch.setattr(LocalAIService, '_maintenance', blocked_maintenance)
        try:
            clients = [app.client, new_operator(app, 'boundaryop1'), new_operator(app, 'boundaryop2')]
            assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
            assert entered_worker.wait(2) and entered_maintenance.wait(2)
            jobs = []
            for client in clients:
                code, job = client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
                assert code == 202 and job['status'] == 'queued'
                jobs.append(app.handler.local_ai._jobs[job['job_id']])
            yield jobs, gate
        finally:
            gate.set()


def assert_owner_locks_available(app):
    acquired = []

    def observe():
        for lock in (app.handler.local_ai._lock, app.core.service.config_lock):
            ok = lock.acquire(timeout=.5)
            acquired.append(ok)
            if ok:
                lock.release()

    thread = threading.Thread(target=observe)
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and acquired == [True, True]


def phases(app, jobs):
    events = app.store.audit_list(action='llm.lifecycle', limit=1000)['events']
    return [[e['outcome'] for e in reversed(events) if e['job_id'] == job.job_id] for job in jobs]


@pytest.mark.parametrize('boundary', ['task_before', 'task_after', 'lease_before', 'lease_after', 'finish_before', 'finish_after'])
def test_retirement_acknowledges_real_nested_cleanup_and_finalization(app, monkeypatch, boundary):
    from local_ai.engine import PreparedTask
    from local_ai.sources import SourceLease
    owner = app.handler.local_ai
    with parked_jobs(app, monkeypatch) as (jobs, gate), monkeypatch.context() as patch:
        task, lease = jobs[0].task, jobs[0].task._lease
        cls = SourceLease if boundary.startswith('lease') else PreparedTask
        original = owner._finish if boundary.startswith('finish') else cls.dispose
        calls = []

        def dispose(self):
            if self is (lease if cls is SourceLease else task):
                calls.append(True)
                # External cleanup must never run under either owner's lock.
                assert_owner_locks_available(app)
                if len(calls) == 1:
                    if boundary.endswith('after'):
                        original(self)
                    raise OSError('PRIVATE single nested cleanup failure')
            return original(self)

        def finish(job, *args, **kwargs):
            if job is jobs[0]:
                calls.append(True)
                if len(calls) == 1:
                    if boundary == 'finish_after':
                        original(job, *args, **kwargs)
                    raise OSError('PRIVATE terminal acknowledgement failure')
            return original(job, *args, **kwargs)

        patch.setattr(owner if boundary.startswith('finish') else cls,
                      '_finish' if boundary.startswith('finish') else 'dispose',
                      finish if boundary.startswith('finish') else dispose)
        assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})[0] == 200
        # Healthy siblings must already be acknowledged despite the first failure.
        assert phases(app, jobs)[1:] == [['started', 'failed'], ['started', 'failed']]
        code, enabled = app.client.call('POST', '/ai/settings', {'revision': 2, 'settings': {'enabled': True}})
        assert code == 200 and enabled['runtime'] == {'applied': True, 'state': 'ready'}
        assert lease._disposed and lease._ctx is None
        assert task._lease is None and task.retained_bytes == 0
        assert phases(app, jobs) == [['started', 'failed']] * 3
        assert not owner._retirements and not owner._users
        assert 1 <= len(calls) <= 2
        gate.set()
        code, next_job = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
        assert code == 202 and wait_job(app.client, '/ai/jobs/' + next_job['job_id'])['status'] == 'completed'


@pytest.mark.parametrize('after_effect', [False, True])
def test_persistent_cleanup_is_bounded_and_truthfully_retained(retaining_app, monkeypatch, after_effect):
    from local_ai.engine import PreparedTask
    app = retaining_app
    owner = app.handler.local_ai
    with parked_jobs(app, monkeypatch) as (jobs, gate), monkeypatch.context() as patch:
        task = jobs[0].task
        original = PreparedTask.dispose
        calls = []

        def dispose(self):
            if self is task:
                calls.append(True)
                if after_effect:
                    original(self)
                raise OSError('PRIVATE persistent cleanup failure')
            return original(self)

        patch.setattr(PreparedTask, 'dispose', dispose)
        for revision in range(1, 9):
            code, saved = app.client.call('POST', '/ai/settings', {
                'revision': revision, 'settings': {'enabled': revision % 2 == 0}})
            assert code == 200
            assert saved['runtime'] == {'applied': False, 'state': 'unavailable'}
            assert len(owner._retirements) == 1 and jobs[0].task is task
            assert len(calls) <= 2
        assert len(calls) == 2
        assert phases(app, jobs)[1:] == [['started', 'failed'], ['started', 'failed']]
        assert owner._users == {jobs[0].actor['id']: jobs[0]}
        code, status = app.client.call('GET', '/ai/status')
        assert code == 200 and not status['accepting']
        assert app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})[0] != 202
        gate.set()
        assert owner.close() == {'complete': False, 'retained_workers': 0}
        assert owner.close() == {'complete': False, 'retained_workers': 0}
        assert len(calls) == 2 and not app.native_requests


def test_persistent_finalizer_failure_keeps_original_obligation_without_retry_growth(retaining_app, monkeypatch):
    app, calls = retaining_app, []
    owner = app.handler.local_ai
    with parked_jobs(app, monkeypatch) as (jobs, gate), monkeypatch.context() as patch:
        original = owner._finish

        def finish(job, *args, **kwargs):
            if job is jobs[0]:
                calls.append(True)
                raise OSError('PRIVATE persistent finalizer entry failure')
            return original(job, *args, **kwargs)

        patch.setattr(owner, '_finish', finish)
        for revision in range(1, 9):
            code, saved = app.client.call('POST', '/ai/settings', {
                'revision': revision, 'settings': {'enabled': revision % 2 == 0}})
            assert code == 200 and not saved['runtime']['applied']
            assert len(owner._retirements) == 1
        assert len(calls) == 2
        assert phases(app, jobs) == [['started'], ['started', 'failed'], ['started', 'failed']]
        assert owner._users == {jobs[0].actor['id']: jobs[0]}
        gate.set()
        assert owner.close() == {'complete': False, 'retained_workers': 0}
        assert len(calls) == 2


@pytest.mark.parametrize('after_effect', [False, True])
def test_retired_terminal_audit_error_is_sticky_without_duplicate_or_sibling_loss(app, monkeypatch, after_effect):
    owner = app.handler.local_ai
    with parked_jobs(app, monkeypatch) as (jobs, gate), monkeypatch.context() as patch:
        original = app.store.audit_llm_lifecycle
        calls = []

        def audit(job_id, *args, **kwargs):
            assert_owner_locks_available(app)
            if job_id == jobs[0].job_id and kwargs['outcome'] != 'started':
                calls.append(True)
                if after_effect:
                    original(job_id, *args, **kwargs)
                raise OSError('PRIVATE terminal audit failure')
            return original(job_id, *args, **kwargs)

        patch.setattr(app.store, 'audit_llm_lifecycle', audit)
        assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})[0] == 200
        code, saved = app.client.call('POST', '/ai/settings', {'revision': 2, 'settings': {'enabled': True}})
        assert code == 200 and saved['runtime'] == {'applied': False, 'state': 'unavailable'}
        assert phases(app, jobs) == [(['started', 'failed'] if after_effect else ['started']),
                                    ['started', 'failed'], ['started', 'failed']]
        assert jobs[0].audit_status == 'failed' and jobs[0].result is None
        assert calls == [True] and not owner._users and not owner._retirements
        gate.set()
        assert app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})[0] != 202
        assert not app.native_requests


@pytest.mark.parametrize('after_effect', [False, True])
def test_rejected_prepare_keeps_task_custody_until_cleanup_ack(app, monkeypatch, after_effect):
    from local_ai.engine import PreparedTask
    owner = app.handler.local_ai
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    entered, release = threading.Event(), threading.Event()
    original_prepare, original_dispose = owner._engine.prepare, PreparedTask.dispose
    tasks, calls, outcome = [], [], []

    def prepare(*args, **kwargs):
        task = original_prepare(*args, **kwargs)
        tasks.append(task)
        entered.set()
        assert release.wait(4)
        return task

    def dispose(self):
        calls.append(True)
        if len(calls) == 1:
            if after_effect:
                original_dispose(self)
            raise OSError('PRIVATE rejected task cleanup failure')
        return original_dispose(self)

    monkeypatch.setattr(owner._engine, 'prepare', prepare)
    monkeypatch.setattr(PreparedTask, 'dispose', dispose)
    thread = threading.Thread(target=lambda: outcome.append(app.client.call(
        'POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})))
    try:
        thread.start()
        assert entered.wait(2)
        lease = tasks[0]._lease
        assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})[0] == 200
        release.set()
        thread.join(4)
        assert not thread.is_alive() and outcome[0][0] != 202
        # A subsequent public save supplies one bounded cleanup opportunity.
        assert app.client.call('POST', '/ai/settings', {'revision': 2, 'settings': {'enabled': True}})[0] == 200
        assert lease._disposed and tasks[0]._lease is None
        assert not owner._retirements and not owner._users and not owner._preparing
        assert len(calls) == 2 and not app.native_requests
    finally:
        release.set()
        thread.join(4)


@pytest.mark.parametrize('command', ['ai_settings', 'config', 'settings'])
def test_exact_commit_can_be_proven_without_preimage(app, monkeypatch, command):
    import config_manager
    original_read, original_write = config_manager.read_config_image, config_manager.write_config
    reads, writes = [], []

    def read(path):
        reads.append(True)
        if len(reads) == 1:
            raise OSError('PRIVATE preimage observation failure')
        return original_read(path)

    def write(path, candidate):
        writes.append(True)
        original_write(path, candidate)
        raise OSError('PRIVATE acknowledgement failure')

    monkeypatch.setattr(config_manager, 'read_config_image', read)
    monkeypatch.setattr(config_manager, 'write_config', write)
    data = {'ai_settings': {'revision': 0, 'settings': app.native},
            'config': {'interval': 30}, 'settings': {'alerts': {}}}[command]
    result = app.core.service.commit(command, data, expected_revision=0)
    assert result['revision'] == app.core.service.snapshot()['config_revision'] == 1
    assert reads == [True, True] and writes == [True]


@pytest.mark.parametrize('boundary', ['open', 'stat', 'read', 'close_after'])
def test_exact_readback_failure_is_fixed_and_closes_owned_descriptor(app, monkeypatch, boundary):
    import config_manager
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    original_write = config_manager.write_config
    original_open, original_stat = os.open, os.fstat
    original_read, original_close = os.read, os.close
    committed, fds, closed, fired = [], [], [], []

    def write(path, candidate):
        original_write(path, candidate)
        committed.append(True)
        raise OSError('PRIVATE writer acknowledgement')

    def opened(path, flags, *args, **kwargs):
        target = committed and str(path) == app.core.service.config_path
        if target and boundary == 'open':
            fired.append(True)
            raise OSError('PRIVATE readback open')
        fd = original_open(path, flags, *args, **kwargs)
        if target:
            fds.append(fd)
        return fd

    def checked_stat(fd):
        if fd in fds and fd not in closed and boundary == 'stat':
            fired.append(True)
            raise OSError('PRIVATE readback stat')
        return original_stat(fd)

    def read(fd, count):
        if fd in fds and fd not in closed and boundary == 'read':
            fired.append(True)
            raise OSError('PRIVATE readback read')
        return original_read(fd, count)

    def close(fd):
        target = fd in fds and fd not in closed
        original_close(fd)
        if target:
            closed.append(fd)
            if boundary == 'close_after':
                fired.append(True)
                raise OSError('PRIVATE readback close acknowledgement')

    monkeypatch.setattr(config_manager, 'write_config', write)
    monkeypatch.setattr(os, 'open', opened)
    monkeypatch.setattr(os, 'fstat', checked_stat)
    monkeypatch.setattr(os, 'read', read)
    monkeypatch.setattr(os, 'close', close)
    code, saved = app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})
    assert code == 503 and saved['code'] == 'config_storage_unavailable'
    assert fired == [True] and fds == closed
    assert app.client.call('GET', '/ai/settings')[0] == 503
    assert not app.handler.local_ai.source_admission_enabled() and not app.native_requests


def test_inflight_settings_get_cannot_publish_old_ready_after_unknown_outcome(app, monkeypatch):
    import config_manager
    import http_api.ai_settings as settings_module
    entered, release = threading.Event(), threading.Event()
    original_encode, original_write = settings_module.encode_receipt, config_manager.write_config
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    outcome = []

    def encode(*args, **kwargs):
        wire = original_encode(*args, **kwargs)
        if not kwargs['post']:
            entered.set()
            assert release.wait(4)
        return wire

    def write(path, candidate):
        original_write(path, candidate)
        Path(path).write_bytes(b'{')
        raise OSError('PRIVATE unknown outcome')

    monkeypatch.setattr(settings_module, 'encode_receipt', encode)
    monkeypatch.setattr(config_manager, 'write_config', write)
    thread = threading.Thread(target=lambda: outcome.append(app.client.call('GET', '/ai/settings')))
    try:
        thread.start()
        assert entered.wait(2)
        assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})[0] == 503
        release.set()
        thread.join(4)
        assert not thread.is_alive() and outcome[0][0] == 503
        assert 'settings' not in outcome[0][1] and 'revision' not in outcome[0][1]
    finally:
        release.set()
        thread.join(4)


@pytest.mark.parametrize('reason', ['cancel', 'revoke', 'prune', 'shutdown'])
@pytest.mark.parametrize('after_effect', [False, True])
def test_sibling_disposal_owners_recover_one_shot_fault(app, monkeypatch, reason, after_effect):
    from local_ai.engine import PreparedTask
    import local_ai.service as service_module
    owner = app.handler.local_ai
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    code, body = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
    assert code == 202
    assert wait_job(app.client, '/ai/jobs/' + body['job_id'])['status'] == 'completed'
    job = owner._jobs[body['job_id']]
    task, lease = job.task, job.task._lease
    original = PreparedTask.dispose
    calls = []

    def dispose(self):
        if self is task:
            calls.append(True)
            if len(calls) == 1:
                if after_effect:
                    original(self)
                raise OSError('PRIVATE one-shot sibling cleanup failure')
        return original(self)

    monkeypatch.setattr(PreparedTask, 'dispose', dispose)
    if reason == 'prune':
        monkeypatch.setattr(service_module, 'RETENTION_SECONDS', -1)
        owner._prune()
    elif reason == 'shutdown':
        assert owner.close()['complete']
    elif reason == 'revoke':
        assert app.client.call('POST', '/auth/logout', {})[0] == 200
    else:
        # Completed cancellation is deliberately inert; it must not dispose.
        assert app.client.call('POST', '/ai/jobs/' + body['job_id'] + '/cancel', {})[0] == 200
        assert calls == [] and job.task is task
        assert owner.close()['complete']
    wait_for(lambda: job.task is None and not owner._retirements)
    assert lease._disposed and task._lease is None and len(calls) == 2
    assert not owner._users


@pytest.fixture
def retaining_app(tmp_path, monkeypatch):
    from http_server import ThreadingHTTPServer, make_handler
    from security.store import SecurityStore

    def reply(sock, stop):
        request = json.loads(requests[-1]['body'])
        schema = request['format']
        props = schema.get('oneOf', [schema])[0]['properties']
        value = {k: props[k]['const'] for k in ('version', 'kind', 'language', 'snapshot_digest')}
        value.update(summary=[{'text': 'Inspect retained evidence.', 'evidence_ids': ['e1']}],
                     counterpoints=[], limitations=[], next_checks=[])
        sock.sendall(http_response(envelope(json.dumps(value))))

    with peer(chat=reply) as (origin, requests, _):
        monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'sightings.json'))
        config = {'domains': [], 'servers': [], 'interval': 60, 'config_revision': 0, 'alerts': {}}
        core = app_factory(tmp_path / 'ledger', config=config)
        store = SecurityStore(tmp_path / 'security' / 'auth.db', create=True)
        store.bootstrap('fixture', 'fixture-only-password')
        server = thread = None
        try:
            handler = make_handler(config, core.cfg.lock, core.service.config_path, str(tmp_path / 'history'),
                                   core.current, core.history, security_store=store, insecure_http=True,
                                   state_repository=core.repo, config_service=core.service,
                                   delivery_diagnostics=core.delivery.store.diagnostics_snapshot,
                                   delivery_health=core.delivery.health_snapshot)
            import importlib
            checkout = Path(__file__).resolve().parents[1]
            for name in ('http_server', 'http_api_handlers', 'local_ai.service', 'local_ai.engine',
                         'local_ai.provider_factory', 'local_ai.provider_settings', 'monitor.config_service',
                         'security.http', 'security.store'):
                assert Path(importlib.import_module(name).__file__).resolve() == checkout / (name.replace('.', '/') + '.py')
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            client = Client(server.server_port)
            assert client.login('fixture', 'fixture-only-password')[0] == 200
            yield SimpleNamespace(client=client, handler=handler, core=core, store=store, config=config,
                                  native_requests=requests,
                                  native={'enabled': True, 'provider': 'ollama', 'base_url': origin,
                                          'model': MODEL, 'model_digest': DIGEST})
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(5)
                assert not thread.is_alive()
                # This fixture permits explicitly tested heap-only quarantine, not live workers.
                assert all(not t.is_alive() for t in (handler.local_ai._worker,
                                                      handler.local_ai._maintenance_worker) if t)
                assert all(not isinstance(r, dict) or r.get('retained_workers', 0) == 0
                           for r in server.background_shutdown)
            core.delivery.stop()


@pytest.mark.parametrize('shape', ['partial', 'other', 'read_error', 'fifo', 'symlink', 'oversized'])
def test_unknown_write_outcome_fences_reads_mutations_and_admission(app, monkeypatch, tmp_path, shape):
    import config_manager
    from monitor.config_service import ConfigError
    owner, writer = app.handler.local_ai, app.core.service
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    code, job = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
    assert code == 202 and wait_job(app.client, '/ai/jobs/' + job['job_id'])['status'] == 'completed'
    calls = []
    original_write, original_read = config_manager.write_config, config_manager.read_config_image
    foreign = tmp_path / 'caller-file'
    foreign.write_bytes(b'caller-owned-proof-sentinel')
    path = Path(writer.config_path)

    def write(pathname, candidate):
        calls.append(True)
        original_write(pathname, candidate)
        if shape == 'partial':
            path.write_bytes(b'{"private-sentinel":')
        elif shape == 'other':
            path.write_text(json.dumps({**candidate, 'caller_owned': True}))
        elif shape in ('fifo', 'symlink'):
            path.unlink()
            if shape == 'fifo':
                os.mkfifo(path)
            else:
                path.symlink_to(foreign)
        elif shape == 'oversized':
            with path.open('r+b') as stream:
                stream.truncate(config_manager.CONFIG_PROOF_BYTES + 1)
        raise OSError('PRIVATE persistence acknowledgement')

    def read(pathname):
        if calls and shape == 'read_error':
            raise OSError('PRIVATE readback failure')
        return original_read(pathname)

    monkeypatch.setattr(config_manager, 'write_config', write)
    monkeypatch.setattr(config_manager, 'read_config_image', read)
    # Real unsupported shapes must not block the config lock or HTTP worker.
    outcome = []
    thread = threading.Thread(target=lambda: outcome.append(app.client.call(
        'POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})))
    try:
        thread.start()
        thread.join(3)
        assert not thread.is_alive(), 'bounded reconciliation must not wait on a FIFO'
        assert outcome[0][0] == 503 and outcome[0][1]['code'] == 'config_storage_unavailable'
        assert owner.runtime() == {'applied': False, 'state': 'unavailable'}
        assert not owner.source_admission_enabled()
        assert app.client.call('GET', '/ai/settings')[0] == 503
        assert app.client.call('GET', '/ai/jobs/' + job['job_id'])[0] != 200
        before = len(app.native_requests)
        assert app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})[0] != 202
        for command, data in [('config', {'interval': 30}), ('settings', {'alerts': {}}),
                              ('decoder_create', {'name': 'later', 'steps': []}),
                              ('ai_settings', {'revision': 1, 'settings': {'enabled': True}})]:
            with pytest.raises(ConfigError) as error:
                writer.commit(command, data, expected_revision=1)
            assert error.value.payload['code'] == 'config_storage_unavailable'
        for reader in (writer.snapshot, writer.catalog):
            with pytest.raises(ConfigError):
                reader()
        assert calls == [True] and len(app.native_requests) == before
        assert foreign.read_bytes() == b'caller-owned-proof-sentinel'
        assert 'PRIVATE' not in json.dumps(outcome)
    finally:
        # Owned test artifact cleanup, never a mechanism recovery claim.
        if shape in ('fifo', 'symlink') and path.exists():
            path.unlink()
        thread.join(3)
        assert not thread.is_alive()


def test_unknown_persistence_fences_last_publication_without_releasing_active_owner(app, monkeypatch):
    import config_manager
    owner = app.handler.local_ai
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    entered, release = threading.Event(), threading.Event()
    original_check = owner._check
    original_write = config_manager.write_config

    def check(job):
        original_check(job)
        if job.finishing:
            entered.set()
            assert release.wait(4)

    def write(path, candidate):
        original_write(path, candidate)
        Path(path).write_bytes(b'{')
        raise OSError('PRIVATE unknown visibility')

    monkeypatch.setattr(owner, '_check', check)
    try:
        code, job = app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})
        assert code == 202 and entered.wait(2)
        active = owner._active
        provider = active.provider
        monkeypatch.setattr(config_manager, 'write_config', write)
        result = app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})
        assert result[0] == 503
        assert owner._active is active and active.provider is provider
        release.set()
        wait_for(lambda: owner._active is None)
        assert active.result is None and active.status == 'failed'
        assert app.client.call('GET', '/ai/jobs/' + job['job_id'])[0] != 200
    finally:
        release.set()
