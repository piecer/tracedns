"""Round-two lifecycle regressions through authenticated application callers.

Preserve real finalizer/task ownership and coherent earlier status snapshots.
"""
import json
from contextlib import contextmanager
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from test_ai_settings_api import app as app_fixture
from test_ai_settings_failure_boundaries import assert_owner_locks_available, phases, retaining_app as retaining_app
from test_ai_settings_failure_recovery import new_operator
from test_local_ai_application import wait_job
from test_local_ai_live_settings import thread_call
from test_local_ai_service import wait_for

app = app_fixture
REQUEST = {'kind': 'delivery', 'language': 'en'}


def record(tmp_path, name, value):
    (tmp_path / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')



@pytest.mark.parametrize('unknown', [False, True])
def test_inflight_status_is_not_a_mixed_ready_snapshot(app, monkeypatch, tmp_path, unknown):
    """Busy for the entire pre-fence interval; never-ready is not a stale snapshot."""
    import config_manager
    owner = app.handler.local_ai
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    finish_entered, finish_release = threading.Event(), threading.Event()
    status_entered, status_release = threading.Event(), threading.Event()
    marker = threading.local()
    original_finish, original_status = owner._finish, owner.status
    original_state, original_write = app.store.llm_provider_state, config_manager.write_config
    faults, jobs, status_observations = [], [], []

    def finish(job, status, **kwargs):
        if status == 'completed':
            jobs.append(job)
            finish_entered.set()
            assert finish_release.wait(4)
        return original_finish(job, status, **kwargs)

    def status(actor):
        marker.status = True
        try:
            return original_status(actor)
        finally:
            marker.status = False

    def state():
        value = original_state()
        if getattr(marker, 'status', False) and not status_entered.is_set():
            with owner._lock:
                status_observations.append({'active': owner._active is jobs[0],
                                            'fenced': owner._configuration_unknown.is_set()})
            status_entered.set()
            assert status_release.wait(4)
        return value

    def unknown_write(path, candidate):
        original_write(path, candidate)
        Path(path).write_bytes(b'{')
        faults.append(True)
        raise OSError('PRIVATE supported unknown visibility')

    monkeypatch.setattr(owner, '_finish', finish)
    monkeypatch.setattr(owner, 'status', status)
    monkeypatch.setattr(app.store, 'llm_provider_state', state)
    thread = None
    try:
        code, admitted = app.client.call('POST', '/ai/jobs', REQUEST)
        assert code == 202 and finish_entered.wait(2)
        assert original_state()['outcome'] == 'settled'
        thread, result = thread_call(lambda: app.client.call('GET', '/ai/status'))
        assert status_entered.wait(2)
        assert status_observations == [{'active': True, 'fenced': False}]
        if unknown:
            monkeypatch.setattr(config_manager, 'write_config', unknown_write)
            assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})[0] == 503
            assert faults == [True] and owner._configuration_unknown.is_set()
            assert owner._active is jobs[0]
        finish_release.set()
        wait_for(lambda: owner._active is None)
        assert jobs[0].audit_status == 'success'
        assert jobs[0].status == ('failed' if unknown else 'completed')
        status_release.set()
        thread.join(4)
        assert not thread.is_alive() and result.error is None
        fresh = app.client.call('GET', '/ai/status')
        runtime = owner.runtime()
        if unknown:
            admission = app.client.call('POST', '/ai/jobs', REQUEST)[0]
            assert admission != 202 and jobs[0].result is None
        else:
            admission = None
        record(tmp_path, 'status-mixed-' + str(unknown).lower(), {
            'unknown': unknown, 'initial_observation': status_observations,
            'fault_fired': len(faults), 'inflight_status': result.value, 'fresh_status': fresh,
            'runtime': runtime, 'job_status': jobs[0].status, 'admission_http': admission,
            'native_paths': [r['path'] for r in app.native_requests],
        })
        assert result.value[0] == 200
        if unknown:
            assert not result.value[1]['accepting'], 'status mixed post-fence idle state with pre-fence authority'
            assert result.value[1]['provider_state'] != 'ready'
        else:
            assert result.value[1]['accepting'] and result.value[1]['provider_state'] == 'ready'
    finally:
        finish_release.set()
        status_release.set()
        if thread is not None:
            thread.join(4)
            assert not thread.is_alive()
        assert owner.close()['complete']



@pytest.mark.parametrize('fault', ['none', 'before', 'after'])
def test_rejected_started_preparation_retains_finalizer_ack(app, monkeypatch, tmp_path, fault):
    """Real source invalidation after intent, before public queue admission."""
    owner = app.handler.local_ai
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    entered, release = threading.Event(), threading.Event()
    audit, prepare, finish = app.store.audit_llm_lifecycle, owner._engine.prepare, owner._finish
    tasks, ids, faults, captured = [], [], [], []

    def preparing(*args, **kwargs):
        task = prepare(*args, **kwargs)
        tasks.append(task)
        return task

    def audit_gate(job_id, *args, **kwargs):
        result = audit(job_id, *args, **kwargs)
        if kwargs['outcome'] == 'started':
            ids.append(job_id)
            entered.set()
            assert release.wait(4)
        return result

    def finalizer(job, *args, **kwargs):
        captured.append(job)
        if fault != 'none' and not faults:
            faults.append(True)
            if fault == 'after':
                finish(job, *args, **kwargs)
            raise OSError('PRIVATE single finalizer acknowledgement')
        return finish(job, *args, **kwargs)

    monkeypatch.setattr(owner._engine, 'prepare', preparing)
    monkeypatch.setattr(app.store, 'audit_llm_lifecycle', audit_gate)
    monkeypatch.setattr(owner, '_finish', finalizer)
    thread, result = thread_call(lambda: app.client.call('POST', '/ai/jobs', REQUEST))
    try:
        assert entered.wait(2) and len(tasks) == 1
        lease = tasks[0]._lease
        assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})[0] == 200
        release.set()
        thread.join(4)
        assert not thread.is_alive() and result.error is None and result.value[0] != 202
        assert len(ids) == 1 and captured and len(faults) == (fault != 'none')
        # This ordinary save supplies the promised bounded recovery opportunity.
        enabled = app.client.call('POST', '/ai/settings', {'revision': 2, 'settings': {'enabled': True}})
        assert enabled[0] == 200
        events = app.store.audit_list(action='llm.lifecycle')['events']
        outcomes = [e['outcome'] for e in reversed(events) if e['job_id'] == ids[0]]
        retained = captured[0] in owner._retirements
        closed = owner.close()
        record(tmp_path, 'rejected-finalizer-' + fault, {
            'fault': fault, 'fault_fired': len(faults), 'rejection': result.value,
            'audit_outcomes': outcomes, 'reenable_runtime': enabled[1]['runtime'],
            'task_disposed': tasks[0]._disposed, 'lease_disposed': lease._disposed,
            'retained_obligation': retained, 'users': len(owner._users),
            'registered_jobs': len(owner._jobs), 'close': closed,
            'native_paths': [r['path'] for r in app.native_requests],
        })
        assert not app.native_requests and not owner._preparing
        assert outcomes == ['started', 'failed'], 'accepted lifecycle intent lost its terminal obligation'
        assert lease._disposed and tasks[0]._lease is None
        assert not owner._retirements and not owner._users and closed['complete']
    finally:
        release.set()
        thread.join(4)
        assert not thread.is_alive()
        assert owner.close()['retained_workers'] == 0



def test_coherent_earlier_status_snapshot_is_not_a_blocker(app, monkeypatch, tmp_path):
    import config_manager
    owner = app.handler.local_ai
    assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
    entered, release = threading.Event(), threading.Event()
    status, write, read = owner.status, config_manager.write_config, config_manager.read_config_image
    captured, faults, read_faults = [], [], []

    def delayed_snapshot(actor):
        payload = status(actor)  # All status fields captured before the fence.
        if not entered.is_set():
            captured.append(dict(payload))
            entered.set()
            assert release.wait(4)
        return payload

    def ack_fault(path, candidate):
        write(path, candidate)
        faults.append(True)
        raise OSError('PRIVATE acknowledgement fault')

    def read_fault(path):
        if faults:
            read_faults.append(True)
            raise OSError('PRIVATE exact readback unavailable')
        return read(path)

    monkeypatch.setattr(owner, 'status', delayed_snapshot)
    thread, response = thread_call(lambda: app.client.call('GET', '/ai/status'))
    try:
        assert entered.wait(2)
        assert captured[0]['provider_state'] == 'ready' and captured[0]['accepting']
        monkeypatch.setattr(config_manager, 'write_config', ack_fault)
        monkeypatch.setattr(config_manager, 'read_config_image', read_fault)
        saved = app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})
        assert saved[0] == 503 and faults == [True] and read_faults == [True]
        assert Path(app.core.service.config_path).is_file()
        assert owner._configuration_unknown.is_set()
        release.set()
        thread.join(4)
        assert not thread.is_alive() and response.error is None
        assert response.value == (200, captured[0])
        fresh = app.client.call('GET', '/ai/status')
        assert fresh[0] == 200 and not fresh[1]['accepting'] and fresh[1]['provider_state'] == 'unavailable'
        assert app.client.call('POST', '/ai/jobs', {'kind': 'delivery', 'language': 'en'})[0] != 202
        assert not app.native_requests
        record(tmp_path, 'legal-earlier-snapshot', {'earlier': response.value, 'fresh': fresh,
            'writer_fault_fired': len(faults), 'readback_fault_fired': len(read_faults)})
    finally:
        release.set()
        thread.join(4)
        assert not thread.is_alive() and owner.close()['complete']


@contextmanager
def rejected_preparation(app, monkeypatch, boundary, *, after=False, persistent=False, started=True):
    """Gate actual intent/prepare return; never rescue retained product objects.

    Maintenance is parked only to observe the first acknowledgement before the
    ordinary next save. Every gate is released and the real workers are joined
    even when setup/observation fails. Persistent heap obligations remain owned.
    """
    from local_ai.engine import PreparedTask
    from local_ai.sources import SourceLease

    owner = app.handler.local_ai
    client = new_operator(app, 'round2operator')
    entered, release = threading.Event(), threading.Event()
    maintenance_entered, maintenance_release = threading.Event(), threading.Event()
    prepare, audit = owner._engine.prepare, app.store.audit_llm_lifecycle
    finish, drain, maintenance = owner._finish, owner._drain_retirements, owner._maintenance
    task_dispose, lease_dispose = PreparedTask.dispose, SourceLease.dispose
    tasks, leases, actors, ids, jobs, calls, observations = [], [], [], [], [], [], []
    preparing_threads = []
    thread = None

    def parked_maintenance():
        maintenance_entered.set()
        assert maintenance_release.wait(20)
        return maintenance()

    def preparing(*args, **kwargs):
        task = prepare(*args, **kwargs)
        tasks.append(task)
        leases.append(task._lease)
        actors.append(dict(args[1]))
        preparing_threads.append(threading.current_thread())
        if not started:
            entered.set()
            assert release.wait(4)
        return task

    def observe(job=None):
        assert_owner_locks_available(app)
        with owner._lock:
            if job is None:
                matches = [j for j in owner._retirements if j.task is tasks[0]]
                job = matches[0] if len(matches) == 1 else None
            observations.append({
                'retained': job in owner._retirements,
                'user_owned': job is not None and owner._users.get(actors[0]['id']) is job,
                'original_actor': job is not None and job.actor == actors[0],
                'original_error': job.retired_error if job else None,
                'terminal_obligation': owner._retirements.get(job),
                'not_admitted': job is not None and job.job_id not in owner._jobs
                                and owner._active is not job and job not in owner._queue,
            })
            if job is not None:
                jobs.append(job)

    def inject(real, *args, **kwargs):
        calls.append(True)
        if persistent or len(calls) == 1:
            if after:
                real(*args, **kwargs)
            raise OSError('PRIVATE rejected-preparation acknowledgement')
        return real(*args, **kwargs)

    def auditing(job_id, *args, **kwargs):
        if kwargs['outcome'] == 'started':
            value = audit(job_id, *args, **kwargs)
            ids.append(job_id)
            entered.set()
            assert release.wait(4)
            return value
        if boundary == 'audit' and ids and job_id == ids[0]:
            # The task was disposed first; identify the original retained job.
            with owner._lock:
                job = next(j for j in owner._retirements if j.job_id == job_id)
            observe(job)
            return inject(audit, job_id, *args, **kwargs)
        return audit(job_id, *args, **kwargs)

    def finalizing(job, *args, **kwargs):
        if ids and job.job_id == ids[0]:
            observe(job)
            if boundary == 'finish':
                return inject(finish, job, *args, **kwargs)
        return finish(job, *args, **kwargs)

    def disposing_task(task):
        if tasks and task is tasks[0] and boundary == 'task':
            observe()
            return inject(task_dispose, task)
        return task_dispose(task)

    def disposing_lease(lease):
        if leases and lease is leases[0] and boundary == 'lease':
            observe()
            return inject(lease_dispose, lease)
        return lease_dispose(lease)

    def draining():
        if (boundary == 'drain' and tasks and release.is_set()
                and threading.current_thread() is preparing_threads[0]):
            observe()
            return inject(drain)
        return drain()

    with monkeypatch.context() as patch:
        patch.setattr(owner, '_maintenance', parked_maintenance)
        patch.setattr(owner._engine, 'prepare', preparing)
        patch.setattr(app.store, 'audit_llm_lifecycle', auditing)
        patch.setattr(owner, '_finish', finalizing)
        patch.setattr(owner, '_drain_retirements', draining)
        patch.setattr(PreparedTask, 'dispose', disposing_task)
        patch.setattr(SourceLease, 'dispose', disposing_lease)
        try:
            assert app.client.call('POST', '/ai/settings', {'revision': 0, 'settings': app.native})[0] == 200
            assert maintenance_entered.wait(2)
            thread, response = thread_call(lambda: client.call('POST', '/ai/jobs', REQUEST))
            assert entered.wait(2) and len(tasks) == len(actors) == len(leases) == 1
            assert len(preparing_threads) == 1 and preparing_threads[0] is not thread
            assert len(ids) == int(started)
            assert owner._preparing == {actors[0]['id']}
            assert set(owner._users) == {actors[0]['id']}
            assert app.client.call('POST', '/ai/settings', {'revision': 1, 'settings': {'enabled': False}})[0] == 200
            release.set()
            thread.join(4)
            assert not thread.is_alive() and response.error is None
            assert response.value[0] == 409 and response.value[1]['code'] == 'source_revoked'
            assert 'PRIVATE' not in json.dumps(response.value)
            assert calls == [True], 'the selected first fault must fire'
            assert jobs and all(j is jobs[0] for j in jobs)
            job = jobs[0]
            assert job.job_id == (ids[0] if started else '')
            assert job.actor == actors[0] and job.retired_error == 'source_revoked'
            assert job.request_id == response.value[1]['request_id']
            assert not owner._jobs and owner._active is None and not owner._queue and not owner._preparing
            assert not job.called and not job.reserved and not app.native_requests
            assert all(o == {'retained': True, 'user_owned': True, 'original_actor': True,
                             'original_error': 'source_revoked', 'terminal_obligation': started,
                             'not_admitted': True} for o in observations)
            yield SimpleNamespace(owner=owner, client=client, task=tasks[0], lease=leases[0],
                                  job=job, calls=calls, observations=observations, response=response.value,
                                  release_maintenance=maintenance_release.set)
        finally:
            release.set()
            maintenance_release.set()
            if thread is not None:
                thread.join(4)
                assert not thread.is_alive()
            assert owner.close()['retained_workers'] == 0


@pytest.mark.parametrize('boundary', ['task', 'lease', 'finish', 'drain'])
@pytest.mark.parametrize('after', [False, True])
def test_rejected_started_fault_recovers_same_user_and_original_error(app, monkeypatch, tmp_path, boundary, after):
    with rejected_preparation(app, monkeypatch, boundary, after=after) as case:
        owner, job = case.owner, case.job
        if boundary != 'drain' or not after:
            assert owner._retirements == {job: True}
            assert owner._users == {job.actor['id']: job}
            assert not owner.runtime()['applied']
        if boundary in ('task', 'lease'):
            assert job.task is case.task
        code, saved = app.client.call('POST', '/ai/settings', {'revision': 2, 'settings': {'enabled': True}})
        assert code == 200 and saved['runtime'] == {'applied': True, 'state': 'ready'}
        assert phases(app, [job]) == [['started', 'failed']]
        assert job.audit_status == 'success' and job.error == 'source_revoked'
        assert job.task is None and case.task._lease is None and case.lease._disposed
        assert not owner._retirements and not owner._users
        assert len(case.calls) == (1 if boundary == 'drain' or (boundary == 'finish' and after) else 2)
        assert not app.native_requests
        # Both the original user and a distinct user can use their own slot.
        for client in (case.client, app.client):
            code, admitted = client.call('POST', '/ai/jobs', REQUEST)
            assert code == 202
            assert wait_job(client, '/ai/jobs/' + admitted['job_id'])['status'] == 'completed'
            wait_for(lambda: owner._active is None)
        assert phases(app, [job]) == [['started', 'failed']]
        case.release_maintenance()
        assert not owner._users and owner.close()['complete']
        record(tmp_path, 'rejected-recovery', {'boundary': boundary, 'after': after,
            'fault_calls': len(case.calls), 'observations': case.observations,
            'original_error': case.response[1]['code'], 'user_id': job.actor['id'],
            'terminal_phases': phases(app, [job]), 'same_and_other_user_completed': True})


@pytest.mark.parametrize('boundary,after', [('finish', False), ('task', False), ('task', True),
                                           ('lease', False), ('lease', True)])
def test_rejected_started_persistent_failure_stays_bounded_and_owned(retaining_app, monkeypatch, tmp_path, boundary, after):
    app = retaining_app
    with rejected_preparation(app, monkeypatch, boundary, after=after, persistent=True) as case:
        owner, job = case.owner, case.job
        for revision in range(2, 10):
            code, saved = app.client.call('POST', '/ai/settings', {
                'revision': revision, 'settings': {'enabled': revision % 2 == 0}})
            assert code == 200 and saved['runtime'] == {'applied': False, 'state': 'unavailable'}
            assert owner._retirements == {job: True} and owner._users == {job.actor['id']: job}
            assert job.retired_error == 'source_revoked' and job.audit_status == 'pending'
            assert len(case.calls) == 2
        assert job.task is (None if boundary == 'finish' else case.task)
        assert phases(app, [job]) == [['started']]
        assert app.client.call('GET', '/ai/status')[1]['accepting'] is False
        assert case.client.call('POST', '/ai/jobs', REQUEST)[0] != 202
        assert not app.native_requests and not owner._jobs and owner._active is None
        # Release/join the real maintenance owner via close, without rescuing its obligation.
        # The context manager releases the park in finally; close now truthfully sees a worker.
        assert not owner.close(timeout=0)['complete']
        record(tmp_path, 'rejected-persistent', {'boundary': boundary, 'after': after,
            'fault_calls': len(case.calls), 'original_error': job.retired_error,
            'identities': len(owner._retirements), 'user_id': job.actor['id'],
            'task_retained': job.task is case.task, 'observations': case.observations})
    assert owner.close() == {'complete': False, 'retained_workers': 0}
    assert owner._retirements == {job: True} and owner._users == {job.actor['id']: job}
    assert len(case.calls) == 2


@pytest.mark.parametrize('after', [False, True])
def test_rejected_started_terminal_audit_failure_is_sticky(app, monkeypatch, tmp_path, after):
    with rejected_preparation(app, monkeypatch, 'audit', after=after, persistent=True) as case:
        owner, job = case.owner, case.job
        assert job.audit_status == 'failed' and job.error == 'audit_unavailable'
        expected = [['started', 'failed']] if after else [['started']]
        for revision in range(2, 6):
            code, saved = app.client.call('POST', '/ai/settings', {
                'revision': revision, 'settings': {'enabled': True}})
            assert code == 200 and saved['runtime'] == {'applied': False, 'state': 'unavailable'}
            assert phases(app, [job]) == expected and case.calls == [True]
            assert not owner._retirements and not owner._users
        assert job.task is None and case.task._lease is None and case.lease._disposed
        assert app.client.call('GET', '/ai/status')[1]['accepting'] is False
        assert case.client.call('POST', '/ai/jobs', REQUEST)[0] != 202 and not app.native_requests
        record(tmp_path, 'rejected-audit', {'after': after, 'terminal_attempts': len(case.calls),
            'phases': phases(app, [job]), 'audit_status': job.audit_status,
            'original_rejection': case.response[1]['code'], 'observations': case.observations})
    assert owner.close() == {'complete': True, 'retained_workers': 0}


@pytest.mark.parametrize('boundary', ['task', 'lease'])
@pytest.mark.parametrize('after', [False, True])
def test_never_started_rejection_cleans_without_fabricated_audit(app, monkeypatch, tmp_path, boundary, after):
    with rejected_preparation(app, monkeypatch, boundary, after=after, started=False) as case:
        owner, job = case.owner, case.job
        assert job.job_id == '' and owner._retirements == {job: False}
        assert owner._users == {job.actor['id']: job} and job.task is case.task
        assert app.store.audit_list(action='llm.lifecycle')['events'] == []
        code, saved = app.client.call('POST', '/ai/settings', {'revision': 2, 'settings': {'enabled': True}})
        assert code == 200 and saved['runtime'] == {'applied': True, 'state': 'ready'}
        assert len(case.calls) == 2 and job.finish_attempts == 0
        assert app.store.audit_list(action='llm.lifecycle')['events'] == []
        assert job.task is None and case.task._lease is None and case.lease._disposed
        assert not owner._retirements and not owner._users and not app.native_requests
        record(tmp_path, 'never-started', {'boundary': boundary, 'after': after,
            'fault_calls': len(case.calls), 'terminal_attempts': job.finish_attempts,
            'audit_events': [], 'observations': case.observations})
