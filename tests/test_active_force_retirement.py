"""Missing authority retires only after authoritative dequeue, without a snapshot."""
import threading
from unittest.mock import Mock

import pytest

from monitor.projection_authority import security_projection_revision
from monitor.runtime_state import state_lock
from monitor.scheduler import MonitorScheduler
from security.jobs import finish_force
from test_stage4_fence_failures import app
from test_lookup_force import enqueue
from test_lookup_liveness import owned_app, wait_for


def missing_job(o):
    job = enqueue(o, ['test.example'])
    del job['_target_leases']
    return job


def snapshot_tripwire():
    raise AssertionError('missing authority entered snapshot')


@pytest.mark.parametrize('explicit_none', [False, True])
@pytest.mark.parametrize('legacy', [False, True])
def test_missing_authority_excludes_snapshot_after_authoritative_dequeue(tmp_path, monkeypatch,
                                                                       explicit_none, legacy):
    o = app(tmp_path)
    audit = Mock()
    job = {'actor': {'id': 7}, '_security_store': audit, 'job_id': 'missing',
           'request_id': 'original-request', 'source_ip': 'fixture', '_registry_view': object()}
    if explicit_none:
        job['_target_leases'] = None
    key = '_force_resolve' if legacy else '_force_resolve_queue'
    o.cfg[key] = job if legacy else [job]
    revision, epoch = security_projection_revision(o.cfg), o.model._epoch
    invalidate = o.model.invalidate
    revoked = []
    def revoke(*, hard=False):
        assert o.cfg[key] is job if legacy else o.cfg[key][0] is job
        assert o.store.condition._is_owned()
        invalidate(hard=hard)
        revoked.append(hard)
    monkeypatch.setattr(o.model, 'invalidate', revoke)
    def forbidden_snapshot():
        pytest.fail('missing authority entered snapshot')
    monkeypatch.setattr(o.store, '_snapshot_locked', forbidden_snapshot)
    held = []
    audit.audit.side_effect = lambda *a, **k: held.append(
        (o.store.condition._is_owned(), state_lock()._is_owned()))
    assert MonitorScheduler(o.store).active_force() is None
    assert key not in o.cfg
    assert revoked == [True]
    assert security_projection_revision(o.cfg) == revision + 1
    assert o.model._epoch == epoch + 1
    assert job['_terminal_outcome'] == 'failure'
    assert held == [(False, False)]
    finish_force(job, 'completed')
    audit.audit.assert_called_once_with(job['actor'], 'force.resolve', target='missing',
        outcome='failure', request_id='original-request', source_ip='fixture', job_id='missing')


@pytest.mark.parametrize('callback_raises', [False, True])
def test_real_owner_retains_blocked_audit_without_waiting_for_state(tmp_path, monkeypatch, callback_raises):
    from monitor import engine
    o = owned_app(tmp_path)
    scheduler = MonitorScheduler(o.cfg)
    job = missing_job(o)
    owner = o.lookup.audit
    state_held, release_state = threading.Event(), threading.Event()
    audit_entered, release_audit = threading.Event(), threading.Event()
    completed = threading.Event()
    results, errors, held = [], [], []
    dispatch = Mock(side_effect=AssertionError('unexpected dispatch'))
    monkeypatch.setattr(engine, 'collect_snapshot', dispatch)
    monkeypatch.setattr(o.cfg, '_snapshot_locked', snapshot_tripwire)
    def callback(*a, **k):
        held.append((o.cfg.condition._is_owned(), state_lock()._is_owned(), owner.condition._is_owned()))
        audit_entered.set()
        assert release_audit.wait(5)
        if callback_raises:
            raise RuntimeError('external audit failure')
    job['_security_store'].audit.side_effect = callback
    def hold_state():
        with state_lock():
            state_held.set()
            release_state.wait(5)
    def pump():
        try:
            results.append(scheduler.active_force())
        except BaseException as error:
            errors.append(error)
        finally:
            completed.set()
    holder, caller = threading.Thread(target=hold_state), threading.Thread(target=pump)
    holder.start()
    try:
        assert state_held.wait(2)
        caller.start()
        assert completed.wait(1), 'missing authority waited for state owner'
        assert not errors and results == [None]
        assert not release_state.is_set() and holder.is_alive()
        assert audit_entered.wait(2)
        assert held == [(False, False, False)]
        assert job['_terminal_audit_owner'] is owner
        assert owner.reservations[id(job)] is job
        assert job['_terminal_outcome'] == 'failure' and not job.get('_terminal_audit_done')
        assert owner.status()['pending'] == 1
        assert not owner.stop(join_seconds=0)['stopped']
        assert not o.delivery.stop(join_seconds=0)['closed']
        finish_force(job, 'completed')
        assert job['_terminal_outcome'] == 'failure'
        dispatch.assert_not_called()
    finally:
        release_state.set()
        release_audit.set()
        holder.join(2)
        if caller.ident is not None:
            caller.join(2)
        o.lookup.stop()
        o.delivery.stop()
    assert not holder.is_alive() and not caller.is_alive()
    assert job['_terminal_audit_done'] and owner.status()['pending'] == 0
    job['_security_store'].audit.assert_called_once()
    assert job['_security_store'].audit.call_args.args[0] is job['actor']


@pytest.mark.parametrize('after_submit', [False, True])
def test_internal_submit_failure_is_not_retried_and_real_fence_keeps_duty(tmp_path, monkeypatch, after_submit):
    o = owned_app(tmp_path)
    scheduler = MonitorScheduler(o.cfg)
    job = missing_job(o)
    owner = o.lookup.audit
    release, entered = threading.Event(), threading.Event()
    def callback(*a, **k):
        entered.set()
        assert release.wait(5)
    job['_security_store'].audit.side_effect = callback
    original, calls = owner.submit, []
    failure = RuntimeError('original submit failure')
    def submit(envelope, outcome):
        calls.append((envelope, outcome, o.cfg.condition._is_owned()))
        if after_submit:
            original(envelope, outcome)
        raise failure
    monkeypatch.setattr(o.cfg, '_snapshot_locked', snapshot_tripwire)
    try:
        with monkeypatch.context() as change:
            change.setattr(owner, 'submit', submit)
            with pytest.raises(RuntimeError) as raised:
                scheduler.active_force()
            assert raised.value is failure
            assert len(calls) == 1 and calls[0] == (job, 'failure', False)
            assert owner.reservations[id(job)] is job
            assert '_force_resolve_queue' not in o.cfg.raw
            assert (job.get('_terminal_outcome') == 'failure') is after_submit
            assert not job.get('_terminal_audit_done')
        assert not scheduler.stop()
        assert entered.wait(2)
        finish_force(job, 'completed')
    finally:
        release.set()
        o.lookup.stop()
        o.delivery.stop()
    assert job['_terminal_audit_done'] and job['_terminal_outcome'] == 'failure'
    job['_security_store'].audit.assert_called_once()


@pytest.mark.parametrize('fault', ['before-revoke', 'after-revoke', 'invalid-revision', 'overflow'])
def test_missing_dequeue_authority_failure_preserves_queue_and_reserved_duty(tmp_path, monkeypatch, fault):
    from monitor.lookup_runtime import LookupRuntime
    o = app(tmp_path)
    lookup = LookupRuntime(o.repo)
    scheduler = MonitorScheduler(o.store)
    job = {'actor': {'id': 4}, '_security_store': Mock(), 'job_id': 'reserved',
           'request_id': 'reserved', 'source_ip': 'fixture'}
    o.cfg['_force_resolve_queue'] = [job]
    epoch = o.model._epoch
    revision = security_projection_revision(o.cfg)
    failure = RuntimeError('revoke fault')
    invalidate = o.model.invalidate
    def revoke(*, hard=False):
        if fault == 'after-revoke':
            invalidate(hard=hard)
        raise failure
    if fault == 'invalid-revision':
        o.cfg['_security_projection_revision'] = False
    elif fault == 'overflow':
        o.cfg['_security_projection_revision'] = 9007199254740991
    else:
        monkeypatch.setattr(o.model, 'invalidate', revoke)
    before_revision = o.cfg.get('_security_projection_revision', 0)
    monkeypatch.setattr(o.store, '_snapshot_locked', snapshot_tripwire)
    try:
        with pytest.raises((RuntimeError, ValueError, OverflowError)) as raised:
            scheduler.active_force()
        if fault in ('before-revoke', 'after-revoke'):
            assert raised.value is failure
        else:
            assert type(raised.value) is (OverflowError if fault == 'overflow' else ValueError)
        assert o.cfg['_force_resolve_queue'][0] is job
        assert o.cfg.get('_security_projection_revision', 0) is before_revision
        assert o.model._epoch == epoch + (fault == 'after-revoke')
        assert lookup.audit.reservations[id(job)] is job
        assert job.get('_terminal_outcome') is None
        job['_security_store'].audit.assert_not_called()
    finally:
        monkeypatch.setattr(o.model, 'invalidate', invalidate)
        o.cfg['_security_projection_revision'] = revision
        scheduler.stop()
        lookup.stop()
    assert job['_terminal_audit_done']
    finish_force(job, 'completed')
    job['_security_store'].audit.assert_called_once()


@pytest.mark.parametrize('callback_raises', [False, True])
def test_synchronous_callback_is_unlocked_but_retains_its_latency(tmp_path, callback_raises):
    o = app(tmp_path)
    scheduler = MonitorScheduler(o.store)
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    held, errors, results = [], [], []
    audit = Mock()
    job = {'actor': {'id': 1}, '_security_store': audit, 'job_id': 'sync',
           'request_id': 'sync', 'source_ip': 'fixture'}
    o.cfg['_force_resolve_queue'] = [job]
    def callback(*a, **k):
        held.append((o.store.condition._is_owned(), state_lock()._is_owned()))
        entered.set()
        assert release.wait(5)
        if callback_raises:
            raise RuntimeError('external callback fault')
    audit.audit.side_effect = callback
    def run():
        try:
            results.append(scheduler.active_force())
        except BaseException as error:
            errors.append(error)
        finally:
            done.set()
    caller = threading.Thread(target=run)
    caller.start()
    try:
        assert entered.wait(2)
        assert not done.is_set() and caller.is_alive()
        assert held == [(False, False)]
        assert job['_terminal_outcome'] == 'failure'
        assert '_terminal_audit_owner' not in job
        finish_force(job, 'completed')
    finally:
        release.set()
        caller.join(2)
    assert not caller.is_alive() and not errors and results == [None]
    audit.audit.assert_called_once()


@pytest.mark.parametrize('stage', ['deepcopy', 'conversion', 'cleanup', 'capture', 'registry'])
def test_missing_skips_incidental_snapshot_operations(tmp_path, monkeypatch, stage):
    from monitor import stores
    o = app(tmp_path)
    job = {}
    o.cfg['_force_resolve_queue'] = [job]
    fault = Mock(side_effect=RuntimeError('snapshot operation must not run'))
    if stage == 'deepcopy':
        monkeypatch.setattr(stores, 'deepcopy', fault)
    elif stage == 'conversion':
        monkeypatch.setattr(stores, 'bounded_int', fault)
    elif stage == 'cleanup':
        monkeypatch.setattr(o.repo, 'retry_cleanup', fault)
    elif stage == 'capture':
        monkeypatch.setattr(o.repo, 'capture', fault)
    else:
        o.cfg['_decoder_registry_snapshot'] = fault
    assert MonitorScheduler(o.store).active_force() is None
    assert job['_terminal_outcome'] == 'failure'
    fault.assert_not_called()


@pytest.mark.parametrize('repository', [False, True])
@pytest.mark.parametrize('stage', ['snapshot', 'deepcopy', 'conversion', 'registry', 'cleanup', 'capture'])
def test_entered_snapshot_fault_keeps_original_error_under_external_audit_fault(tmp_path, monkeypatch,
                                                                              repository, stage):
    from monitor import stores
    o = app(tmp_path)
    if not repository:
        o.store.state_repository = None
    job = {'actor': {'id': 1}, '_security_store': Mock(), 'job_id': 'valid',
           'request_id': 'valid', 'source_ip': 'fixture'}
    if repository:
        job['_target_leases'] = o.repo.capture()
    o.cfg['_force_resolve_queue'] = [job]
    job['_security_store'].audit.side_effect = RuntimeError('external audit failure')
    failure = RuntimeError('primary snapshot fault')
    fault = Mock(side_effect=failure)
    if stage == 'snapshot':
        monkeypatch.setattr(o.store, '_snapshot_locked', fault)
    elif stage == 'deepcopy':
        monkeypatch.setattr(stores, 'deepcopy', fault)
    elif stage == 'conversion':
        monkeypatch.setattr(stores, 'bounded_int', fault)
    elif stage == 'registry':
        o.cfg['_decoder_registry_snapshot'] = fault
    else:
        monkeypatch.setattr(o.repo, 'retry_cleanup' if stage == 'cleanup' else 'capture', fault)
    if not repository and stage in ('cleanup', 'capture'):
        assert MonitorScheduler(o.store).active_force().force_req is job
        fault.assert_not_called()
        finish_force(job, 'failure')
    else:
        with pytest.raises(RuntimeError) as raised:
            MonitorScheduler(o.store).active_force()
        assert raised.value is failure
        fault.assert_called_once()
    assert job['_terminal_outcome'] == 'failure'
    job['_security_store'].audit.assert_called_once()


@pytest.mark.parametrize('stage', ['snapshot', 'cleanup', 'capture', 'registry'])
def test_owned_entered_snapshot_error_survives_real_callback_failure(tmp_path, monkeypatch, stage):
    o = owned_app(tmp_path)
    scheduler = MonitorScheduler(o.cfg)
    job = enqueue(o, ['test.example'])
    failure = RuntimeError('primary owned snapshot error')
    job['_security_store'].audit.side_effect = RuntimeError('external audit failure')
    fault = Mock(side_effect=failure)
    if stage == 'snapshot':
        monkeypatch.setattr(o.cfg, '_snapshot_locked', fault)
    elif stage == 'registry':
        o.cfg.raw['_decoder_registry_snapshot'] = fault
    else:
        monkeypatch.setattr(o.repo, 'retry_cleanup' if stage == 'cleanup' else 'capture', fault)
    try:
        with pytest.raises(RuntimeError) as raised:
            scheduler.active_force()
        assert raised.value is failure
        fault.assert_called_once()
        assert job['_terminal_outcome'] == 'failure'
        assert wait_for(lambda: job.get('_terminal_audit_done'))
        job['_security_store'].audit.assert_called_once()
    finally:
        o.lookup.stop()
        o.delivery.stop()


@pytest.mark.parametrize('value', ['valid', 'empty', 'revoked', 'partial', 'list', 'zero', 'false', 'string', 'bad-value'])
def test_nonmissing_preserves_snapshot_and_owned_scan_validation(tmp_path, monkeypatch, value):
    from monitor.engine import OwnedScan
    o = owned_app(tmp_path)
    scheduler = MonitorScheduler(o.cfg)
    job = enqueue(o, ['test.example'])
    old = job['_target_leases']
    if value == 'revoked':
        o.repo.configure({**o.cfg.raw, 'servers': ['changed']})
    elif value != 'valid':
        job['_target_leases'] = {'empty': {}, 'partial': {'test.example': None}, 'list': [],
            'zero': 0, 'false': False, 'string': 'bad', 'bad-value': {'test.example': object()}}[value]
    snapshot = o.cfg._snapshot_locked
    calls = []
    def capture():
        calls.append(True)
        return snapshot()
    monkeypatch.setattr(o.cfg, '_snapshot_locked', capture)
    try:
        snap = scheduler.active_force()
        assert snap.force_req is job and calls == [True]
        assert job.get('_terminal_outcome') is None
        args = dict(force_req=job, state_repository=o.repo, domains_raw=snap.domains,
                    target_leases=snap.target_leases, registry_view=snap.registry_view)
        if value in ('list', 'zero', 'false', 'string', 'bad-value'):
            with pytest.raises(AttributeError):
                OwnedScan(args, snapshot=snap)
        else:
            scan = OwnedScan(args, snapshot=snap)
            assert scan.leases is job['_target_leases']
            assert scan.invalid is (value in ('revoked', 'partial'))
            if value == 'valid':
                assert scan.leases is old
    finally:
        scheduler.stop()
        o.lookup.stop()
        o.delivery.stop()


def test_missing_defers_cleanup_but_not_obligation_or_readd_fence(tmp_path, monkeypatch):
    from history_manager import persist_history_entry, history_file_path
    from monitor.runtime_state import get_state_version
    o = owned_app(tmp_path)
    job = missing_job(o)
    old = o.repo.capture()['test.example']
    persist_history_entry(str(tmp_path), 'test.example', old.history)
    retire = o.delivery.store.retire_dht
    attempts = []
    def blocked_retire(name):
        attempts.append(name)
        return False
    try:
        with monkeypatch.context() as change:
            change.setattr(o.delivery.store, 'retire_dht', blocked_retire)
            o.cfg.raw['domains'] = ['replacement.example']
            assert o.repo.configure(o.cfg.raw) == ['history_cleanup_pending']
            assert attempts == ['test.example']
            assert not o.repo.current and not o.repo.history
            before = get_state_version()
            assert MonitorScheduler(o.cfg).active_force() is None
            assert attempts == ['test.example']
            assert o.repo._pending_cleanup == {'test.example'}
            assert not o.repo.current and not o.repo.history
            assert get_state_version() == before
            with pytest.raises(ValueError, match='history_cleanup_pending'):
                o.repo.validate_config({'domains': ['test.example']})
        snap = o.cfg.snapshot()
        assert not o.repo._pending_cleanup
        assert snap.target_leases['replacement.example'].current is o.repo.current['replacement.example']
        assert get_state_version() > before
        o.repo.validate_config({'domains': ['test.example']})
        o.cfg.raw['domains'] = ['test.example']
        o.repo.configure(o.cfg.raw)
        replacement = o.cfg.snapshot().target_leases['test.example']
        assert replacement.target is not old.target
        persist_history_entry(str(tmp_path), 'test.example', replacement.history)
        assert o.repo.retry_cleanup() == []
        from pathlib import Path
        assert Path(history_file_path(str(tmp_path), 'test.example')).exists()
        assert retire is not None and job['_terminal_outcome'] == 'failure'
    finally:
        o.lookup.stop()
        o.delivery.stop()


def test_mixed_fifo_one_per_pump_preserves_clock_and_pinned_authority(tmp_path):
    o = owned_app(tmp_path)
    scheduler = MonitorScheduler(o.cfg, clock=lambda: 10)
    scheduler.completed(scheduler.next_scan(block=False), accepted=True)
    missing = missing_job(o)
    valid = enqueue(o, ['test.example'])
    tokens, registry = valid['_target_leases'], valid['_registry_view']
    before = (scheduler.last_full_completion, scheduler._full_due, scheduler._full_generation)
    try:
        assert scheduler.active_force() is None
        assert o.cfg.raw['_force_resolve_queue'] == [valid]
        assert missing['_terminal_outcome'] == 'failure' and valid.get('_terminal_outcome') is None
        assert before == (scheduler.last_full_completion, scheduler._full_due, scheduler._full_generation)
        snap = scheduler.active_force()
        assert snap.force_req is valid
        assert valid['_target_leases'] is tokens and valid['_registry_view'] is registry
        assert before == (scheduler.last_full_completion, scheduler._full_due, scheduler._full_generation)
    finally:
        scheduler.stop()
        o.lookup.stop()
        o.delivery.stop()


@pytest.mark.parametrize('boundary', ['busy', 'stopped', 'empty', 'terminalized'])
def test_no_work_boundaries_and_already_selected_outcome(tmp_path, monkeypatch, boundary):
    o = app(tmp_path)
    job = {}
    if boundary != 'empty':
        o.cfg['_force_resolve_queue'] = [job]
    if boundary == 'stopped':
        o.cfg['_monitor_stopped'] = True
    elif boundary == 'terminalized':
        finish_force(job, 'completed')
    monkeypatch.setattr(o.store, '_snapshot_locked', snapshot_tripwire)
    release, held = threading.Event(), threading.Event()
    def holder():
        with o.store.condition:
            held.set()
            release.wait(5)
    thread = threading.Thread(target=holder)
    if boundary == 'busy':
        thread.start()
        assert held.wait(2)
    try:
        assert MonitorScheduler(o.store).active_force() is None
        if boundary in ('busy', 'stopped'):
            assert o.cfg['_force_resolve_queue'][0] is job and job == {}
        elif boundary == 'terminalized':
            assert job['_terminal_outcome'] == 'completed'
            assert '_force_resolve_queue' not in o.cfg
    finally:
        release.set()
        if thread.ident is not None:
            thread.join(2)
            assert not thread.is_alive()


def test_stop_between_dequeue_and_submit_selects_one_failure(tmp_path, monkeypatch):
    from monitor import scheduler as module
    o = owned_app(tmp_path)
    scheduler = MonitorScheduler(o.cfg)
    job = missing_job(o)
    calls = []
    def stop_before_finish(envelope, outcome):
        assert not o.cfg.condition._is_owned()
        assert envelope is job
        calls.append(outcome)
        scheduler.stop()
        return finish_force(envelope, outcome)
    monkeypatch.setattr(module, 'finish_force', stop_before_finish)
    try:
        assert scheduler.active_force() is None
        assert calls == ['failure']
        assert wait_for(lambda: job.get('_terminal_audit_done'))
        finish_force(job, 'completed')
        assert job['_terminal_outcome'] == 'failure'
        job['_security_store'].audit.assert_called_once()
    finally:
        o.lookup.stop()
        o.delivery.stop()
