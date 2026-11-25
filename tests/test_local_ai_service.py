"""Service lifecycle with real SecurityStore and effect-controlled engine tasks.

Tasks isolate engine behavior only; successful/uncertain native exchanges below
use the real Ollama adapter against invocation-owned loopback peers.
"""
import importlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from local_ai.contracts import AIError
from security.store import SecurityStore

REQUEST = {'kind': 'delivery', 'language': 'en'}
SETTINGS = {'enabled': True, 'origin': 'http://127.0.0.1:9',
            'model': 'qwen3.5:9b', 'model_digest': 'a' * 64}


def service_module():
    try:
        module = importlib.import_module('local_ai.service')
    except ModuleNotFoundError:
        pytest.fail('bounded LocalAIService is missing')
    assert Path(module.__file__).resolve() == Path(__file__).resolve().parents[1] / 'local_ai/service.py'
    return module


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


class Task:
    """Trusted effect-controlled PreparedTask; NOT real engine acceptance."""
    retained_bytes = 100

    def __init__(self, *, native=False, run=None, check=None):
        self.native = native
        self.run_hook = run
        self.check_hook = check
        self.disposed = False
        self.entered = threading.Event()
        self.checks = []
        self.deadlines = []

    def check(self, deadline):
        self.checks.append(deadline)
        if self.disposed:
            raise AIError('source_revoked')
        if self.check_hook:
            self.check_hook(deadline)

    def run(self, deadline, generate):
        self.deadlines.append(deadline)
        self.entered.set()
        if self.run_hook:
            return self.run_hook(deadline, generate)
        if self.native:
            reply = generate([{'role': 'user', 'content': 'Synthetic facts.'}], {'type': 'object'})
            assert reply.content == '{"ok":true}'
        return b'{"snapshot":{"fact":"synthetic"},"model":null}'

    def dispose(self):
        self.disposed = True
        self.run_hook = None
        self.check_hook = None


class Engine:
    def __init__(self, *tasks, prepare=None):
        self.tasks = list(tasks)
        self.prepared = []
        self.prepare_hook = prepare

    def prepare(self, request, actor, deadline):
        self.prepared.append((request, actor, deadline))
        if self.prepare_hook:
            self.prepare_hook(request, actor, deadline)
        return self.tasks.pop(0)


def wait_for(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.005)
    pytest.fail('bounded wait expired')


def terminal(service, job, actor):
    def settled():
        value = service.get(job['job_id'], actor)
        return value if value['status'] in ('completed', 'failed', 'cancelled') and value['audit_status'] != 'pending' else None
    return wait_for(settled)


def test_real_native_success_is_authorized_settled_audited_and_public(account):
    from test_local_ai_provider import DIGEST, peer

    module = service_module()
    store, actor = account
    task = Task(native=True)
    engine = Engine(task)
    with peer() as (origin, requests, _):
        service = module.LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST}, store, engine)
        assert requests == []
        service.start()
        try:
            job = service.submit(REQUEST, actor, request_id='request-1', source_ip='127.0.0.1')
            result = terminal(service, job, actor)
            assert set(result) == {'job_id', 'kind', 'language', 'status', 'created_at', 'deadline_at',
                                   'audit_status', 'error', 'result', 'cancel_requested'}
            assert result['status'] == 'completed'
            assert result['audit_status'] == 'success'
            assert result['result'] == {'snapshot': {'fact': 'synthetic'}, 'model': None}
            assert result['error'] is None
            assert result['deadline_at'] - result['created_at'] == 120000
            assert len(result['job_id']) == 32
            assert len(encode(result)) <= 32768
            # Ancillary GET/sweep checks have a shorter read budget; only the
            # prepare/run/native work lease must be identical and never renewed.
            assert task.checks and all(d <= task.deadlines[0] for d in task.checks)
            assert task.deadlines[0] in task.checks
            assert engine.prepared[0][2] == task.deadlines[0]
            assert [r['path'] for r in requests] == ['/api/tags', '/api/chat']
            assert store.llm_provider_state() == {'blocked': False, 'job_id': job['job_id'], 'outcome': 'settled'}
            events = store.audit_list(action='llm.lifecycle')['events']
            assert [(e['outcome'], e['job_id']) for e in reversed(events)] == [
                ('started', job['job_id']), ('completed', job['job_id'])]
            assert service.status(actor)['active_job'] is None
        finally:
            assert service.close()['complete']


@pytest.mark.parametrize('fault', ['malformed', 'truncated', 'oversized', 'timeout'])
def test_uncertain_real_native_reservation_survives_restart_and_prune(account, monkeypatch, fault):
    from test_local_ai_provider import DIGEST, http_response, peer

    module = service_module()
    store, actor = account
    if fault == 'timeout':
        monkeypatch.setattr(module, 'DEADLINE_SECONDS', .15)
    response = {'malformed': http_response(b'{not JSON'),
                'truncated': b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{}',
                'oversized': http_response(b'x' * 65537),
                'timeout': lambda sock, stop: stop.wait(.5)}[fault]
    task = Task(native=True)
    with peer(chat=response) as (origin, requests, _):
        settings = {**SETTINGS, 'origin': origin, 'model_digest': DIGEST}
        service = module.LocalAIService(settings, store, Engine(task))
        service.start()
        try:
            job = service.submit(REQUEST, actor)
            result = terminal(service, job, actor)
            assert result['status'] == 'failed' and result['result'] is None
            assert store.llm_provider_state()['blocked'] is True
            assert service.status(actor)['provider_state'] == 'unsettled'
        finally:
            assert service.close()['complete']
        store.retention_days = -1
        store.prune_audit()
        engine = Engine(Task(native=True))
        restarted = module.LocalAIService(settings, store, engine)
        restarted.start()
        try:
            before = len(requests)
            with pytest.raises(AIError, match='^provider_unsettled$'):
                restarted.submit(REQUEST, actor)
            assert engine.prepared == []
            assert len(requests) == before
            assert store.llm_provider_state()['job_id'] == job['job_id']
        finally:
            assert restarted.close()['complete']


def test_native_content_error_settles_before_fixed_output_failure(account):
    from test_local_ai_provider import DIGEST, envelope, http_response, peer

    store, actor = account
    with peer(chat=http_response(envelope('x' * 16385))) as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST},
                                                 store, Engine(Task(native=True)))
        service.start()
        try:
            result = terminal(service, service.submit(REQUEST, actor), actor)
            assert result['error'] == 'invalid_model_output'
            assert result['result'] is None and result['status'] == 'failed'
            assert store.llm_provider_state()['outcome'] == 'settled'
            assert len(requests) == 2
        finally:
            assert service.close()['complete']


def add_actor(store, name, role='operator', *, same_user=None):
    # Real DB fixture identities; only the successful tracer needs password login.
    with store._db() as db:
        user = same_user or store._insert_user(db, name, 'not-a-login-hash', role, False)
        session = secrets.token_hex(16)
        now = store.clock()
        db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)',
                   (session, secrets.token_hex(32), user['id'], now, now, now + 43200))
    return store.authorize_session(session, user['id'], (role,))


def test_one_physical_worker_two_queues_and_one_unfinished_per_user(account):
    store, actor = account
    others = [add_actor(store, 'op' + str(i)) for i in range(3)]
    other_session = add_actor(store, 'ignored', 'admin', same_user=actor)
    release = threading.Event()
    first = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    tasks = [first, Task(), Task(), Task()]
    engine = Engine(*tasks)
    service = service_module().LocalAIService(SETTINGS, store, engine)
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        assert first.entered.wait(2)
        with pytest.raises(AIError, match='^busy$'):
            service.submit(REQUEST, other_session)
        queued = [service.submit(REQUEST, op) for op in others[:2]]
        assert service.status(actor)['queued'] == 2
        assert service.status(other_session)['active_job'] is None
        assert service.status(actor)['active_job'] == {'job_id': job['job_id'], 'kind': 'delivery', 'status': 'running'}
        with pytest.raises(AIError, match='^busy$'):
            service.submit(REQUEST, others[2])
        assert len(engine.prepared) == 3
        assert not tasks[1].entered.is_set() and not tasks[2].entered.is_set()
        release.set()
        assert terminal(service, job, actor)['status'] == 'completed'
        for queued_job, op in zip(queued, others):
            assert terminal(service, queued_job, op)['status'] == 'completed'
        assert store.llm_provider_state()['outcome'] == 'absent'
    finally:
        release.set()
        assert service.close()['complete']


def test_preparation_reservations_are_bounded_and_release_on_failure(account):
    store, actor = account
    actors = [actor] + [add_actor(store, 'op' + str(i)) for i in range(3)]
    entered = []
    release = threading.Event()
    errors = []

    def prepare(request, principal, deadline):
        entered.append(principal['id'])
        assert release.wait(4)
        raise AIError('source_unavailable')

    engine = Engine(prepare=prepare)
    service = service_module().LocalAIService(SETTINGS, store, engine)
    service.start()

    def submit(principal):
        try:
            service.submit(REQUEST, principal)
        except AIError as e:
            errors.append(e.code)

    threads = [threading.Thread(target=submit, args=(a,)) for a in actors[:3]]
    try:
        for thread in threads:
            thread.start()
        wait_for(lambda: len(entered) == 3)
        with pytest.raises(AIError, match='^busy$'):
            service.submit(REQUEST, actors[3])
        with pytest.raises(AIError, match='^busy$'):
            service.submit(REQUEST, actor)
        release.set()
        for thread in threads:
            thread.join(2)
            assert not thread.is_alive()
        assert errors == ['source_unavailable'] * 3
        assert service._jobs == {}
        assert store.audit_list(action='llm.lifecycle')['total'] == 0
        engine.prepare_hook = None
        engine.tasks.append(Task())
        assert terminal(service, service.submit(REQUEST, actor), actor)['status'] == 'completed'
    finally:
        release.set()
        for thread in threads:
            thread.join(3)
        assert service.close()['complete']


def test_late_preparation_expires_without_allocating_job_id(account, monkeypatch):
    from types import SimpleNamespace

    module = service_module()
    monkeypatch.setattr(module, 'DEADLINE_SECONDS', .02)
    ids = []
    monkeypatch.setattr(module, 'secrets', SimpleNamespace(token_hex=lambda n: ids.append(n) or 'b' * 32))
    task = Task()
    engine = Engine(task, prepare=lambda r, a, d: time.sleep(.04))
    service = module.LocalAIService(SETTINGS, account[0], engine)
    service.start()
    try:
        with pytest.raises(AIError, match='^deadline_exceeded$'):
            service.submit(REQUEST, account[1])
        assert ids == []
        assert task.disposed
        assert service._jobs == {}
    finally:
        assert service.close()['complete']


def test_running_cancel_drains_real_native_queued_cancel_is_confirmed(account):
    from test_local_ai_provider import DIGEST, envelope, http_response, peer

    store, actor = account
    other = add_actor(store, 'operator')
    release = threading.Event()
    sent = threading.Event()

    def response(sock, stop):
        sent.set()
        assert release.wait(4)
        sock.sendall(http_response(envelope()))

    running, queued = Task(native=True), Task(native=True)
    with peer(chat=response) as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST},
                                                 store, Engine(running, queued))
        service.start()
        try:
            first = service.submit(REQUEST, actor)
            assert sent.wait(2)
            second = service.submit(REQUEST, other)
            cancelled = service.cancel(second['job_id'], other)
            assert cancelled['status'] == 'cancelled'
            assert cancelled['cancellation_requested'] and cancelled['cancellation_confirmed']
            assert queued.disposed and not queued.entered.is_set()
            pending = service.cancel(first['job_id'], actor)
            assert pending['status'] == 'cancel_pending'
            assert pending['cancellation_requested'] and not pending['cancellation_confirmed']
            assert running.disposed
            assert service.get(first['job_id'], actor)['result'] is None
            assert store.llm_provider_state()['blocked']
            shutdown = service.close(timeout=.02)
            assert not shutdown['complete'] and shutdown['retained_workers'] == 1
            assert len(requests) == 2
            release.set()
            done = terminal(service, first, actor)
            assert done['status'] == 'cancelled' and done['result'] is None
            assert not store.llm_provider_state()['blocked']
            assert service.cancel(first['job_id'], actor)['cancellation_confirmed']
            events = store.audit_list(action='llm.lifecycle')['events']
            assert sorted((e['outcome'], e['job_id']) for e in events) == sorted([
                (outcome, job['job_id']) for job in (first, second) for outcome in ('started', 'cancelled')])
        finally:
            release.set()
            assert service.close()['complete']


def test_admin_cannot_get_or_cancel_other_user_or_session_and_terminal_is_truthful(account):
    store, admin = account
    owner = add_actor(store, 'owner')
    same = add_actor(store, 'unused', 'operator', same_user=owner)
    task = Task()
    service = service_module().LocalAIService(SETTINGS, store, Engine(task))
    service.start()
    try:
        job = service.submit(REQUEST, owner)
        complete = terminal(service, job, owner)
        for actor in (admin, same):
            with pytest.raises(AIError, match='^not_found$'):
                service.get(job['job_id'], actor)
            with pytest.raises(AIError, match='^not_found$'):
                service.cancel(job['job_id'], actor)
        response = service.cancel(job['job_id'], owner)
        assert response == {**complete, 'cancellation_requested': False, 'cancellation_confirmed': False}
        assert not task.disposed
    finally:
        assert service.close()['complete']


@pytest.mark.parametrize('phase', ['intent', 'reservation', 'settlement', 'terminal'])
def test_real_sql_audit_failure_never_publishes_or_retries(account, phase):
    from test_local_ai_provider import DIGEST, peer

    store, actor = account
    predicate = {
        'intent': "NEW.action='llm.lifecycle' AND NEW.outcome='started'",
        'reservation': "NEW.action='llm.provider' AND NEW.outcome='started'",
        'settlement': "NEW.action='llm.provider' AND NEW.outcome='settled'",
        'terminal': "NEW.action='llm.lifecycle' AND NEW.outcome='completed'",
    }[phase]
    with store._db() as db:
        db.execute("CREATE TRIGGER audit_fault BEFORE INSERT ON audit_events WHEN " + predicate +
                   " BEGIN SELECT RAISE(ABORT, 'private audit failure prose'); END")
    task = Task(native=True)
    engine = Engine(task, Task(native=True))
    with peer() as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST}, store, engine)
        service.start()
        try:
            if phase == 'intent':
                with pytest.raises(AIError, match='^audit_unavailable$'):
                    service.submit(REQUEST, actor)
                assert requests == []
            else:
                result = terminal(service, service.submit(REQUEST, actor), actor)
                assert result['status'] == 'failed'
                assert result['error'] == 'audit_unavailable' and result['result'] is None
                if phase == 'terminal':
                    assert result['audit_status'] == 'failed'
                assert sum(r['path'] == '/api/chat' for r in requests) == (0 if phase == 'reservation' else 1)
                assert store.llm_provider_state()['blocked'] == (phase == 'settlement')
            assert task.disposed
            before = len(requests)
            with pytest.raises(AIError, match='^(audit_unavailable|provider_unsettled)$'):
                service.submit(REQUEST, actor)
            assert len(engine.prepared) == 1 and len(requests) == before
        finally:
            assert service.close()['complete']


def test_reservation_commit_then_raise_during_cancel_stays_uncertain(account, monkeypatch):
    from test_local_ai_provider import DIGEST, peer

    store, actor = account
    entered, release = threading.Event(), threading.Event()
    original = store.begin_llm_provider

    def begin(*args, **kwargs):
        assert original(*args, **kwargs)
        entered.set()
        assert release.wait(4)
        raise sqlite3.OperationalError('private commit acknowledgement failure')

    monkeypatch.setattr(store, 'begin_llm_provider', begin)
    with peer() as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST},
                                                 store, Engine(Task(native=True)))
        service.start()
        try:
            job = service.submit(REQUEST, actor)
            assert entered.wait(2)
            assert not service.cancel(job['job_id'], actor)['cancellation_confirmed']
            release.set()
            result = terminal(service, job, actor)
            assert result['status'] == 'failed' and result['error'] == 'audit_unavailable'
            assert not service.cancel(job['job_id'], actor)['cancellation_confirmed']
            assert store.llm_provider_state()['blocked']
            assert [r['path'] for r in requests] == ['/api/tags']
        finally:
            release.set()
            assert service.close()['complete']


def test_generate_callback_permits_at_most_one_native_call(account):
    from test_local_ai_provider import DIGEST, peer

    def twice(deadline, generate):
        for _ in range(2):
            generate([{'role': 'user', 'content': 'synthetic'}], {'type': 'object'})
        return b'{}'

    store, actor = account
    with peer() as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST},
                                                 store, Engine(Task(run=twice)))
        service.start()
        try:
            result = terminal(service, service.submit(REQUEST, actor), actor)
            assert result['status'] == 'failed' and result['error'] == 'verification_failed'
            assert [r['path'] for r in requests] == ['/api/tags', '/api/chat']
            assert not store.llm_provider_state()['blocked']
        finally:
            assert service.close()['complete']


@pytest.mark.parametrize('payload,code', [
    ({**REQUEST, 'endpoint': 'http://127.0.0.1:9'}, 'invalid_request'),
    ({'kind': 'delivery', 'language': 'x' * 20000}, 'too_large'),
    ({**REQUEST, 'extra': float('nan')}, 'invalid_request'),
    ({**REQUEST, 'extra': 1 << 1000}, 'invalid_request'),
    ({**REQUEST, 'extra': object()}, 'invalid_request'),
    (None, 'invalid_request'),
])
def test_defensive_request_refusal_precedes_capture_and_native(account, payload, code):
    store, actor = account
    engine = Engine(Task(native=True))
    service = service_module().LocalAIService(SETTINGS, store, engine)
    service.start()
    try:
        with pytest.raises(AIError, match='^' + code + '$'):
            service.submit(payload, actor)
        assert engine.prepared == []
        assert store.llm_provider_state()['outcome'] == 'absent'
        assert store.audit_list(action='llm.lifecycle')['total'] == 0
    finally:
        assert service.close()['complete']


@pytest.mark.parametrize('charge', [-1, True, 65537])
def test_prepared_task_charge_is_bounded_before_job_allocation(account, charge):
    store, actor = account
    task = Task()
    task.retained_bytes = charge
    engine = Engine(task, Task())
    service = service_module().LocalAIService(SETTINGS, store, engine)
    service.start()
    try:
        with pytest.raises(AIError, match='^too_large$'):
            service.submit(REQUEST, actor)
        assert task.disposed and not task.entered.is_set()
        assert service._jobs == {}
        assert terminal(service, service.submit(REQUEST, actor), actor)['status'] == 'completed'
    finally:
        assert service.close()['complete']


def test_decoder_admin_role_with_bounded_request_contract_fixture(account, monkeypatch):
    # Coverage is service role enforcement only. The independent engine branch
    # adds decoder validation; this seed load_request supports delivery/pair.
    module = service_module()
    original = module.contracts.load_request
    decoder = {'kind': 'decoder_suggest', 'language': 'en', 'decoder_type': 'TXT',
               'samples': [], 'generate': False}

    def bounded_decoder(raw):
        if raw == encode(decoder):
            return json.loads(raw)
        return original(raw)

    monkeypatch.setattr(module.contracts, 'load_request', bounded_decoder)
    store, admin = account
    operator = add_actor(store, 'operator')
    engine = Engine(Task())
    service = module.LocalAIService(SETTINGS, store, engine)
    service.start()
    try:
        with pytest.raises(AIError, match='^source_revoked$'):
            service.submit(decoder, operator)
        assert engine.prepared == []
        assert terminal(service, service.submit(decoder, admin), admin)['kind'] == 'decoder_suggest'
        assert store.llm_provider_state()['outcome'] == 'absent'
    finally:
        assert service.close()['complete']


@pytest.mark.parametrize('extra', [0, 1])
def test_whole_envelope_limit_includes_cancellation_fields(account, extra):
    store, actor = account
    release = threading.Event()
    output = []
    task = Task(run=lambda d, g: (release.wait(3), output[0])[1])
    service = service_module().LocalAIService(SETTINGS, store, Engine(task))
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        shell = {**job, 'status': 'completed', 'audit_status': 'success', 'result': {'pad': ''},
                 'cancellation_requested': False, 'cancellation_confirmed': False}
        count = 32768 - len(encode(shell)) + extra
        output.append(encode({'pad': 'x' * count}))
        assert len(output[0]) < 32768, 'this tests the ENVELOPE, not the raw result limit'
        release.set()
        result = terminal(service, job, actor)
        if extra:
            assert result['status'] == 'failed' and result['error'] == 'too_large'
            assert task.disposed
        else:
            assert result['status'] == 'completed'
            assert len(encode(service.cancel(job['job_id'], actor))) == 32768
        assert len(encode(result)) <= 32768
    finally:
        release.set()
        assert service.close()['complete']


def test_terminal_count_and_ttl_evict_source_and_result_together(account, monkeypatch):
    module = service_module()
    store, actor = account
    tasks = [Task() for _ in range(34)]
    service = module.LocalAIService(SETTINGS, store, Engine(*tasks))
    service.start()
    try:
        jobs = []
        for _ in tasks:
            job = service.submit(REQUEST, actor)
            assert terminal(service, job, actor)['status'] == 'completed'
            wait_for(lambda: service.status(actor)['provider_state'] == 'ready')
            jobs.append(job)
        assert len(service._jobs) == 32
        for job, task in zip(jobs[:2], tasks):
            with pytest.raises(AIError, match='^not_found$'):
                service.get(job['job_id'], actor)
            assert task.disposed
        assert module.RETENTION_SECONDS == 600
        # Move just the recorded retention age; do not fake auth/provider clocks.
        with service._lock:
            service._jobs[jobs[2]['job_id']].terminal_at -= 601
        with pytest.raises(AIError, match='^not_found$'):
            service.get(jobs[2]['job_id'], actor)
        assert tasks[2].disposed
    finally:
        assert service.close()['complete']


def test_aggregate_complete_record_bytes_not_result_bytes(account, monkeypatch):
    module = service_module()
    assert getattr(module, 'RETAINED_BYTES', None) == 1048576
    monkeypatch.setattr(module, 'RETAINED_BYTES', 1000)
    store, actor = account
    tasks = [Task(run=lambda d, g: encode({'pad': 'x' * 350})) for _ in range(2)]
    service = module.LocalAIService(SETTINGS, store, Engine(*tasks))
    service.start()
    try:
        jobs = []
        for _ in tasks:
            jobs.append(service.submit(REQUEST, actor))
            assert terminal(service, jobs[-1], actor)['status'] == 'completed'
            wait_for(lambda: service.status(actor)['provider_state'] == 'ready')
        assert len(service._jobs) == 1, '700 result bytes fit, both complete records do not'
        assert tasks[0].disposed
        with pytest.raises(AIError, match='^not_found$'):
            service.get(jobs[0]['job_id'], actor)
    finally:
        assert service.close()['complete']


def test_maintenance_retires_unpolled_revocation_during_blocked_work(account):
    store, admin = account
    owner = add_actor(store, 'owner')
    release = threading.Event()
    first = Task()
    blocked = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    service = service_module().LocalAIService(SETTINGS, store, Engine(first, blocked))
    service.start()
    try:
        job = service.submit(REQUEST, owner)
        assert terminal(service, job, owner)['status'] == 'completed'
        current = service.submit(REQUEST, admin)
        assert blocked.entered.wait(2)
        store.revoke_sessions(owner['id'], actor=admin)
        # No GET/status calls can drive this maintenance.
        wait_for(lambda: first.disposed, timeout=2)
        assert job['job_id'] not in service._jobs
        assert not blocked.disposed
        with pytest.raises(AIError, match='^not_found$'):
            service.get(job['job_id'], admin)
        release.set()
        assert terminal(service, current, admin)['status'] == 'completed'
    finally:
        release.set()
        assert service.close()['complete']


def test_background_authority_checks_do_not_touch_expiring_sessions(account):
    store, actor = account
    with store._read_db() as db:
        before = tuple(db.execute('SELECT * FROM sessions').fetchone())
    service = service_module().LocalAIService(SETTINGS, store, Engine(Task()))
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        assert terminal(service, job, actor)['status'] == 'completed'
        for _ in range(3):
            service.status(actor)
            service.get(job['job_id'], actor)
        with store._read_db() as db:
            assert tuple(db.execute('SELECT * FROM sessions').fetchone()) == before
        store.clock = lambda: before[4] + store.idle_seconds
        with pytest.raises(AIError, match='^source_revoked$'):
            service.get(job['job_id'], actor)
        assert job['job_id'] not in service._jobs
        with store._read_db() as db:
            assert tuple(db.execute('SELECT * FROM sessions').fetchone()) == before
    finally:
        assert service.close()['complete']


def test_sweep_expires_queued_job_at_original_deadline_during_running_work(account, monkeypatch):
    module = service_module()
    store, actor = account
    other = add_actor(store, 'queued')
    release = threading.Event()
    first, second = Task(run=lambda d, g: (release.wait(4), b'{}')[1]), Task(native=True)
    service = module.LocalAIService(SETTINGS, store, Engine(first, second))
    service.start()
    try:
        running = service.submit(REQUEST, actor)
        assert first.entered.wait(2)
        monkeypatch.setattr(module, 'DEADLINE_SECONDS', .1)
        queued = service.submit(REQUEST, other)
        wait_for(lambda: second.disposed, timeout=2)
        result = terminal(service, queued, other)
        assert result['error'] == 'deadline_exceeded'
        assert result['deadline_at'] == queued['deadline_at']
        assert not second.entered.is_set()
        assert not store.llm_provider_state()['blocked']
        release.set()
        assert terminal(service, running, actor)['status'] == 'completed'
    finally:
        release.set()
        assert service.close()['complete']


def test_source_invalidation_after_terminal_audit_prevents_publication(account, monkeypatch):
    store, actor = account
    invalid = threading.Event()
    entered, release = threading.Event(), threading.Event()

    def check(deadline):
        if invalid.is_set():
            raise AIError('source_revoked')

    task = Task(check=check)
    original = store.audit_llm_lifecycle

    def audit(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs['outcome'] == 'completed':
            entered.set()
            assert release.wait(4)
            invalid.set()
        return result

    monkeypatch.setattr(store, 'audit_llm_lifecycle', audit)
    service = service_module().LocalAIService(SETTINGS, store, Engine(task))
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        assert entered.wait(2)
        pending = service.get(job['job_id'], actor)
        assert pending['audit_status'] == 'pending' and pending['result'] is None
        release.set()
        wait_for(lambda: task.disposed)
        # The job may be retired by maintenance; it must never become usable.
        try:
            result = service.get(job['job_id'], actor)
        except AIError as e:
            assert e.code in ('not_found', 'source_revoked')
        else:
            assert result['status'] == 'failed' and result['error'] == 'source_revoked'
            assert result['result'] is None
        assert store.audit_list(action='llm.lifecycle')['total'] == 2
    finally:
        release.set()
        assert service.close()['complete']


def test_close_stops_queued_dispatch_retires_references_and_never_replaces_worker(account):
    store, actor = account
    other = add_actor(store, 'queued')
    release = threading.Event()
    first = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    second = Task()
    engine = Engine(first, second)
    service = service_module().LocalAIService(SETTINGS, store, engine)
    service.start()
    original_worker = service._worker
    try:
        running = service.submit(REQUEST, actor)
        assert first.entered.wait(2)
        queued = service.submit(REQUEST, other)
        service.stop_admission()
        with pytest.raises(AIError, match='^stopped$'):
            service.submit(REQUEST, other)
        state = service.close(timeout=.05)
        assert not state['complete'] and state['retained_workers'] == 1
        assert first.disposed and second.disposed
        assert not second.entered.is_set()
        service.start()
        assert service._worker is original_worker
        release.set()
        assert service.close()['complete']
        assert not second.entered.is_set()
        for job, owner in ((running, actor), (queued, other)):
            result = service.get(job['job_id'], owner)
            assert result['status'] == 'failed' and result['error'] == 'stopped' and result['result'] is None
        assert not store.llm_provider_state()['blocked']
    finally:
        release.set()
        assert service.close()['complete']


def test_close_reports_incomplete_while_admitted_preparation_is_blocked(account):
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    task = Task()
    errors = []

    def prepare(r, a, d):
        entered.set()
        assert release.wait(4)

    service = service_module().LocalAIService(SETTINGS, store, Engine(task, prepare=prepare))
    service.start()

    def submit():
        try:
            service.submit(REQUEST, actor)
        except AIError as error:
            errors.append(error.code)

    thread = threading.Thread(target=submit)
    thread.start()
    try:
        assert entered.wait(2)
        assert not service.close(timeout=.02)['complete']
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        assert errors == ['stopped'] and task.disposed
        assert service.close()['complete']
        assert service._jobs == {}
    finally:
        release.set()
        thread.join(3)
        service.close()


def test_registry_lock_is_never_held_across_external_work(account, monkeypatch):
    from test_local_ai_provider import DIGEST, peer

    store, actor = account
    calls = []
    service = None

    def probe(name):
        # Allow an unrelated worker's finite registry section to finish; a
        # callback invoked under this non-reentrant lock cannot release it.
        acquired = service._lock.acquire(timeout=.1)
        assert acquired, name + ' was called with registry lock held'
        service._lock.release()
        calls.append(name)

    task = Task(native=True, check=lambda d: probe('check'))
    original_dispose = task.dispose

    def dispose():
        probe('dispose')
        original_dispose()

    task.dispose = dispose
    engine = Engine(task, prepare=lambda r, a, d: probe('prepare'))
    for name in ('authorize_session', 'llm_provider_state', 'begin_llm_provider',
                 'settle_llm_provider', 'audit_llm_lifecycle'):
        original = getattr(store, name)

        def checked(*args, _name=name, _original=original, **kwargs):
            probe(_name)
            return _original(*args, **kwargs)

        monkeypatch.setattr(store, name, checked)
    with peer() as (origin, _, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST}, store, engine)
        service.start()
        try:
            job = service.submit(REQUEST, actor)
            assert terminal(service, job, actor)['status'] == 'completed'
        finally:
            assert service.close()['complete']
        assert {'prepare', 'check', 'dispose', 'authorize_session', 'llm_provider_state',
                'begin_llm_provider', 'settle_llm_provider', 'audit_llm_lifecycle'} <= set(calls)


def test_live_native_status_is_busy_and_stale_settlement_cannot_clear_successor(account):
    from test_local_ai_provider import DIGEST, envelope, http_response, peer

    store, actor = account
    entered, release = threading.Event(), threading.Event()

    def response(sock, stop):
        entered.set()
        assert release.wait(4)
        sock.sendall(http_response(envelope()))

    with peer(chat=response) as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST},
                                                 store, Engine(Task(native=True)))
        service.start()
        try:
            job = service.submit(REQUEST, actor)
            assert entered.wait(2)
            state = service.status(actor)
            assert state['provider_state'] == 'busy' and state['accepting']
            # This deliberately simulates an external OFFLINE recovery followed
            # by a successor; the live service never performs recovery itself.
            assert store.acknowledge_llm_provider_stopped(job['job_id'], tracedns_stopped=True, provider_stopped=True)
            assert store.begin_llm_provider('c' * 32, actor)
            release.set()
            result = terminal(service, job, actor)
            assert result['error'] == 'provider_unsettled' and result['result'] is None
            assert store.llm_provider_state() == {'blocked': True, 'job_id': 'c' * 32, 'outcome': 'started'}
            assert service.status(actor)['provider_state'] == 'unsettled'
            assert len(requests) == 2
        finally:
            release.set()
            assert service.close()['complete']


def test_queued_job_does_not_dispatch_after_prior_terminal_audit_failure(account, monkeypatch):
    from test_local_ai_provider import DIGEST, envelope, http_response, peer

    store, actor = account
    other = add_actor(store, 'queued')
    entered, release = threading.Event(), threading.Event()

    def response(sock, stop):
        entered.set()
        assert release.wait(4)
        sock.sendall(http_response(envelope()))

    with store._db() as db:
        db.execute("CREATE TRIGGER audit_fault BEFORE INSERT ON audit_events "
                   "WHEN NEW.action='llm.lifecycle' AND NEW.outcome='completed' "
                   "BEGIN SELECT RAISE(ABORT, 'private prose'); END")
    second = Task(native=True)
    with peer(chat=response) as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST},
                                                 store, Engine(Task(native=True), second))
        service.start()
        try:
            first = service.submit(REQUEST, actor)
            assert entered.wait(2)
            queued = service.submit(REQUEST, other)
            release.set()
            assert terminal(service, first, actor)['error'] == 'audit_unavailable'
            assert terminal(service, queued, other)['error'] == 'audit_unavailable'
            assert not second.entered.is_set()
            assert [r['path'] for r in requests] == ['/api/tags', '/api/chat']
            assert service.status(actor)['provider_state'] == 'unavailable'
        finally:
            release.set()
            assert service.close()['complete']


def test_physical_slot_is_distinct_from_two_queues_before_worker_runs(account, monkeypatch):
    module = service_module()
    store, actor = account
    others = [add_actor(store, 'op' + str(i)) for i in range(2)]
    entered, release = threading.Event(), threading.Event()
    original = module.LocalAIService._work

    def paused(self):
        entered.set()
        assert release.wait(4)
        original(self)

    monkeypatch.setattr(module.LocalAIService, '_work', paused)
    tasks = [Task() for _ in range(3)]
    service = module.LocalAIService(SETTINGS, store, Engine(*tasks))
    service.start()
    try:
        assert entered.wait(2)
        jobs = [service.submit(REQUEST, a) for a in [actor, *others]]
        assert service.status(actor)['queued'] == 2
        cancelled = service.cancel(jobs[0]['job_id'], actor)
        assert cancelled['cancellation_confirmed']
        assert not tasks[0].entered.is_set()
        release.set()
        for job, a in zip(jobs[1:], others):
            assert terminal(service, job, a)['status'] == 'completed'
    finally:
        release.set()
        assert service.close()['complete']


def test_eviction_releases_idle_worker_frame_references(account):
    import weakref

    store, actor = account
    service = service_module().LocalAIService(SETTINGS, store, Engine(Task()))
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        terminal(service, job, actor)
        wait_for(lambda: service.status(actor)['provider_state'] == 'ready')
        with service._lock:
            reference = weakref.ref(service._jobs[job['job_id']])
            service._jobs[job['job_id']].terminal_at -= 601
        with pytest.raises(AIError, match='^not_found$'):
            service.get(job['job_id'], actor)
        wait_for(lambda: reference() is None, timeout=1)
    finally:
        assert service.close()['complete']


def test_retirement_during_final_source_check_cannot_republish_result(account, monkeypatch):
    store, actor = account
    fired = threading.Event()
    task = Task()
    service = service_module().LocalAIService(SETTINGS, store, Engine(task))
    original = service._check

    def check(job):
        original(job)
        if job.finishing and job.status == 'completed' and not fired.is_set():
            fired.set()
            # Deterministic concurrent-retirement boundary: after the final
            # successful authority read but before registry publication.
            service._invalidate(job, 'source_revoked')

    monkeypatch.setattr(service, '_check', check)
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        result = terminal(service, job, actor)
        assert fired.is_set() and task.disposed
        assert result['status'] == 'failed' and result['error'] == 'source_revoked'
        assert result['result'] is None
    finally:
        assert service.close()['complete']


def test_close_while_startup_is_blocked_does_not_create_late_workers(account, monkeypatch):
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    original = store.ensure_llm_interlock

    def ensure():
        entered.set()
        assert release.wait(4)
        original()

    monkeypatch.setattr(store, 'ensure_llm_interlock', ensure)
    service = service_module().LocalAIService(SETTINGS, store, Engine())
    thread = threading.Thread(target=service.start)
    thread.start()
    try:
        assert entered.wait(2)
        assert not service.close(timeout=.01)['complete']
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        assert service._worker is None and service._maintenance_worker is None
        assert service.close()['complete']
    finally:
        release.set()
        thread.join(3)
        service.close()


def test_blocked_maintenance_check_keeps_shutdown_truthfully_incomplete(account):
    store, actor = account
    entered, release = threading.Event(), threading.Event()

    def check(deadline):
        if threading.current_thread().name == 'local-ai-maintenance':
            entered.set()
            assert release.wait(4)

    task = Task(check=check)
    service = service_module().LocalAIService(SETTINGS, store, Engine(task))
    service.start()
    try:
        terminal(service, service.submit(REQUEST, actor), actor)
        assert entered.wait(2)
        before = time.monotonic()
        state = service.close(timeout=.02)
        assert time.monotonic() - before < .5
        assert not state['complete'] and state['retained_workers'] == 1
        release.set()
        assert service.close()['complete']
        assert task.disposed
    finally:
        release.set()
        assert service.close()['complete']


def test_pending_terminal_audit_keeps_owner_handle_without_result(account, monkeypatch):
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    original = store.audit_llm_lifecycle

    def audit(*args, **kwargs):
        if kwargs['outcome'] == 'completed':
            entered.set()
            assert release.wait(4)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, 'audit_llm_lifecycle', audit)
    service = service_module().LocalAIService(SETTINGS, store, Engine(Task()))
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        assert entered.wait(2)
        response = service.get(job['job_id'], actor)
        assert response['audit_status'] == 'pending' and response['result'] is None
        assert service.status(actor)['active_job'] == {'job_id': job['job_id'], 'kind': 'delivery', 'status': 'completed'}
        with pytest.raises(AIError, match='^busy$'):
            service.submit(REQUEST, actor)
        release.set()
        assert terminal(service, job, actor)['audit_status'] == 'success'
    finally:
        release.set()
        assert service.close()['complete']


def test_concurrent_owner_cancellation_has_one_terminal_audit(account):
    store, actor = account
    other = add_actor(store, 'queued')
    release = threading.Event()
    running = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    queued = Task()
    service = service_module().LocalAIService(SETTINGS, store, Engine(running, queued))
    service.start()
    responses = []
    start = threading.Barrier(3)

    def cancel():
        start.wait(timeout=2)
        responses.append(service.cancel(job['job_id'], other))

    threads = [threading.Thread(target=cancel) for _ in range(2)]
    try:
        service.submit(REQUEST, actor)
        assert running.entered.wait(2)
        job = service.submit(REQUEST, other)
        for thread in threads:
            thread.start()
        start.wait(timeout=2)
        for thread in threads:
            thread.join(2)
            assert not thread.is_alive()
        assert len(responses) == 2
        assert all(r['cancellation_requested'] for r in responses)
        assert terminal(service, job, other)['status'] == 'cancelled'
        assert queued.disposed and not queued.entered.is_set()
        events = store.audit_list(action='llm.lifecycle')['events']
        assert [(e['outcome']) for e in events if e['job_id'] == job['job_id']].count('cancelled') == 1
    finally:
        release.set()
        for thread in threads:
            if thread.ident:
                thread.join(2)
        assert service.close()['complete']


@pytest.mark.parametrize('fault', ['idle', 'absolute', 'role', 'inactive', 'password', 'revoked'])
def test_current_authority_refuses_before_capture_with_zero_native(account, fault):
    store, actor = account
    if fault in ('idle', 'absolute'):
        with store._db() as db:
            db.execute('UPDATE sessions SET ' + ('last_seen=0' if fault == 'idle' else 'expires=0'))
    elif fault == 'revoked':
        store.revoke_sessions(actor['id'], actor=actor)
    else:
        column, value = {'role': ('role', 'viewer'), 'inactive': ('active', 0),
                         'password': ('must_change_password', 1)}[fault]
        with store._db() as db:
            db.execute(f'UPDATE users SET {column}=?', (value,))
    engine = Engine(Task(native=True))
    service = service_module().LocalAIService(SETTINGS, store, engine)
    service.start()
    try:
        with pytest.raises(AIError, match='^source_revoked$'):
            service.submit(REQUEST, actor)
        assert engine.prepared == []
        assert store.llm_provider_state()['outcome'] == 'absent'
        assert store.audit_list(action='llm.lifecycle')['total'] == 0
    finally:
        assert service.close()['complete']


def test_source_revocation_during_native_call_discards_but_settles(account):
    from test_local_ai_provider import DIGEST, envelope, http_response, peer

    store, actor = account
    entered, release, invalid = threading.Event(), threading.Event(), threading.Event()

    def response(sock, stop):
        entered.set()
        assert release.wait(4)
        sock.sendall(http_response(envelope()))

    def check(deadline):
        if invalid.is_set():
            raise AIError('source_revoked')

    task = Task(native=True, check=check)
    with peer(chat=response) as (origin, requests, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST}, store, Engine(task))
        service.start()
        try:
            job = service.submit(REQUEST, actor)
            assert entered.wait(2)
            invalid.set()
            wait_for(lambda: task.disposed)
            assert store.llm_provider_state()['blocked']
            release.set()
            result = terminal(service, job, actor)
            assert result['error'] == 'source_revoked' and result['result'] is None
            assert not store.llm_provider_state()['blocked']
            assert len(requests) == 2
        finally:
            release.set()
            assert service.close()['complete']


def test_bad_model_content_is_validated_only_after_native_settlement(account, caplog):
    from test_local_ai_provider import DIGEST, envelope, http_response, peer

    store, actor = account
    sentinel = 'private model prose not JSON'
    validated = []

    def run(deadline, generate):
        reply = generate([{'role': 'user', 'content': 'synthetic'}], {'type': 'object'})
        assert store.llm_provider_state()['outcome'] == 'settled'
        assert reply.content == sentinel
        validated.append(True)
        raise AIError('invalid_model_output')

    with peer(chat=http_response(envelope(sentinel))) as (origin, _, _):
        service = service_module().LocalAIService({**SETTINGS, 'origin': origin, 'model_digest': DIGEST}, store, Engine(Task(run=run)))
        service.start()
        try:
            result = terminal(service, service.submit(REQUEST, {**actor, 'bearer': sentinel, 'digest': sentinel}), actor)
            assert result['error'] == 'invalid_model_output' and validated == [True]
            assert sentinel not in json.dumps(result)
            assert sentinel not in json.dumps(store.audit_list())
            assert sentinel not in caplog.text
        finally:
            assert service.close()['complete']


def test_status_hides_decoder_handle_after_current_role_loss(account, monkeypatch):
    module = service_module()
    original = module.contracts.load_request
    decoder = {'kind': 'decoder_suggest', 'language': 'en', 'decoder_type': 'TXT',
               'samples': [], 'generate': False}
    monkeypatch.setattr(module.contracts, 'load_request',
                        lambda raw: json.loads(raw) if raw == encode(decoder) else original(raw))
    store, actor = account
    release = threading.Event()
    task = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    service = module.LocalAIService(SETTINGS, store, Engine(task))
    service.start()
    try:
        service.submit(decoder, actor)
        assert task.entered.wait(2)
        with store._db() as db:
            db.execute("UPDATE users SET role='operator' WHERE id=?", (actor['id'],))
        assert service.status(actor)['active_job'] is None
        assert task.disposed
    finally:
        release.set()
        assert service.close()['complete']


def test_terminal_audit_delay_cannot_extend_original_work_deadline(account, monkeypatch):
    from types import SimpleNamespace

    module = service_module()
    offset = [0]
    monkeypatch.setattr(module, 'time', SimpleNamespace(time=time.time, monotonic=lambda: time.monotonic() + offset[0]))
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    original = store.audit_llm_lifecycle

    def audit(*args, **kwargs):
        if kwargs['outcome'] == 'completed':
            entered.set()
            assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, 'audit_llm_lifecycle', audit)
    task = Task()
    service = module.LocalAIService(SETTINGS, store, Engine(task))
    service.start()
    try:
        job = service.submit(REQUEST, actor)
        assert entered.wait(2)
        assert job['deadline_at'] - job['created_at'] == 120000
        offset[0] = 121  # Advance observation time, never change the job lease.
        release.set()
        result = terminal(service, job, actor)
        assert result['error'] == 'deadline_exceeded' and result['result'] is None
        assert task.disposed
    finally:
        release.set()
        assert service.close()['complete']


@pytest.fixture
def account(tmp_path):
    store = SecurityStore(tmp_path / 'private/security.db', create=True)
    store.bootstrap('admin', 'correct horse battery staple')
    token, _ = store.login('admin', 'correct horse battery staple', '127.0.0.1')
    actor = store.authenticate(token, touch=False)
    return store, actor


@pytest.mark.parametrize('settings', [[], {'enabled': 1}, {'enabled': True},
    {**SETTINGS, 'endpoint': 'http://127.0.0.1:9'},
    {**SETTINGS, 'origin': 'http://example.com:80'},
    {**SETTINGS, 'model_digest': 'a' * 63},
    {**SETTINGS, 'model': 'cloud:latest'}])
def test_startup_settings_are_closed_even_with_injected_provider(account, settings):
    module = service_module()
    with pytest.raises(AIError):
        module.LocalAIService(settings, account[0], object(), provider=object())


def test_constructor_validates_without_dialing(account, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        pytest.fail('constructor dialed')

    monkeypatch.setattr(socket, 'socket', forbidden)
    service = service_module().LocalAIService(SETTINGS, account[0], object())
    assert service.close()['complete']


def test_disabled_defaults_are_zero_effect_and_public_status_is_closed(account):
    module = service_module()
    store, actor = account

    class Forbidden:
        def __getattr__(self, name):
            pytest.fail('disabled service must not access engine/provider: ' + name)

    service = module.LocalAIService({}, store, Forbidden(), provider=Forbidden())
    service.start()
    try:
        assert service.status(actor) == {
            'enabled': False, 'accepting': False, 'provider_state': 'disabled',
            'queued': 0, 'active_job': None,
        }
        with pytest.raises(AIError, match='^disabled$'):
            service.submit(REQUEST, actor)
        assert store.llm_provider_state()['outcome'] == 'absent'
    finally:
        assert service.close() == {'complete': True, 'retained_workers': 0}
