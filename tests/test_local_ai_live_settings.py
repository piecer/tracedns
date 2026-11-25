"""Live-owner barriers. Controlled engines isolate races, not provider acceptance."""
import threading
from types import SimpleNamespace

import pytest

from local_ai.contracts import AIError
from local_ai.provider_settings import normalize_settings
from local_ai.service import LocalAIService
from monitor.config_service import ConfigService
from test_local_ai_service import Engine, REQUEST, SETTINGS, Task, terminal, wait_for
from test_local_ai_service import account as account_fixture

account = account_fixture


COMPATIBLE = {'enabled': True, 'provider': 'openai_compatible',
              'base_url': 'http://127.0.0.1:9/v1', 'endpoint_policy': 'loopback',
              'model': 'fixture', 'api_key': 'fixture-only-Bearer',
              'token_limit_field': 'max_completion_tokens'}


class ResolverContract:
    """Explicit owner injection; NOT a real DNS resolver/transport substitute."""
    def __init__(self):
        self.retained = False
        self.deadlines = []
    def busy(self):
        return self.retained
    def retained_workers(self):
        return int(self.retained)
    def close(self, deadline):
        self.deadlines.append(deadline)
        return not self.retained


class PromptEngine(Engine):
    def prepare(self, request, actor, deadline, **kwargs):
        self.mode = kwargs
        return super().prepare(request, actor, deadline)


@pytest.mark.parametrize('status,code', [(400, 'provider_request_rejected'), (401, 'provider_auth_failed'),
    (403, 'provider_auth_failed'), (404, 'provider_request_rejected'),
    (422, 'provider_request_rejected'), (429, 'provider_rate_limited')])
def test_explicit_compatible_contract_rejection_settles_without_native_completion(account, status, code):
    from local_ai.provider_outcomes import ProviderRejected
    store, actor = account
    resolver = ResolverContract()
    observed = []
    class Adapter:
        def generate(self, messages, schema, deadline, *, before_send):
            before_send()
            return ProviderRejected(status)
    def factory(settings, *, resolver):
        observed.append((dict(settings), resolver))
        return Adapter()
    engine = PromptEngine(Task(native=True))
    owner = LocalAIService(COMPATIBLE, store, engine, provider_factory=factory, resolver=resolver)
    owner.start()
    try:
        job = owner.submit(REQUEST, actor)
        result = terminal(owner, job, actor)
        assert result['status'] == 'failed' and result['error'] == code and result['result'] is None
        assert result['audit_status'] == 'success'
        assert engine.mode == {'prompt_mode': 'json_object'}
        assert observed == [(COMPATIBLE, resolver)]
        assert store.llm_provider_state() == {'blocked': False, 'job_id': job['job_id'], 'outcome': 'http_rejected'}
        assert all(e['outcome'] != 'completed' for e in store.audit_list(action='llm.lifecycle')['events'])
    finally:
        assert owner.close()['complete']


def test_explicit_factory_constructor_contract_and_lazy_native_path():
    from local_ai.provider_factory import create_provider
    resolver = ResolverContract()
    observed = []
    adapter = object()
    def compatible(settings, *, resolver, clock):
        observed.append((settings, resolver, clock))
        return adapter
    clock = lambda: 0
    assert create_provider(COMPATIBLE, resolver=resolver, clock=clock, compatible_factory=compatible) is adapter
    assert observed == [(COMPATIBLE, resolver, clock)]
    assert create_provider({'enabled': False}, resolver=None) is None


def test_retained_resolver_blocks_admission_across_generation_and_close(account, tmp_path):
    store, actor = account
    resolver = ResolverContract()
    engine = Engine(Task())
    owner = LocalAIService(SETTINGS, store, engine, resolver=resolver)
    writer = ConfigService({'local_ai': SETTINGS}, threading.Lock(), str(tmp_path / 'config.json'))
    writer.local_ai = owner
    owner.start()
    try:
        resolver.retained = True  # Injected DNS owner outcome, not a service flag.
        save(writer, {'model': 'fixture:new'})
        with pytest.raises(AIError, match='busy'):
            owner.submit(REQUEST, actor)
        assert not engine.prepared
        assert owner.runtime()['state'] == 'draining'
        assert not owner.status(actor)['accepting']
        closed = owner.close(.1)
        assert not closed['complete'] and closed['retained_workers'] == 1
        assert resolver.deadlines
    finally:
        resolver.retained = False
        assert owner.close()['complete']


def live(store, engine, tmp_path, *, provider=None):
    settings = normalize_settings(SETTINGS)
    config = {'config_revision': 0, 'local_ai': settings}
    writer = ConfigService(config, threading.Lock(), str(tmp_path / 'config.json'))
    owner = LocalAIService(settings, store, engine, provider=provider)
    writer.local_ai = owner
    owner.start()
    return owner, writer


def save(writer, patch):
    revision = writer.snapshot()['config_revision']
    return writer.commit('ai_settings', {'revision': revision, 'settings': patch}, expected_revision=revision)


def thread_call(call):
    result = SimpleNamespace(value=None, error=None)
    def run():
        try:
            result.value = call()
        except Exception as exc:
            result.error = exc
    thread = threading.Thread(target=run)
    thread.start()
    return thread, result


@pytest.mark.parametrize('failed_name', ['local-ai-worker', 'local-ai-maintenance'])
def test_partial_worker_start_failure_stays_unavailable_across_save(account, tmp_path, monkeypatch, failed_name):
    store, _ = account
    owner = LocalAIService(None, store, Engine(Task()))
    writer = ConfigService({}, threading.Lock(), str(tmp_path / 'config.json'))
    writer.local_ai = owner
    original = threading.Thread.start
    started = []
    def start(thread):
        if thread.name == failed_name:
            raise RuntimeError('PRIVATE_THREAD_START')
        started.append(thread)
        return original(thread)
    monkeypatch.setattr(threading.Thread, 'start', start)
    try:
        first = save(writer, normalize_settings(SETTINGS))
        assert not first['runtime']['applied']
        second = save(writer, {'enabled': True})
        assert second['runtime'] == {'applied': False, 'state': 'unavailable'}
        assert not owner.source_admission_enabled()
        assert len(started) <= 1
    finally:
        assert owner.close()['complete']


def test_retired_adapter_reference_drops_after_actual_return(account, tmp_path):
    store, actor = account
    release = threading.Event()
    task = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    adapter = object()
    owner, writer = live(store, Engine(task), tmp_path, provider=adapter)
    try:
        receipt = owner.submit(REQUEST, actor)
        assert task.entered.wait(2)
        job = owner._active
        assert job.provider is adapter
        save(writer, {'model': 'fixture:new'})
        assert job.provider is adapter and owner._active is job
        release.set()
        wait_for(lambda: owner._active is None)
        assert job.provider is None
        with pytest.raises(AIError):
            owner.get(receipt['job_id'], actor)
    finally:
        release.set()
        assert owner.close()['complete']


def test_stop_before_send_hook_refuses_new_provider_reservation(account, tmp_path):
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    class Adapter:
        def generate(self, messages, schema, deadline, *, before_send):
            entered.set()
            assert release.wait(4)
            before_send()
            raise RuntimeError('unexpected dispatch permit after permanent stop')
    owner, _ = live(store, Engine(Task(native=True)), tmp_path, provider=Adapter())
    try:
        job = owner.submit(REQUEST, actor)
        assert entered.wait(2)
        owner.stop_admission()
        release.set()
        result = terminal(owner, job, actor)
        assert result['error'] == 'stopped'
        assert store.llm_provider_state()['outcome'] == 'absent'
    finally:
        release.set()
        assert owner.close()['complete']


def test_late_typed_rejection_cannot_release_reservation(account, monkeypatch):
    import time
    import local_ai.service as module
    from local_ai.provider_outcomes import ProviderRejected
    store, actor = account
    monkeypatch.setattr(module, 'DEADLINE_SECONDS', .3)
    class Adapter:
        def generate(self, messages, schema, deadline, *, before_send):
            before_send()
            wait_for(lambda: time.monotonic() > deadline)
            return ProviderRejected(401)
    owner = LocalAIService(COMPATIBLE, store, PromptEngine(Task(native=True)),
                           provider_factory=lambda *a, **k: Adapter(), resolver=ResolverContract())
    owner.start()
    try:
        result = terminal(owner, owner.submit(REQUEST, actor), actor)
        assert result['error'] == 'deadline_exceeded'
        assert store.llm_provider_state()['blocked']
    finally:
        assert owner.close()['complete']


def test_setup_and_disposal_run_outside_config_and_service_locks(account, tmp_path):
    store, actor = account
    release = threading.Event()
    task = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    owner, writer = live(store, Engine(task), tmp_path)
    checked = []
    def probe():
        for lock in (writer.config_lock, owner._lock):
            assert lock.acquire(blocking=False), 'config/service lock crossed callback'
            lock.release()
        checked.append(True)
    dispose = task.dispose
    def checked_dispose():
        probe()
        return dispose()
    task.dispose = checked_dispose
    factory = owner._factory
    def checked_factory(*args, **kwargs):
        probe()
        return factory(*args, **kwargs)
    owner._factory = checked_factory  # Explicit constructor boundary observation.
    try:
        owner.submit(REQUEST, actor)
        assert task.entered.wait(2)
        save(writer, {'model': 'fixture:new'})
        assert len(checked) >= 2
    finally:
        release.set()
        assert owner.close()['complete']


def test_stale_apply_callback_cannot_replace_new_generation(account, tmp_path):
    store, actor = account
    owner, writer = live(store, Engine(Task()), tmp_path)
    try:
        old = save(writer, {'model': 'fixture:old'})
        current = save(writer, {'model': 'fixture:current'})
        provider, workers = owner._provider, (owner._worker, owner._maintenance_worker)
        owner.apply_configuration(old['config']['local_ai'], old['revision'])
        assert owner._provider is provider
        assert owner._settings == current['config']['local_ai']
        assert (owner._worker, owner._maintenance_worker) == workers
        assert terminal(owner, owner.submit(REQUEST, actor), actor)['status'] == 'completed'
    finally:
        assert owner.close()['complete']


def test_reserved_queued_slot_is_retired_before_owned_worker_runs(account, tmp_path, monkeypatch):
    from test_local_ai_service import add_actor
    store, actor = account
    others = [add_actor(store, 'queued2'), add_actor(store, 'queued3')]
    entered, release = threading.Event(), threading.Event()
    original = LocalAIService._work
    def work(owner):
        entered.set()
        assert release.wait(4)
        return original(owner)
    monkeypatch.setattr(LocalAIService, '_work', work)
    tasks = [Task(), Task(), Task()]
    owner, writer = live(store, Engine(*tasks), tmp_path)
    try:
        assert entered.wait(2)
        jobs = [owner.submit(REQUEST, principal) for principal in [actor, *others]]
        assert all(job['status'] == 'queued' for job in jobs)
        save(writer, {'enabled': False})
        assert owner._active is None and not owner._users and not owner._queue
        assert all(task.disposed and not task.entered.is_set() for task in tasks)
        events = store.audit_list(action='llm.lifecycle')['events']
        assert len(events) == 6
        for job in jobs:
            assert [e['outcome'] for e in reversed(events) if e['job_id'] == job['job_id']] == ['started', 'failed']
    finally:
        release.set()
        assert owner.close()['complete']


def test_queued_retirement_is_once_audited_and_physical_slot_not_released(account, tmp_path):
    from test_local_ai_service import add_actor
    store, actor = account
    other, third = add_actor(store, 'second'), add_actor(store, 'third')
    release = threading.Event()
    first = Task(run=lambda d, g: (release.wait(4), b'{}')[1])
    second, last = Task(), Task()
    owner, writer = live(store, Engine(first, second, last), tmp_path)
    try:
        active = owner.submit(REQUEST, actor)
        assert first.entered.wait(2)
        queued = owner.submit(REQUEST, other)
        queued2 = owner.submit(REQUEST, third)
        save(writer, {'model': 'fixture:new'})
        assert owner._active.job_id == active['job_id']
        assert not owner._queue
        assert set(owner._users) == {actor['id']}
        assert first.disposed and second.disposed and last.disposed
        assert not second.entered.is_set() and not last.entered.is_set()
        events = store.audit_list(action='llm.lifecycle')['events']
        for job in (queued, queued2):
            assert [e['outcome'] for e in reversed(events) if e['job_id'] == job['job_id']] == ['started', 'failed']
        release.set()
        wait_for(lambda: owner._active is None)
        assert all(e['outcome'] != 'completed' for e in store.audit_list(action='llm.lifecycle')['events'])
    finally:
        release.set()
        assert owner.close()['complete']


@pytest.mark.parametrize('phase', ['before_reserve', 'inside_reserve', 'after_permit'])
def test_save_serializes_dispatch_permit_and_pins_admitted_adapter(account, tmp_path, monkeypatch, phase):
    from local_ai.provider_outcomes import ProviderRejected
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    sent = []
    def gate():
        entered.set()
        assert release.wait(4)
    original = store.begin_llm_provider
    def reserve(*args, **kwargs):
        value = original(*args, **kwargs)
        if phase == 'inside_reserve':
            gate()
        return value
    monkeypatch.setattr(store, 'begin_llm_provider', reserve)
    class Adapter:
        def __init__(self, settings):
            self.settings = dict(settings)
        def generate(self, messages, schema, deadline, *, before_send):
            if phase == 'before_reserve':
                gate()
            before_send()
            if phase == 'after_permit':
                gate()
            sent.append(self.settings)
            return ProviderRejected(401)
    factory = lambda settings, **kw: Adapter(settings)
    owner = LocalAIService(COMPATIBLE, store, PromptEngine(Task(native=True)),
                           provider_factory=factory, resolver=ResolverContract())
    writer = ConfigService({'local_ai': dict(COMPATIBLE)}, threading.Lock(), str(tmp_path / 'config.json'))
    writer.local_ai = owner
    owner.start()
    try:
        job = owner.submit(REQUEST, actor)
        assert entered.wait(2)
        save(writer, {'base_url': 'http://127.0.0.1:10/v1', 'api_key': 'new-fixture-only-key'})
        assert owner._active.job_id == job['job_id']
        release.set()
        wait_for(lambda: owner._active is None)
        assert sent == ([COMPATIBLE] if phase == 'after_permit' else [])
        state = store.llm_provider_state()
        assert state['blocked'] is (phase == 'inside_reserve')
        if phase == 'after_permit':
            assert state['outcome'] == 'http_rejected'
        assert all(e['outcome'] != 'completed' for e in store.audit_list(action='llm.lifecycle')['events'])
    finally:
        release.set()
        assert owner.close()['complete']


@pytest.mark.parametrize('failure', ['raise', 'false', 'wrong_type'])
def test_rejection_without_exact_durable_settlement_stays_quarantined(account, monkeypatch, failure):
    from local_ai.provider_outcomes import ProviderRejected
    store, actor = account
    class Adapter:
        def generate(self, messages, schema, deadline, *, before_send):
            before_send()
            return SimpleNamespace(http_status=401) if failure == 'wrong_type' else ProviderRejected(401)
    def reject(*args, **kwargs):
        if failure == 'raise':
            raise OSError('PRIVATE_REJECTION_AUDIT')
        return False
    monkeypatch.setattr(store, 'reject_llm_provider', reject)
    owner = LocalAIService(COMPATIBLE, store, PromptEngine(Task(native=True)),
                           provider_factory=lambda *a, **k: Adapter(), resolver=ResolverContract())
    owner.start()
    try:
        result = terminal(owner, owner.submit(REQUEST, actor), actor)
        assert result['error'] == {'raise': 'audit_unavailable', 'false': 'provider_unsettled',
                                   'wrong_type': 'provider_failed'}[failure]
        assert store.llm_provider_state()['blocked']
        assert not owner.status(actor)['accepting']
    finally:
        assert owner.close()['complete']


def test_final_terminal_audit_barrier_cannot_publish_after_save(account, tmp_path, monkeypatch):
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    original = store.audit_llm_lifecycle
    def audit(*args, **kwargs):
        if kwargs['outcome'] == 'completed':
            entered.set()
            assert release.wait(4)
        return original(*args, **kwargs)
    monkeypatch.setattr(store, 'audit_llm_lifecycle', audit)
    owner, writer = live(store, Engine(Task()), tmp_path)
    try:
        job = owner.submit(REQUEST, actor)
        assert entered.wait(2)
        save(writer, {'model': 'fixture:new'})
        release.set()
        wait_for(lambda: owner._active is None)
        with pytest.raises(AIError):
            owner.get(job['job_id'], actor)
        events = store.audit_list(action='llm.lifecycle')['events']
        assert [e['outcome'] for e in reversed(events)] == ['started', 'completed']
        assert not any(j.result for j in owner._jobs.values())
    finally:
        release.set()
        assert owner.close()['complete']


def test_save_never_clears_persistent_quarantine_even_while_disabled(account, tmp_path):
    store, actor = account
    owner, writer = live(store, Engine(Task()), tmp_path)
    try:
        assert store.begin_llm_provider('a' * 32, actor)
        receipt = save(writer, {'enabled': False})
        assert receipt['runtime']['state'] == 'unsettled'
        assert receipt['warnings'] == ['ai_provider_unsettled']
        receipt = save(writer, {'enabled': True})
        assert receipt['runtime']['state'] == 'unsettled'
        assert store.llm_provider_state()['job_id'] == 'a' * 32
        with pytest.raises(AIError, match='provider_unsettled'):
            owner.submit(REQUEST, actor)
    finally:
        assert owner.close()['complete']


def test_preparing_generation_is_captured_before_prepare_and_lease_released(account, tmp_path):
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    task = Task()
    def prepare(*args):
        entered.set()
        assert release.wait(4)
    owner, writer = live(store, Engine(task, prepare=prepare), tmp_path)
    thread, result = thread_call(lambda: owner.submit(REQUEST, actor))
    try:
        assert entered.wait(2)
        save(writer, {'model': 'fixture:new'})
        assert owner._preparing == {actor['id']}
        release.set()
        thread.join(4)
        assert not thread.is_alive()
        assert isinstance(result.error, AIError) and result.error.code == 'source_revoked'
        assert task.disposed and not owner._preparing and not owner._users
        assert not store.audit_list(action='llm.lifecycle')['events']
    finally:
        release.set()
        thread.join(4)
        assert owner.close()['complete']


def test_real_old_native_call_keeps_slot_settles_without_publication(account, tmp_path):
    from test_local_ai_provider import DIGEST, http_response, envelope, peer
    store, actor = account
    entered, release = threading.Event(), threading.Event()
    def reply(sock, stop):
        entered.set()
        assert release.wait(4)
        sock.sendall(http_response(envelope()))
    with peer(chat=reply) as (origin, requests, _):
        settings = normalize_settings({**SETTINGS, 'origin': origin, 'model_digest': DIGEST})
        config = {'config_revision': 0, 'local_ai': settings}
        writer = ConfigService(config, threading.Lock(), str(tmp_path / 'config.json'))
        owner = LocalAIService(settings, store, Engine(Task(native=True), Task()))
        writer.local_ai = owner
        owner.start()
        try:
            workers = owner._worker, owner._maintenance_worker
            job = owner.submit(REQUEST, actor)
            assert entered.wait(2)
            receipt = save(writer, {'enabled': False})
            assert receipt['runtime']['state'] == 'draining'
            save(writer, {'enabled': True, 'model': 'fixture:new'})
            assert (owner._worker, owner._maintenance_worker) == workers
            with pytest.raises(AIError) as denied:
                owner.submit(REQUEST, actor)
            assert denied.value.code in ('busy', 'provider_unsettled')
            with pytest.raises(AIError) as denied:
                owner.get(job['job_id'], actor)
            assert denied.value.code == 'source_revoked'
            release.set()
            wait_for(lambda: owner._active is None)
            assert store.llm_provider_state()['outcome'] == 'settled'
            assert len([r for r in requests if r['path'] == '/api/chat']) == 1
            assert all(e['outcome'] != 'completed' for e in store.audit_list(action='llm.lifecycle')['events'])
        finally:
            release.set()
            assert owner.close()['complete']


def test_terminal_result_is_revoked_without_rewriting_audit(account, tmp_path):
    store, actor = account
    task = Task()
    owner, writer = live(store, Engine(task), tmp_path)
    try:
        job = owner.submit(REQUEST, actor)
        assert terminal(owner, job, actor)['status'] == 'completed'
        before = store.audit_list(action='llm.lifecycle')['events']
        save(writer, {'model': 'fixture:new'})
        with pytest.raises(AIError) as denied:
            owner.get(job['job_id'], actor)
        assert denied.value.code in ('source_revoked', 'not_found')
        assert task.disposed
        assert store.audit_list(action='llm.lifecycle')['events'] == before
    finally:
        assert owner.close()['complete']


def test_stop_wins_over_late_enable_setup_without_new_workers(account, tmp_path, monkeypatch):
    store, actor = account
    owner = LocalAIService(None, store, Engine(Task()))
    writer = ConfigService({}, threading.Lock(), str(tmp_path / 'config.json'))
    writer.local_ai = owner
    entered, release = threading.Event(), threading.Event()
    original = store.ensure_llm_interlock
    def ensure():
        entered.set()
        assert release.wait(4)
        return original()
    monkeypatch.setattr(store, 'ensure_llm_interlock', ensure)
    thread, result = thread_call(lambda: save(writer, normalize_settings(SETTINGS)))
    try:
        assert entered.wait(2)
        owner.stop_admission()
        release.set()
        thread.join(4)
        assert not thread.is_alive() and result.error is None
        assert owner.runtime()['state'] == 'stopped'
        assert owner._worker is None and owner._maintenance_worker is None
        assert not owner.status(actor)['accepting']
        with pytest.raises(Exception) as denied:
            save(writer, {'enabled': False})
        assert getattr(denied.value, 'code', None) == 'stopped' or getattr(denied.value, 'status', None) == 503
        assert writer.snapshot()['config_revision'] == 1
    finally:
        release.set()
        thread.join(4)
        assert owner.close()['complete']
