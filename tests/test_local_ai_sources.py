"""Original producer provenance and bounded, revocable source leases."""
from concurrent.futures import Future
import copy
import importlib
import importlib.util
import threading
import time
from types import SimpleNamespace

import pytest

from http_api import relationship_handlers as rh
from http_api.read_model import BackgroundReadModel
from local_ai.contracts import AIError

ACTOR = {'id': 'a' * 32, 'session_id': 'b' * 32, 'role': 'operator'}


def context():
    def forbidden(*args, **kwargs):
        pytest.fail('source authority must not rebuild or enrich')
    return SimpleNamespace(shared_config={'config_revision': 7}, config_lock=threading.RLock(),
                           read_model=BackgroundReadModel(forbidden, forbidden))


def sources():
    assert importlib.util.find_spec('local_ai.sources') is not None, 'source lease implementation missing'
    return importlib.import_module('local_ai.sources')


class InlineExecutor:
    """Execute the unchanged real relationship producer without a pool."""
    def submit(self, function, *args):
        result = Future()
        result.set_result(function(*args))
        return result


def original_job(monkeypatch, ctx, *, actor=None, stamp=True, data=None):
    actor = ACTOR if actor is None else actor
    source = sources()
    service = rh.RelationshipJobService()
    service.executor = InlineExecutor()
    for name in ('begin_cache_batch', 'end_cache_batch', 'get_vt_runtime_config'):
        monkeypatch.setattr(rh, name, None)
    monkeypatch.setattr(rh, 'get_ip_report', lambda *a, **k: pytest.fail('intelligence request'))
    monkeypatch.setattr(rh, '_load_geoip_reader', lambda path: None)
    data = data or {'ips': ['192.0.2.1', '192.0.2.2'], 'include_vt': False,
                    'min_score': 1, 'pair_gate_enabled': False}
    authority = source.capture_relationship_stamp(ctx, actor, data) if stamp else None
    if stamp:
        source.validate_relationship_stamp(ctx, authority)
    admitted = rh.start_ip_relationship_job(data, principal=actor, service=service,
                                            ai_source_stamp=authority)
    job_id = admitted['job_id']
    result = rh.get_ip_relationship_job(job_id, include_result=True, principal=actor, service=service)[0]
    assert result['status'] == 'completed' and result['result']['pairs']
    pair = result['result']['pairs'][0]
    return service, {'job_id': job_id, 'a': pair['a'], 'b': pair['b']}, authority


def test_original_submission_retains_private_precapture_stamp_without_changing_result(monkeypatch):
    ctx = context()
    before = copy.deepcopy(ctx.shared_config)
    service, selector, stamp = original_job(monkeypatch, ctx)
    original, status = rh.get_ip_relationship_job(selector['job_id'], include_result=True,
                                                principal=ACTOR, service=service)
    assert status == 200
    assert service.jobs[selector['job_id']]['_ai_source_stamp'] == stamp
    assert '_ai_source_stamp' not in original
    assert '_ai_source_id' not in original
    assert ctx.shared_config == before
    sources().validate_relationship_stamp(ctx, stamp)
    ctx.shared_config['config_revision'] += 1
    with pytest.raises(AIError, match='source_revoked'):
        sources().validate_relationship_stamp(ctx, stamp)


def capture(monkeypatch, *, stamp=True, actor=None, data=None):
    ctx = context()
    service, selector, original_stamp = original_job(monkeypatch, ctx, stamp=stamp, actor=actor, data=data)
    return ctx, service, selector, original_stamp


@pytest.mark.parametrize('change,code', [
    ('missing', 'not_found'), ('unstamped', 'source_unavailable'), ('misp', 'source_unavailable'),
    ('cross-user', 'not_found'), ('cross-session', 'not_found'), ('admin-other-user', 'not_found'),
    ('admin-other-session', 'not_found'), ('current-viewer', 'source_revoked'),
    ('legacy-service', 'source_unavailable'), ('pending', 'source_not_ready'),
])
def test_source_eligibility_never_borrows_current_authority_or_admin_visibility(monkeypatch, change, code):
    ctx, service, selector, _ = capture(monkeypatch, stamp=change != 'unstamped', data=(
        {'ips': ['192.0.2.1', '192.0.2.2'], 'include_vt': False, 'min_score': 1,
         'pair_gate_enabled': False, 'misp_event_id': '17'} if change == 'misp' else None))
    actor = dict(ACTOR)
    if change == 'missing':
        service.jobs.clear()
    elif change in ('cross-user', 'admin-other-user'):
        actor['id'] = 'c' * 32
    elif change in ('cross-session', 'admin-other-session'):
        actor['session_id'] = 'c' * 32
    elif change == 'current-viewer':
        actor['role'] = 'viewer'
    elif change == 'legacy-service':
        service = rh._legacy_job_service
    elif change == 'pending':
        service.jobs[selector['job_id']]['status'] = 'running'
    if change.startswith('admin-'):
        actor['role'] = 'admin'
    with pytest.raises(AIError) as refused:
        sources().capture_pair(ctx, service, selector, actor, time.monotonic() + 10)
    assert refused.value.code == code


@pytest.mark.parametrize('mutation', ['config', 'security', 'hard', 'model', 'delete', 'expire',
                                      'digest', 'index', 'replace-job', 'replace-result'])
def test_pair_lease_revalidates_hard_authority_and_exact_original_source(monkeypatch, mutation):
    ctx, service, selector, _ = capture(monkeypatch)
    deadline = time.monotonic() + 10
    lease, encoded = sources().capture_pair(ctx, service, selector, ACTOR, deadline)
    ctx.read_model.invalidate(hard=False)
    lease.check(deadline)
    job = service.jobs[selector['job_id']]
    if mutation == 'config':
        ctx.shared_config['config_revision'] += 1
    elif mutation == 'security':
        ctx.shared_config['_security_projection_revision'] = 1
    elif mutation == 'hard':
        ctx.read_model.invalidate(hard=True)
    elif mutation == 'model':
        ctx.read_model = context().read_model
    elif mutation == 'delete':
        service.jobs.clear()
    elif mutation == 'expire':
        job['done_at'] = time.time() - rh._IP_REL_JOB_TTL_SECONDS - 1
    elif mutation == 'digest':
        job['result']['pairs'][0]['score'] += 1
    elif mutation == 'index':
        job['result']['pairs'].insert(0, {'a': '198.51.100.1', 'b': '198.51.100.2'})
    elif mutation == 'replace-job':
        service.jobs[selector['job_id']] = dict(job)
    elif mutation == 'replace-result':
        job['result'] = copy.deepcopy(job['result'])
    with pytest.raises(AIError, match='source_revoked'):
        lease.check(deadline)
    lease.dispose()
    assert b'analysis_as_of' in encoded


def test_initial_pair_lookup_caps_before_projection_then_rechecks_only_retained_index(monkeypatch):
    ctx, service, selector, _ = capture(monkeypatch)
    result = service.jobs[selector['job_id']]['result']
    selected = result['pairs'][0]
    other = {'a': '198.51.100.1', 'b': '198.51.100.2'}
    result['pairs'] = [other] * 4999 + [selected]
    deadline = time.monotonic() + 10
    lease, _ = sources().capture_pair(ctx, service, selector, ACTOR, deadline)
    # Reading any predecessor now would fail closed; exact-index revalidation succeeds.
    result['pairs'][:4999] = [object()] * 4999
    lease.check(deadline)
    lease.dispose()
    result['pairs'].append(selected)
    import local_ai.evidence as evidence
    monkeypatch.setattr(evidence, 'project_pair', lambda *a, **k: pytest.fail('oversize lookup projected'))
    with pytest.raises(AIError, match='too_large'):
        sources().capture_pair(ctx, service, selector, ACTOR, deadline)


@pytest.mark.parametrize('lock_name', ['config', 'jobs', 'model'])
def test_source_lock_contention_has_bounded_wait(monkeypatch, lock_name):
    ctx, service, selector, _ = capture(monkeypatch)
    lock = {'config': ctx.config_lock, 'jobs': service.lock, 'model': ctx.read_model._condition}[lock_name]
    entered, release = threading.Event(), threading.Event()
    def hold():
        with lock:
            entered.set()
            assert release.wait(3)
    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert entered.wait(1)
        start = time.monotonic()
        with pytest.raises(AIError, match='source_unavailable'):
            sources().capture_pair(ctx, service, selector, ACTOR, start + 2)
        assert time.monotonic() - start < 0.5
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive()


@pytest.mark.parametrize('mutation', ['hard', 'delete', 'digest'])
def test_invalidation_during_privacy_is_not_a_successful_source_check(monkeypatch, mutation):
    ctx, service, selector, _ = capture(monkeypatch)
    deadline = time.monotonic() + 10
    module = sources()
    lease, _ = module.capture_pair(ctx, service, selector, ACTOR, deadline)
    original = module.secret_free
    def invalidate(*args, **kwargs):
        safe = original(*args, **kwargs)
        if mutation == 'hard':
            ctx.read_model.invalidate(hard=True)
        elif mutation == 'delete':
            service.jobs.clear()
        else:
            service.jobs[selector['job_id']]['result']['pairs'][0]['score'] += 1
        return safe
    monkeypatch.setattr(module, 'secret_free', invalidate)
    with pytest.raises(AIError, match='source_revoked'):
        lease.check(deadline)
    lease.dispose()


def test_disposed_source_fences_in_progress_private_check(monkeypatch):
    ctx, service, selector, _ = capture(monkeypatch)
    deadline = time.monotonic() + 10
    module = sources()
    lease, _ = module.capture_pair(ctx, service, selector, ACTOR, deadline)
    original = module.secret_free
    entered, release = threading.Event(), threading.Event()
    outcome = []
    def pause(*args, **kwargs):
        safe = original(*args, **kwargs)
        entered.set()
        assert release.wait(3)
        return safe
    monkeypatch.setattr(module, 'secret_free', pause)
    def check():
        try:
            lease.check(deadline)
            outcome.append('published')
        except AIError as exc:
            outcome.append(exc.code)
    worker = threading.Thread(target=check)
    worker.start()
    try:
        assert entered.wait(2)
        lease.dispose()
        assert lease._ctx is None and lease._identity is None and lease._jobs is None
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive() and outcome == ['source_revoked']


@pytest.mark.parametrize('field', ['actor-user', 'actor-session', 'job-id', 'pair-identity'])
def test_private_stamp_must_agree_with_actual_original_job_provenance(monkeypatch, field):
    ctx, service, selector, _ = capture(monkeypatch)
    job = service.jobs[selector['job_id']]
    if field == 'actor-user':
        job['actor']['id'] = 'd' * 32
    elif field == 'actor-session':
        job['actor']['session_id'] = 'd' * 32
    elif field == 'job-id':
        job['job_id'] = 'd' * 32
    else:
        class UnknownIdentity:
            def __eq__(self, other):
                pytest.fail('malformed producer value was executed')
        job['result']['pairs'][0]['a'] = UnknownIdentity()
    with pytest.raises(AIError, match='source_unavailable'):
        sources().capture_pair(ctx, service, selector, ACTOR, time.monotonic() + 10)
