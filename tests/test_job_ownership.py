from concurrent.futures import Future
from unittest.mock import Mock
import pytest
from security.store import SecurityStore
from http_api import relationship_handlers as jobs

ALICE = {'id': 1, 'username': 'alice', 'role': 'operator'}
BOB = {'id': 2, 'username': 'bob', 'role': 'operator'}
ADMIN = {'id': 3, 'username': 'admin', 'role': 'admin'}


@pytest.fixture
def executor(monkeypatch):
    jobs._IP_REL_JOBS.clear()
    ex = Mock()
    ex.submit.side_effect = lambda *args: Future()
    monkeypatch.setattr(jobs, '_get_ip_rel_job_executor', lambda: ex)
    yield ex
    jobs._IP_REL_JOBS.clear()


def test_owner_access_and_per_user_capacity(executor):
    ids = [jobs.start_ip_relationship_job({'ips': ['1.1.1.1', '8.8.8.8']}, principal=ALICE)['job_id'] for _ in range(4)]
    with pytest.raises(jobs.RelationshipJobCapacityError):
        jobs.start_ip_relationship_job({'ips': ['1.1.1.1', '8.8.8.8']}, principal=ALICE)
    with pytest.raises(jobs.RelationshipJobCapacityError):
        jobs.ensure_ip_relationship_job_capacity(principal=ALICE)
    assert jobs.get_ip_relationship_job(ids[0], principal=BOB)[1] == 404
    assert jobs.cancel_ip_relationship_job(ids[0], principal=BOB)[1] == 404
    assert jobs.get_ip_relationship_job(ids[0], principal=ADMIN)[1] == 200
    jobs.start_ip_relationship_job({'ips': ['1.1.1.1', '8.8.8.8']}, principal=BOB)


@pytest.mark.parametrize('outcome', ['completed', 'failed', 'cancelled'])
def test_parent_callback_audits_terminal_once_without_payload(executor, outcome):
    store = Mock()
    job_id = jobs.start_ip_relationship_job({'ips': ['1.1.1.1', '8.8.8.8']},
        principal=ALICE, security_store=store, request_id='req', source_ip='127.0.0.1')['job_id']
    future = jobs._IP_REL_JOBS[job_id]['future']
    if outcome == 'completed':
        future.set_result({'payload': {'private': 'never audit'}, 'status_code': 200})
    elif outcome == 'failed':
        future.set_exception(RuntimeError('never audit'))
    else:
        jobs.cancel_ip_relationship_job(job_id, principal=ALICE)
    jobs._ip_rel_job_done(job_id, future)
    assert store.audit.call_count == 2
    args, kwargs = store.audit.call_args_list[-1]
    assert args == (ALICE, 'analysis.lifecycle')
    assert kwargs['status'] == outcome
    assert kwargs['job_id'] == job_id
    assert kwargs['request_id'] == 'req'
    assert 'never audit' not in str(store.audit.call_args)
    assert store not in executor.submit.call_args.args


def test_failed_completion_audit_is_visible_to_the_owner(executor):
    store = Mock()
    store.audit.side_effect = [None, OSError('audit unavailable')]
    job_id = jobs.start_ip_relationship_job({'ips': ['1.1.1.1', '8.8.8.8']},
        principal=ALICE, security_store=store)['job_id']
    jobs._IP_REL_JOBS[job_id]['future'].set_result({'payload': {}, 'status_code': 200})
    payload, status = jobs.get_ip_relationship_job(job_id, principal=ALICE)
    assert status == 200 and payload['audit_status'] == 'failed'


def test_restart_marks_unfinished_analysis_intent_unknown(executor, tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.sqlite', create=True)
    principal = store.bootstrap('alice', 'test-password-123')
    job_id = jobs.start_ip_relationship_job(
        {'ips': ['1.1.1.1', '8.8.8.8']}, principal=principal,
        security_store=store, request_id='interrupted', source_ip='127.0.0.1',
    )['job_id']
    assert store.audit_list(action='analysis.lifecycle', outcome='started')['total'] == 1
    assert store.reconcile_intents() == 1
    events = store.audit_list(action='analysis.lifecycle', outcome='unknown')['events']
    assert events[0]['job_id'] == job_id and events[0]['request_id'] == 'interrupted'