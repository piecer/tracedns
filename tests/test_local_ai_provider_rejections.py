"""HTTP rejection is a matching-job audit fact, not a model completion."""
import sqlite3
import time
from contextlib import closing, contextmanager
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from security.store import SecurityError, SecurityStore


@pytest.fixture
def store(tmp_path):
    value = SecurityStore(tmp_path / 'private' / 'security.db', create=True, retention_days=1)
    value.ensure_llm_interlock()
    return value


def provider_rows(store):
    with closing(sqlite3.connect(store.path.as_uri() + '?mode=ro', uri=True)) as db:
        return db.execute("SELECT outcome,status,job_id,details FROM audit_events "
                          "WHERE action='llm.provider' ORDER BY rowid").fetchall()


@pytest.mark.parametrize('status', [400, 401, 403, 404, 422, 429])
def test_complete_http_rejection_releases_only_matching_reservation_once(store, status):
    assert hasattr(store, 'reject_llm_provider'), 'matching HTTP rejection transition is missing'
    first, successor = 'a' * 32, 'b' * 32
    assert store.reject_llm_provider(first, actor=None, http_status=status) is False
    assert store.begin_llm_provider(first, None)
    assert store.reject_llm_provider(successor, actor=None, http_status=status) is False
    assert store.reject_llm_provider(first, actor=None, http_status=status) is True
    assert store.reject_llm_provider(first, actor=None, http_status=status) is False
    assert store.llm_provider_state() == {'blocked': False, 'job_id': first, 'outcome': 'http_rejected'}
    assert SecurityStore(store.path).llm_provider_state() == store.llm_provider_state()
    assert provider_rows(store) == [('started', None, first, '{}'), ('http_rejected', status, first, '{}')]
    assert store.begin_llm_provider(successor, None)
    assert store.reject_llm_provider(first, actor=None, http_status=status) is False
    assert store.llm_provider_state() == {'blocked': True, 'job_id': successor, 'outcome': 'started'}


@pytest.mark.parametrize('status', [400, 401, 403, 404, 422, 429])
def test_rejection_receipt_is_a_closed_frozen_non_model_outcome(status):
    from local_ai import provider_outcomes
    assert hasattr(provider_outcomes, 'ProviderRejected'), 'typed rejection receipt is missing'
    receipt = provider_outcomes.ProviderRejected(status)
    assert [field.name for field in fields(receipt)] == ['http_status']
    assert receipt.http_status == status
    assert not hasattr(receipt, 'content') and not hasattr(receipt, 'metadata')
    with pytest.raises(FrozenInstanceError):
        setattr(receipt, 'http_status', 500)
    with pytest.raises(ValueError, match='^Invalid provider rejection$'):
        replace(receipt, http_status=500)


@pytest.mark.parametrize('status', [None, True, '401', 401.0, 200, 302, 408, 500, 599])
def test_unclassified_status_cannot_release_or_change_a_reservation(store, status):
    from local_ai.provider_outcomes import ProviderRejected
    with pytest.raises(ValueError, match='^Invalid provider rejection$'):
        ProviderRejected(status)
    job = 'a' * 32
    assert store.begin_llm_provider(job, None)
    before = provider_rows(store)
    with pytest.raises(SecurityError, match='^Invalid provider rejection$'):
        store.reject_llm_provider(job, http_status=status)
    assert provider_rows(store) == before
    assert store.llm_provider_state()['blocked'] is True


@pytest.mark.parametrize('status', [None, 200, 302, 408, 500])
def test_malformed_persisted_rejection_remains_quarantined(store, status):
    store.audit(None, 'llm.provider', outcome='http_rejected', status=status, job_id='a' * 32)
    assert store.llm_provider_state()['blocked'] is True
    assert not store.begin_llm_provider('b' * 32, None)


def test_rejection_audit_failure_rolls_back_without_releasing(store):
    job = 'a' * 32
    assert store.begin_llm_provider(job, None)
    before = provider_rows(store)
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("CREATE TRIGGER deny_rejection AFTER INSERT ON audit_events "
                   "WHEN NEW.outcome='http_rejected' BEGIN SELECT RAISE(ABORT, 'fixture rejection denied'); END")
    with pytest.raises(sqlite3.DatabaseError, match='fixture rejection denied'):
        store.reject_llm_provider(job, http_status=401)
    assert provider_rows(store) == before
    assert store.llm_provider_state()['blocked'] is True


def test_rejection_commit_then_observer_error_does_not_fabricate_rollback(store, monkeypatch):
    job = 'a' * 32
    assert store.begin_llm_provider(job, None)
    original = store._llm_db

    @contextmanager
    def commit_then_raise():
        with original() as db:
            yield db
        raise OSError('fixture postcommit observer failure')

    monkeypatch.setattr(store, '_llm_db', commit_then_raise)
    with pytest.raises(OSError, match='fixture postcommit observer failure'):
        store.reject_llm_provider(job, http_status=401)
    assert SecurityStore(store.path).llm_provider_state() == {
        'blocked': False, 'job_id': job, 'outcome': 'http_rejected'}
    assert provider_rows(store)[-1] == ('http_rejected', 401, job, '{}')


def test_rejection_proof_survives_pruning_and_reconciliation(store, monkeypatch):
    job = 'a' * 32
    assert store.begin_llm_provider(job, {'bearer': 'fixture-private-bearer'})
    assert store.reject_llm_provider(job, actor={'api_key': 'fixture-private-key'}, http_status=429)
    assert store.reconcile_intents() == 0
    now = store.clock()
    monkeypatch.setattr(store, 'clock', lambda: now + 86401)
    store.prune_audit()
    assert provider_rows(store) == [('http_rejected', 429, job, '{}')]
    restarted = SecurityStore(store.path)
    assert restarted.llm_provider_state() == {'blocked': False, 'job_id': job, 'outcome': 'http_rejected'}
    assert restarted.begin_llm_provider('b' * 32, None)


@pytest.mark.parametrize('job_id', [None, '', 1, False, b'job'])
def test_rejection_job_identity_is_not_coerced(store, job_id):
    assert store.begin_llm_provider('a' * 32, None)
    before = provider_rows(store)
    with pytest.raises(SecurityError, match='job ID'):
        store.reject_llm_provider(job_id, http_status=401)
    assert provider_rows(store) == before


def test_rejection_uses_bounded_writer_and_preserves_uncertainty(store):
    job = 'a' * 32
    assert store.begin_llm_provider(job, None)
    before = provider_rows(store)
    with closing(sqlite3.connect(store.path)) as writer, writer:
        writer.execute('BEGIN EXCLUSIVE')
        started = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match='locked'):
            store.reject_llm_provider(job, http_status=401)
        assert time.monotonic() - started < 2
    assert provider_rows(store) == before
    assert store.llm_provider_state()['blocked'] is True
