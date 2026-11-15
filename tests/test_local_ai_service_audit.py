"""Bounded lifecycle audit helpers on the actual private SQLite store."""
import sqlite3
import time
from contextlib import closing

import pytest

from security.store import SecurityError, SecurityStore


@pytest.fixture
def store(tmp_path):
    return SecurityStore(tmp_path / 'private/security.db', create=True)


def rows(store):
    with closing(sqlite3.connect(store.path.as_uri() + '?mode=ro', uri=True)) as db:
        return db.execute("SELECT action,target,outcome,status,job_id,details FROM audit_events "
                          "WHERE action='llm.lifecycle' ORDER BY rowid").fetchall()


def test_lifecycle_audit_is_once_only_fixed_grammar_and_bounded(store):
    assert hasattr(store, 'audit_llm_lifecycle'), 'bounded lifecycle audit helper is missing'
    store.ensure_llm_interlock()
    actor = {'id': 'a' * 32, 'username': 'admin', 'role': 'admin',
             'bearer': 'never-retain', 'digest': 'never-retain'}
    job = 'b' * 32
    assert store.audit_llm_lifecycle(job, actor, kind='delivery', outcome='started') is True
    assert store.audit_llm_lifecycle(job, actor, kind='delivery', outcome='started') is False
    assert store.audit_llm_lifecycle(job, actor, kind='delivery', outcome='completed') is True
    assert store.audit_llm_lifecycle(job, actor, kind='delivery', outcome='failed', error='provider_failed') is False
    assert rows(store) == [
        ('llm.lifecycle', 'delivery', 'started', None, job, '{}'),
        ('llm.lifecycle', 'delivery', 'completed', 200, job, '{}'),
    ]
    with closing(sqlite3.connect(store.path)) as writer:
        writer.execute('BEGIN IMMEDIATE')
        began = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match='locked'):
            store.audit_llm_lifecycle('c' * 32, actor, kind='delivery', outcome='started')
        assert time.monotonic() - began < 1.5
        writer.rollback()
    assert len(rows(store)) == 2


@pytest.mark.parametrize('kwargs', [
    {'job_id': 'model prose'}, {'kind': 'model prose'}, {'outcome': 'model prose'},
    {'request_id': 'x' * 129}, {'source_ip': 'model prose'}, {'error': 'model prose'},
])
def test_lifecycle_audit_refuses_unbounded_or_open_text(store, kwargs):
    assert hasattr(store, 'audit_llm_lifecycle'), 'bounded lifecycle audit helper is missing'
    values = {'job_id': 'b' * 32, 'kind': 'delivery', 'outcome': 'started', **kwargs}
    with pytest.raises(SecurityError, match='^Invalid lifecycle audit$'):
        store.audit_llm_lifecycle(actor=None, **values)
    assert rows(store) == []
