import os
import sqlite3

import pytest


def test_initialization_is_explicit_private_and_versioned(tmp_path):
    from security.store import SecurityStore, SecurityError

    path = tmp_path / 'private' / 'auth.db'
    with pytest.raises(SecurityError):
        SecurityStore(path)
    store = SecurityStore(path, create=True)
    assert not store.has_admin()
    assert os.stat(path.parent).st_mode & 0o777 == 0o700
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert not SecurityStore(path).has_admin()
    with sqlite3.connect(path) as conn:
        assert conn.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        conn.execute('UPDATE schema_version SET version=999')
    with pytest.raises(SecurityError):
        SecurityStore(path)


def test_audit_filters_redaction_retention_and_atomic_failures(tmp_path):
    from security.store import SecurityStore
    now = [1000.0]
    store = SecurityStore(tmp_path / 'private' / 'auth.db', create=True,
                          retention_days=1, clock=lambda: now[0])
    admin = store.bootstrap('admin', 'correct horse battery staple')
    event = store.audit(admin, 'test.action', target='record', request_id='req',
                        source_ip='127.0.0.1', status=202, job_id='job',
                        details={'password': 'SECRET', 'role': 'viewer',
                                 'active': False, 'count': 2, 'url': 'SECRET'})
    result = store.audit_list(user_id=admin['id'], action='test.action', outcome='success',
                              target='record', since=999, until=1001, limit=1)
    assert result['total'] == 1
    assert result['events'][0]['id'] == event
    assert result['events'][0]['details'] == {'role': 'viewer', 'active': False, 'count': 2}
    assert 'SECRET' not in str(result)
    assert store.audit_list(offset=2)['events'] == []
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TRIGGER audit_fail BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
    with pytest.raises(sqlite3.DatabaseError):
        store.create_user('viewer', 'correct horse battery staple', 'viewer', actor=admin)
    assert len(store.list_users()) == 1
    with sqlite3.connect(store.path) as db:
        db.execute('DROP TRIGGER audit_fail')
    now[0] += 86401
    assert store.prune_audit() == 2
    events = store.audit_list()['events']
    assert len(events) == 1
    assert events[0]['action'] == 'audit.prune'
    assert events[0]['details']['count'] == 2
