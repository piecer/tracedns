import hashlib
import sqlite3

import pytest

from security.store import SecurityError, SecurityStore

PASSWORD = 'correct horse battery staple'


def test_sessions_are_digest_only_persistent_revocable_and_expire(tmp_path):
    now = [1000.0]
    store = SecurityStore(tmp_path / 'private' / 'auth.db', create=True,
                          idle_seconds=10, absolute_seconds=25, clock=lambda: now[0])
    admin = store.bootstrap('admin', PASSWORD)
    token, principal = store.login('ADMIN', PASSWORD, '127.0.0.1')
    assert principal == admin
    assert all(store.authenticate(token)[key] == value for key, value in admin.items())
    with sqlite3.connect(store.path) as db:
        rows = db.execute('SELECT * FROM sessions').fetchall()
        assert token not in str(rows)
        assert hashlib.sha256(token.encode()).hexdigest() in str(rows)
    assert SecurityStore(store.path, clock=lambda: now[0]).authenticate(token)['id'] == admin['id']
    now[0] += 9
    assert store.authenticate(token)
    now[0] += 9
    assert store.authenticate(token)
    now[0] += 8
    assert store.authenticate(token) is None
    token, _ = store.login('admin', PASSWORD, '127.0.0.1')
    now[0] += 10
    assert store.authenticate(token) is None
    token, _ = store.login('admin', PASSWORD, '127.0.0.1')
    entries = store.sessions(admin['id'])
    assert token not in str(entries)
    assert 'digest' not in str(entries)
    store.revoke_sessions(admin['id'], actor=admin, session_id=entries[0]['id'])
    assert store.authenticate(token) is None
    token, _ = store.login('admin', PASSWORD, '127.0.0.1')
    store.logout(token)
    assert store.authenticate(token) is None


def test_login_failure_is_uniform_persistently_limited(tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.db', create=True)
    store.bootstrap('admin', PASSWORD)
    for username in ('missing', 'admin'):
        with pytest.raises(SecurityError, match='Invalid credentials') as error:
            store.login(username, 'wrong', '127.0.0.1')
        assert error.value.status == 401
    for _ in range(8):
        with pytest.raises(SecurityError):
            store.login('missing', 'wrong', '127.0.0.1')
    with pytest.raises(SecurityError) as error:
        SecurityStore(store.path).login('admin', PASSWORD, '127.0.0.1')
    assert error.value.status == 429


def test_authenticated_principal_includes_public_session_id(tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.db', create=True)
    admin = store.bootstrap('admin', PASSWORD)
    token, _ = store.login('admin', PASSWORD, 'local')
    assert store.authenticate(token)['session_id'] == store.sessions(admin['id'])[0]['id']
