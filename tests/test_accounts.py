import sqlite3

import pytest

from security.store import SecurityError, SecurityStore

PASSWORD = 'correct horse battery staple'


def test_bootstrap_accounts_and_password_policy(tmp_path):
    from security.passwords import hash_password, verify_password

    for password in ('short', 'x' * 129):
        with pytest.raises(SecurityError):
            hash_password(password)
    encoded = hash_password(PASSWORD)
    assert encoded.startswith('$argon2id$')
    assert verify_password(encoded, PASSWORD)
    assert not verify_password(encoded, 'wrong')
    store = SecurityStore(tmp_path / 'private' / 'auth.db', create=True)
    admin = store.bootstrap('Admin', PASSWORD)
    assert admin['username'] == 'admin'
    assert admin['role'] == 'admin'
    assert not admin['must_change_password']
    assert store.has_admin()
    with pytest.raises(SecurityError):
        store.bootstrap('other', PASSWORD)
    user = store.create_user('Viewer', PASSWORD, 'viewer', actor=admin)
    assert user['must_change_password']
    assert store.get_user(user['id']) == user
    assert len(store.list_users()) == 2
    assert 'password_hash' not in str(store.list_users())
    with pytest.raises(SecurityError):
        store.create_user('viewer', PASSWORD, 'viewer', actor=admin)
    with pytest.raises(SecurityError):
        store.create_user('bad', PASSWORD, 'root', actor=admin)
    with pytest.raises(SecurityError):
        store.create_user('bad', PASSWORD, 'viewer', actor=user)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0] == 2


def test_account_changes_revoke_sessions_and_protect_last_admin(tmp_path):
    store = SecurityStore(tmp_path / 'private' / 'auth.db', create=True)
    admin = store.bootstrap('admin', PASSWORD)
    with pytest.raises(SecurityError):
        store.update_user(admin['id'], actor=admin, active=False)
    with pytest.raises(SecurityError):
        store.update_user(admin['id'], actor=admin, role='viewer')
    user = store.create_user('viewer', PASSWORD, 'viewer', actor=admin)
    token, _ = store.login('viewer', PASSWORD, 'local')
    updated = store.update_user(user['id'], actor=admin, role='operator')
    assert updated['role'] == 'operator'
    assert store.authenticate(token) is None
    token, _ = store.login('viewer', PASSWORD, 'local')
    store.update_user(user['id'], actor=admin, password='another secure password')
    assert store.authenticate(token) is None
    with pytest.raises(SecurityError):
        store.change_password(user['id'], 'wrong', PASSWORD, actor=user)
    token, user = store.login('viewer', 'another secure password', 'local')
    changed = store.change_password(user['id'], 'another secure password', PASSWORD, actor=user)
    assert not changed['must_change_password']
    assert store.authenticate(token) is None
    store.update_user(user['id'], actor=admin, active=False)
    with pytest.raises(SecurityError):
        store.login('viewer', PASSWORD, 'local')


def test_concurrent_last_admin_demotion_is_serialized(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    store = SecurityStore(tmp_path / 'private' / 'auth.db', create=True)
    one = store.bootstrap('one', PASSWORD)
    two = store.create_user('two', PASSWORD, 'admin', actor=one)
    def demote(user):
        try:
            store.update_user(user['id'], actor=user, role='viewer')
            return True
        except SecurityError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(demote, (one, two))) == [False, True]
    assert store.has_admin()


def test_cli_bootstrap_and_audited_local_recovery(tmp_path, monkeypatch, capsys):
    from security.cli import main
    path = tmp_path / 'private' / 'auth.db'
    monkeypatch.setattr('security.cli.getpass.getpass', lambda prompt: PASSWORD)
    assert main(['--db', str(path), 'bootstrap', 'admin']) == 0
    store = SecurityStore(path)
    token, _ = store.login('admin', PASSWORD, 'local')
    replacement = 'replacement password is long'
    monkeypatch.setattr('security.cli.getpass.getpass', lambda prompt: replacement)
    assert main(['--db', str(path), 'reset-password', 'admin']) == 0
    assert store.authenticate(token) is None
    _, principal = store.login('admin', replacement, 'local')
    assert principal['must_change_password']
    assert store.audit_list(action='account.local_reset')['total'] == 1
    assert replacement not in capsys.readouterr().out
    answers = iter([PASSWORD, replacement])
    monkeypatch.setattr('security.cli.getpass.getpass', lambda prompt: next(answers))
    assert main(['--db', str(path), 'reset-password', 'admin']) == 1
    with pytest.raises(SystemExit):
        main(['--db', str(path), 'reset-password', 'admin', '--password', PASSWORD])
