"""Local-AI authorization and durable physical-provider settlement contracts."""
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace

import security.store as store_module

import pytest

from security.store import SecurityError, SecurityStore

PASSWORD = 'correct horse battery staple'


def test_local_ai_store_and_recovery_import_from_this_checkout():
    import local_ai.recover as recover

    root = Path(__file__).resolve().parents[1]
    assert Path(store_module.__file__).resolve() == root / 'security' / 'store.py'
    assert Path(recover.__file__).resolve() == root / 'local_ai' / 'recover.py'


@pytest.fixture
def account(tmp_path):
    now = [1000.0]
    store = SecurityStore(tmp_path / 'private' / 'security.db', create=True,
                          idle_seconds=10, absolute_seconds=25, retention_days=1,
                          clock=lambda: now[0])
    admin = store.bootstrap('admin', PASSWORD)
    token, _ = store.login('admin', PASSWORD, '127.0.0.1')
    return store, admin, token, now


def raw_rows(store, query, parameters=()):
    with closing(sqlite3.connect(store.path.as_uri() + '?mode=ro', uri=True)) as db:
        return db.execute(query, parameters).fetchall()


@pytest.mark.parametrize('expires', ['idle', 'absolute'])
def test_no_touch_authentication_never_refreshes_or_deletes(account, expires):
    store, admin, token, now = account
    before = raw_rows(store, 'SELECT * FROM sessions')
    now[0] += 9
    principal = store.authenticate(token, touch=False)
    assert principal == {**admin, 'session_id': before[0][0]}
    assert raw_rows(store, 'SELECT * FROM sessions') == before
    if expires == 'absolute':
        with closing(sqlite3.connect(store.path)) as db, db:
            db.execute('UPDATE sessions SET last_seen=?', (now[0] + 15,))
        before = raw_rows(store, 'SELECT * FROM sessions')
        now[0] += 16
    else:
        now[0] += 1
    assert store.authenticate(token, touch=False) is None
    assert raw_rows(store, 'SELECT * FROM sessions') == before
    assert store.authenticate(token) is None
    assert raw_rows(store, 'SELECT * FROM sessions') == []


@pytest.mark.parametrize('invalid', [None, 'user', 'session', 'token', 'role',
                                     'inactive', 'password', 'idle', 'absolute', 'revoked'])
def test_authorize_exact_live_session_with_current_role(account, invalid):
    store, admin, token, now = account
    session_id = store.sessions(admin['id'])[0]['id']
    user_id, supplied_session = admin['id'], session_id
    allowed_roles = ('admin', 'operator')
    if invalid == 'user':
        user_id = 'another-user'
    elif invalid == 'session':
        supplied_session = 'another-session'
    elif invalid == 'token':
        supplied_session = token
    elif invalid in ('role', 'inactive', 'password'):
        column, value = {'role': ('role', 'viewer'), 'inactive': ('active', 0),
                         'password': ('must_change_password', 1)}[invalid]
        with closing(sqlite3.connect(store.path)) as db, db:
            db.execute(f'UPDATE users SET {column}=? WHERE id=?', (value, admin['id']))
    elif invalid == 'idle':
        now[0] += 10
    elif invalid == 'absolute':
        with closing(sqlite3.connect(store.path)) as db, db:
            db.execute('UPDATE sessions SET last_seen=?', (now[0] + 24,))
        now[0] += 25
    elif invalid == 'revoked':
        store.revoke_sessions(admin['id'], actor=admin, session_id=session_id)
    before = raw_rows(store, 'SELECT * FROM sessions')
    result = store.authorize_session(supplied_session, user_id, allowed_roles)
    assert result == ({**admin, 'session_id': session_id} if invalid is None else None)
    assert raw_rows(store, 'SELECT * FROM sessions') == before


def test_ai_session_reads_are_sqlite_read_only_even_with_a_writer(account, monkeypatch):
    store, admin, token, now = account
    session_id = store.sessions(admin['id'])[0]['id']
    original = sqlite3.connect
    connections, statements = [], []

    def observe(*args, **kwargs):
        db = original(*args, **kwargs)
        connections.append((args, kwargs))
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            db.execute('DELETE FROM sessions')
        db.set_trace_callback(statements.append)
        return db

    with closing(original(store.path)) as writer, writer:
        writer.execute('BEGIN IMMEDIATE')
        writer.execute('UPDATE sessions SET last_seen=?', (now[0] + 1,))
        monkeypatch.setattr(sqlite3, 'connect', observe)
        assert store.authenticate(token, touch=False)['session_id'] == session_id
        assert store.authorize_session(session_id, admin['id'], ('admin',))['id'] == admin['id']
    assert len(connections) == 2
    assert all(args[0].endswith('?mode=ro') and kwargs['uri'] for args, kwargs in connections)
    assert all(statement.lstrip().upper().startswith('SELECT') for statement in statements)


def test_interlock_index_is_opt_in_and_state_read_is_nonmutating(account):
    store, _admin, _token, _now = account
    initial = raw_rows(store, "SELECT name,sql FROM sqlite_master WHERE type='index'")
    assert not any('llm' in row[0] for row in initial)
    assert store.llm_provider_state() == {'blocked': False, 'job_id': None, 'outcome': 'absent'}
    assert raw_rows(store, "SELECT name,sql FROM sqlite_master WHERE type='index'") == initial
    store.ensure_llm_interlock()
    with closing(sqlite3.connect(store.path)) as db, db:
        plan = db.execute("EXPLAIN QUERY PLAN SELECT job_id,outcome FROM audit_events "
                          "WHERE action='llm.provider' ORDER BY rowid DESC LIMIT 1").fetchall()
    assert any('USING INDEX audit_llm_provider' in row[3] for row in plan)
    assert not any('TEMP B-TREE' in row[3] for row in plan)
    after = raw_rows(store, 'SELECT sql FROM sqlite_master ORDER BY name')
    store.ensure_llm_interlock()
    assert raw_rows(store, 'SELECT sql FROM sqlite_master ORDER BY name') == after
    assert raw_rows(store, "SELECT * FROM audit_events WHERE action='llm.provider'") == []


def test_begin_reserves_durably_and_refuses_double_begin(account):
    store, admin, _token, now = account
    store.ensure_llm_interlock()
    assert store.begin_llm_provider('job-first', admin, request_id='request-first',
                                    source_ip='127.0.0.1') is True
    expected = {'blocked': True, 'job_id': 'job-first', 'outcome': 'started'}
    assert store.llm_provider_state() == expected
    restarted = SecurityStore(store.path, clock=lambda: now[0])
    assert restarted.llm_provider_state() == expected
    assert restarted.begin_llm_provider('job-second', admin) is False
    assert restarted.begin_llm_provider('job-first', admin) is False
    rows = raw_rows(store, "SELECT actor_user_id,action,target,outcome,request_id,source_ip,details,job_id "
                           "FROM audit_events WHERE action='llm.provider'")
    assert rows == [(admin['id'], 'llm.provider', '', 'started', 'request-first',
                     '127.0.0.1', '{}', 'job-first')]


def test_settlement_is_exact_once_and_late_settlement_cannot_clear_successor(account):
    store, admin, _token, now = account
    store.ensure_llm_interlock()
    assert store.settle_llm_provider('job-first', actor=admin) is False
    assert store.begin_llm_provider('job-first', admin) is True
    assert store.settle_llm_provider('wrong-job', actor=admin) is False
    now[0] -= 100  # A clock adjustment cannot reverse the durable event order.
    assert store.settle_llm_provider('job-first', actor=admin) is True
    assert store.settle_llm_provider('job-first', actor=admin) is False
    assert store.llm_provider_state() == {'blocked': False, 'job_id': 'job-first', 'outcome': 'settled'}
    assert store.begin_llm_provider('job-second', admin) is True
    assert store.settle_llm_provider('job-first') is False
    assert store.llm_provider_state() == {'blocked': True, 'job_id': 'job-second', 'outcome': 'started'}
    assert store.settle_llm_provider('job-second') is True
    assert raw_rows(store, "SELECT outcome,job_id FROM audit_events WHERE action='llm.provider' "
                           'ORDER BY rowid') == [('started', 'job-first'), ('settled', 'job-first'),
                                                ('started', 'job-second'), ('settled', 'job-second')]


@pytest.mark.parametrize('phase', ['started', 'settled'])
def test_failed_provider_audit_is_atomic_and_fail_closed(account, phase):
    store, admin, _token, _now = account
    store.ensure_llm_interlock()
    if phase == 'settled':
        assert store.begin_llm_provider('job-first', admin) is True
    before = raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid')
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("CREATE TRIGGER reject_provider AFTER INSERT ON audit_events "
                   "WHEN NEW.action='llm.provider' BEGIN "
                   "SELECT RAISE(ABORT, 'provider audit unavailable'); END")
    operation = (lambda: store.begin_llm_provider('job-first', admin)) if phase == 'started' else (
        lambda: store.settle_llm_provider('job-first', actor=admin))
    with pytest.raises(sqlite3.DatabaseError, match='provider audit unavailable'):
        operation()
    assert raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid') == before
    assert store.llm_provider_state()['blocked'] == (phase == 'settled')
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute('DROP TRIGGER reject_provider')
    assert operation() is True


def test_reconcile_uses_provider_event_order_not_request_id(account):
    store, admin, _token, now = account
    store.ensure_llm_interlock()
    assert store.begin_llm_provider('job-first', admin, request_id='first-request')
    assert store.settle_llm_provider('job-first', actor=admin)
    assert store.reconcile_intents() == 0
    assert store.begin_llm_provider('job-second', admin, request_id='second-request')
    restarted = SecurityStore(store.path, clock=lambda: now[0])
    assert restarted.reconcile_intents() == 1
    assert restarted.llm_provider_state() == {'blocked': True, 'job_id': 'job-second', 'outcome': 'unknown'}
    assert restarted.reconcile_intents() == 0
    assert restarted.begin_llm_provider('job-third', admin) is False
    assert restarted.settle_llm_provider('job-first') is False
    assert restarted.settle_llm_provider('job-second') is True
    assert restarted.reconcile_intents() == 0


@pytest.mark.parametrize('outcome', ['started', 'unknown', 'settled'])
def test_pruning_preserves_latest_interlock_across_restart(account, outcome):
    store, admin, _token, now = account
    store.ensure_llm_interlock()
    assert store.begin_llm_provider('job-first', admin)
    assert store.settle_llm_provider('job-first')
    assert store.begin_llm_provider('job-second', admin)
    if outcome == 'unknown':
        assert store.reconcile_intents() == 1
    elif outcome == 'settled':
        assert store.settle_llm_provider('job-second')
    before = store.llm_provider_state()
    now[0] += 86401
    old_count = raw_rows(store, 'SELECT COUNT(*) FROM audit_events')[0][0]
    assert store.prune_audit() == old_count - 1
    assert raw_rows(store, "SELECT outcome,job_id FROM audit_events WHERE action='llm.provider'") == [
        (outcome, 'job-second')]
    restarted = SecurityStore(store.path, retention_days=1, clock=lambda: now[0])
    assert restarted.llm_provider_state() == before
    assert restarted.begin_llm_provider('job-third', admin) is (not before['blocked'])


@pytest.mark.parametrize(('tracedns', 'provider'), [(False, True), (True, False),
                                                  (False, False), (1, True), (True, 'yes')])
def test_recovery_requires_explicit_boolean_attestations(account, tracedns, provider):
    store, admin, _token, _now = account
    store.ensure_llm_interlock()
    assert store.begin_llm_provider('job-first', admin)
    before = raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid')
    with pytest.raises(SecurityError, match='attest'):
        store.acknowledge_llm_provider_stopped('job-first', tracedns_stopped=tracedns,
                                               provider_stopped=provider)
    assert raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid') == before
    assert store.llm_provider_state()['blocked'] is True


def test_recovery_attests_only_exact_outstanding_job_and_survives_pruning(account):
    store, admin, _token, now = account
    store.ensure_llm_interlock()

    def attest(job_id):
        return store.acknowledge_llm_provider_stopped(job_id, tracedns_stopped=True,
                                                     provider_stopped=True)

    assert attest('job-first') is False
    assert store.begin_llm_provider('job-first', admin)
    assert store.reconcile_intents() == 1
    assert attest('other-job') is False
    assert attest('job-first') is True
    expected = {'blocked': False, 'job_id': 'job-first', 'outcome': 'operator_confirmed_stopped'}
    assert store.llm_provider_state() == expected
    assert attest('job-first') is False
    now[0] += 86401
    store.prune_audit()
    assert SecurityStore(store.path).llm_provider_state() == expected
    assert store.begin_llm_provider('job-second', admin)
    assert store.settle_llm_provider('job-first') is False
    assert attest('job-first') is False
    assert store.llm_provider_state()['job_id'] == 'job-second'
    assert store.llm_provider_state()['blocked'] is True


def recovery_cli(store, job_id, *confirmations):
    return subprocess.run([sys.executable, '-m', 'local_ai.recover', '--security-db', str(store.path),
                           '--job-id', job_id, *confirmations],
                          cwd=Path(__file__).resolve().parents[1],
                          capture_output=True, text=True, timeout=15)


def test_offline_recovery_cli_requires_both_flags_and_matching_job(account):
    store, admin, _token, _now = account
    store.ensure_llm_interlock()
    assert store.begin_llm_provider('job-first', admin)
    before = raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid')
    for flags in ((), ('--confirm-tracedns-stopped',), ('--confirm-provider-stopped',)):
        result = recovery_cli(store, 'job-first', *flags)
        assert result.returncode == 2, result.stderr
        assert 'required' in result.stderr
        assert raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid') == before
    flags = ('--confirm-tracedns-stopped', '--confirm-provider-stopped')
    wrong = recovery_cli(store, 'wrong-job', *flags)
    assert wrong.returncode == 1
    assert 'matching outstanding' in wrong.stderr
    assert raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid') == before
    result = recovery_cli(store, 'job-first', *flags)
    assert result.returncode == 0, result.stderr
    assert 'operator_confirmed_stopped' in result.stdout
    assert 'attestation' in result.stdout and 'not machine proof' in result.stdout
    assert store.llm_provider_state() == {'blocked': False, 'job_id': 'job-first',
                                         'outcome': 'operator_confirmed_stopped'}
    repeat = recovery_cli(store, 'job-first', *flags)
    assert repeat.returncode == 1


@pytest.mark.parametrize('operation', ['read', 'write', 'index'])
def test_ai_sql_work_budget_interrupts_and_rolls_back(account, monkeypatch, operation):
    store, admin, _token, _now = account
    if operation == 'read':
        assert store.begin_llm_provider('job-first', admin)
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000) "
                   "INSERT INTO audit_events(id,action,outcome) "
                   "SELECT 'unrelated-'||x,'unrelated','success' FROM n")
        if operation == 'write':
            db.execute("CREATE TRIGGER bounded_work AFTER INSERT ON audit_events "
                       "WHEN NEW.action='llm.provider' BEGIN SELECT sum(x) FROM "
                       "(WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000) "
                       'SELECT x FROM n); END')
    before = raw_rows(store, 'SELECT COUNT(*) FROM audit_events')
    ticks = iter([0.0, 100.0])
    monkeypatch.setattr(store_module, 'time', SimpleNamespace(monotonic=lambda: next(ticks, 100.0)))
    with pytest.raises(sqlite3.OperationalError, match='interrupted'):
        if operation == 'read':
            store.llm_provider_state()
        elif operation == 'write':
            store.begin_llm_provider('job-first', admin)
        else:
            store.ensure_llm_interlock()
    assert raw_rows(store, 'SELECT COUNT(*) FROM audit_events') == before
    assert raw_rows(store, "SELECT name FROM sqlite_master WHERE name='audit_llm_provider'") == []
    monkeypatch.undo()
    if operation == 'read':
        assert store.llm_provider_state()['blocked'] is True
    else:
        assert store.begin_llm_provider('job-after-interrupt', admin)


@pytest.mark.parametrize('operation', ['authenticate', 'authorize'])
def test_read_only_authorization_checks_expiry_after_database_acquisition(account, monkeypatch, operation):
    store, admin, token, now = account
    session_id = store.sessions(admin['id'])[0]['id']
    original = store._read_db

    @contextmanager
    def delayed_read():
        with original() as db:
            now[0] += 10
            yield db

    monkeypatch.setattr(store, '_read_db', delayed_read)
    if operation == 'authenticate':
        assert store.authenticate(token, touch=False) is None
    else:
        assert store.authorize_session(session_id, admin['id'], ('admin',)) is None
    assert raw_rows(store, 'SELECT id FROM sessions') == [(session_id,)]


@pytest.mark.parametrize('job_id', ['', None, 1, False, b'job-first'])
@pytest.mark.parametrize('operation', ['begin', 'settle', 'attest'])
def test_provider_identifiers_are_nonempty_strings_without_coercion(account, job_id, operation):
    store, admin, _token, _now = account
    before = raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid')
    with pytest.raises(SecurityError, match='job ID'):
        if operation == 'begin':
            store.begin_llm_provider(job_id, admin)
        elif operation == 'settle':
            store.settle_llm_provider(job_id)
        else:
            store.acknowledge_llm_provider_stopped(job_id, tracedns_stopped=True, provider_stopped=True)
    assert raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid') == before


def test_independent_store_reservation_race_has_one_durable_winner(account, monkeypatch):
    store, admin, _token, _now = account
    store.ensure_llm_interlock()
    contender = SecurityStore(store.path)
    paused, release, contender_seen = threading.Event(), threading.Event(), threading.Event()
    local = threading.local()
    waits = []
    original = sqlite3.connect

    def pause():
        paused.set()
        waits.append(release.wait(5))
        return 0

    def trace(statement):
        if statement == 'BEGIN IMMEDIATE' and getattr(local, 'job', None) == 'job-second':
            contender_seen.set()
            release.set()

    def observe(*args, **kwargs):
        db = original(*args, **kwargs)
        db.create_function('pause_provider', 0, pause)
        db.set_trace_callback(trace)
        return db

    with closing(original(store.path)) as db, db:
        db.execute("CREATE TRIGGER pause_first AFTER INSERT ON audit_events "
                   "WHEN NEW.action='llm.provider' AND NEW.job_id='job-first' "
                   'BEGIN SELECT pause_provider(); END')
    monkeypatch.setattr(sqlite3, 'connect', observe)

    def reserve(target, job_id):
        local.job = job_id
        return target.begin_llm_provider(job_id, admin)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reserve, store, 'job-first')
        try:
            assert paused.wait(5)
            assert raw_rows(store, "SELECT job_id FROM audit_events WHERE action='llm.provider'") == []
            second = pool.submit(reserve, contender, 'job-second')
            assert contender_seen.wait(5)
            assert first.result(timeout=5) is True
            assert second.result(timeout=5) is False
        finally:
            release.set()
    assert waits == [True]
    assert raw_rows(store, "SELECT outcome,job_id FROM audit_events WHERE action='llm.provider'") == [
        ('started', 'job-first')]


@pytest.mark.parametrize('operation', ['index', 'begin', 'settle', 'attest', 'state', 'authenticate', 'authorize'])
def test_ai_sqlite_lock_waits_are_bounded(account, operation):
    store, admin, token, _now = account
    store.ensure_llm_interlock()
    session_id = store.sessions(admin['id'])[0]['id']
    assert store.begin_llm_provider('job-first', admin)
    before = raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid')
    actions = {
        'index': store.ensure_llm_interlock,
        'begin': lambda: store.begin_llm_provider('job-second', admin),
        'settle': lambda: store.settle_llm_provider('job-first'),
        'attest': lambda: store.acknowledge_llm_provider_stopped(
            'job-first', tracedns_stopped=True, provider_stopped=True),
        'state': store.llm_provider_state,
        'authenticate': lambda: store.authenticate(token, touch=False),
        'authorize': lambda: store.authorize_session(session_id, admin['id'], ('admin',)),
    }
    with closing(sqlite3.connect(store.path)) as writer, writer:
        assert writer.execute('PRAGMA journal_mode=DELETE').fetchone()[0] == 'delete'
        writer.execute('BEGIN EXCLUSIVE')
        start = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match='locked'):
            actions[operation]()
        assert time.monotonic() - start < 2
    assert raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid') == before
    assert store.llm_provider_state()['blocked'] is True


def test_recovery_audit_failure_leaves_interlock_and_hides_exception_text(account, capsys, monkeypatch):
    from local_ai.recover import main
    import os
    import socket

    store, admin, _token, _now = account
    assert store.begin_llm_provider('job-first', admin)
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("CREATE TRIGGER reject_recovery AFTER INSERT ON audit_events "
                   "WHEN NEW.outcome='operator_confirmed_stopped' "
                   "BEGIN SELECT RAISE(ABORT, 'PRIVATE-DRIVER-TEXT'); END")
    before = raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid')

    def forbidden(*_args, **_kwargs):
        pytest.fail('Offline recovery attempted a network/process operation')

    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'kill', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)
    args = ['--security-db', str(store.path), '--job-id', 'job-first',
            '--confirm-tracedns-stopped', '--confirm-provider-stopped']
    assert main(args) == 1
    output = capsys.readouterr()
    assert 'security audit unavailable' in output.err
    assert 'PRIVATE-DRIVER-TEXT' not in output.err
    assert raw_rows(store, 'SELECT * FROM audit_events ORDER BY rowid') == before
    assert store.llm_provider_state()['blocked'] is True
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute('DROP TRIGGER reject_recovery')
    assert main(args) == 0
    assert store.llm_provider_state()['outcome'] == 'operator_confirmed_stopped'


@pytest.mark.parametrize('role', ['admin', 'operator', 'viewer'])
def test_authorization_uses_current_exact_role_and_never_retains_secrets(account, role):
    store, admin, token, _now = account
    session_id = store.sessions(admin['id'])[0]['id']
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute('UPDATE users SET role=? WHERE id=?', (role, admin['id']))
    result = store.authorize_session(session_id, admin['id'], (role,))
    assert result == {**admin, 'role': role, 'session_id': session_id}
    assert token not in str(result)
    assert store.authorize_session(session_id, admin['id'], ('prefix-' + role,)) is None
    assert store.authorize_session(session_id, admin['id'], ()) is None


def test_unknown_provider_outcome_never_admits_and_state_read_is_read_only(account, monkeypatch):
    store, admin, _token, _now = account
    store.ensure_llm_interlock()
    store.audit(admin, 'llm.provider', outcome='unexpected-outcome', job_id='job-unknown')
    original = sqlite3.connect
    statements = []

    def observe(*args, **kwargs):
        assert kwargs.get('uri') is True and args[0].endswith('?mode=ro')
        db = original(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db

    with monkeypatch.context() as context:
        context.setattr(sqlite3, 'connect', observe)
        assert store.llm_provider_state() == {'blocked': True, 'job_id': 'job-unknown',
                                             'outcome': 'unexpected-outcome'}
    assert all(statement.startswith('SELECT') for statement in statements)
    assert store.begin_llm_provider('job-next', admin) is False


def test_recovery_cli_does_not_initialize_a_missing_database(tmp_path):
    missing = tmp_path / 'missing-private' / 'auth.db'
    result = recovery_cli(SimpleNamespace(path=missing), 'job-first',
                          '--confirm-tracedns-stopped', '--confirm-provider-stopped')
    assert result.returncode == 1
    assert 'security audit unavailable or invalid' in result.stderr
    assert not missing.parent.exists()


def test_recovery_readback_failure_cannot_report_success(account, monkeypatch, capsys):
    from local_ai.recover import main

    store, admin, _token, _now = account
    assert store.begin_llm_provider('job-first', admin)

    def unavailable(_self):
        raise sqlite3.OperationalError('PRIVATE-READBACK-DETAIL')

    monkeypatch.setattr(SecurityStore, 'llm_provider_state', unavailable)
    assert main(['--security-db', str(store.path), '--job-id', 'job-first',
                 '--confirm-tracedns-stopped', '--confirm-provider-stopped']) == 1
    output = capsys.readouterr()
    assert output.out == ''
    assert 'keep TraceDNS stopped' in output.err
    assert 'PRIVATE-READBACK-DETAIL' not in output.err
    assert raw_rows(store, "SELECT outcome FROM audit_events WHERE action='llm.provider' "
                           'ORDER BY rowid DESC LIMIT 1') == [('operator_confirmed_stopped',)]


def test_provider_audit_drops_bearer_and_extra_actor_payload(account):
    store, admin, token, _now = account
    enriched = {**admin, 'bearer': token, 'prompt': 'PRIVATE-PROMPT', 'model_text': 'PRIVATE-RESULT'}
    assert store.begin_llm_provider('job-first', enriched)
    assert store.settle_llm_provider('job-first', actor=enriched)
    rows = raw_rows(store, "SELECT * FROM audit_events WHERE action='llm.provider'")
    encoded = str(rows)
    assert token not in encoded
    assert 'PRIVATE-PROMPT' not in encoded
    assert 'PRIVATE-RESULT' not in encoded
