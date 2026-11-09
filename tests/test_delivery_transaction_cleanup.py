"""Real SQLite rollback refusal must never expose a speculative writer."""
import json
import sqlite3

import pytest

from test_delivery_store_atomic import AUTH, BINDINGS, obs, store_at
from test_delivery_store_claims import result as provider_result

TEAMS = [{**BINDINGS[0], 'channel': 'teams'}]


class ConnectionFault:
    """Delegate state to the actual native connection, never fabricate closure."""
    def __init__(self, native, rollback='refuse', commit=False):
        self.native = native
        self.rollback_mode = rollback
        self.commit_raises = commit
        self.rollbacks = 0
        self.commits = 0

    def __getattr__(self, name):
        return getattr(self.native, name)

    def rollback(self):
        self.rollbacks += 1
        if self.rollback_mode != 'refuse':
            self.native.rollback()
        if self.rollback_mode != 'normal':
            raise sqlite3.OperationalError('rollback refusal')

    def commit(self):
        self.commits += 1
        self.native.commit()
        if self.commit_raises:
            raise sqlite3.OperationalError('commit completed but driver raised')


def durable(store):
    """Raw independent read-only observer; no initialization or writer cleanup."""
    db = sqlite3.connect(store.path.as_uri() + '?mode=ro', uri=True, timeout=.05)
    try:
        db.row_factory = sqlite3.Row
        return {table: [dict(row) for row in db.execute('SELECT * FROM ' + table)]
                for table in ('control', 'cursor', 'receipt', 'batch', 'terminal', 'dht_state')}
    finally:
        db.close()


@pytest.mark.parametrize('actionable', [False, True])
def test_optional_seal_rollback_refusal_quarantines_live_writer(tmp_path, actionable):
    store = store_at(tmp_path, limits={'batch_items': 1} if actionable else None)
    assert store.bootstrap({}, {}, AUTH)['ready']
    native = store._db
    wrapper = ConnectionFault(native)
    store._db = wrapper
    calls = []
    observation = obs(['192.0.2.1'])

    def fault(point):
        calls.append(point)
        if calls.count('before_commit') == 2 and point == 'before_commit':
            raise sqlite3.OperationalError('database or disk is full')

    store._fault = fault
    try:
        result = store.record_domain(observation, AUTH, TEAMS)
        saved = durable(store)  # BEFORE any cleanup, including fixture finalization
        assert calls == ['before_commit', 'after_commit', 'before_commit']
        assert wrapper.rollbacks == 1
        assert native.in_transaction
        assert saved['cursor'][0]['operation'] == observation['source_operation_id']
        assert len(saved['receipt']) == 1
        assert saved['receipt'][0]['state'] == 'unsealed'
        assert saved['batch'] == saved['terminal'] == []
        assert json.loads(saved['control'][0]['data'])['last_transaction'] == observation['source_operation_id']
        assert result['ledger_committed'] and result['admitted_receipts'] == 1
        assert result['missed_receipts'] == 0
        assert not store._gap and not any(store._volatile.values())
        assert store.diagnostics_snapshot()['storage_error']['code'] == 'sqlite_full'
        assert not store.dispatch_available(), 'live failed rollback returned an unfenced reusable writer'
        assert store._unresolved is not None
        assert store.health_snapshot()['counts_stale']
    finally:
        store._fault = lambda _: None
        store._db = native
        native.rollback()
        store.close(clean=False)


@pytest.fixture
def ledger(tmp_path):
    store = store_at(tmp_path, clock=lambda: 100)
    assert store.bootstrap({}, {}, AUTH)['ready']
    native = store._db
    assert native.execute('PRAGMA synchronous').fetchone()[0] == 2
    assert native.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
    try:
        yield store, native
    finally:
        store._fault = lambda _: None
        store._db = native
        native.set_trace_callback(None)
        native.rollback()
        store.close(clean=False)


def fail_before(point):
    if point == 'before_commit':
        raise sqlite3.OperationalError('database or disk is full')


class SQLTrace(list):
    def __init__(self):
        super().__init__()
        self.dropped = 0

    def append(self, statement):
        if len(self) < 4096:
            super().append(statement)
        else:
            self.dropped += 1


def test_quarantine_blocks_sibling_reads_writes_and_repeated_recovery(ledger):
    store, native = ledger
    wrapper = ConnectionFault(native)
    store._db = wrapper
    observation = obs(['192.0.2.1'])
    before = durable(store)
    owner = store._owner
    store._fault = fail_before
    assert store.record_domain(observation, AUTH, BINDINGS)['outcome'] == 'gap'
    assert durable(store) == before
    assert native.in_transaction
    assert store._unresolved['losses'] == {'misp': 1, 'teams': 0}
    assert store._volatile == {'misp': 0, 'teams': 0}
    pending = store._unresolved
    statements = SQLTrace()
    native.set_trace_callback(statements.append)
    # Same-operation retries must not acquire a second speculative loss owner.
    assert store.record_domain(observation, AUTH, BINDINGS)['outcome'] == 'gap'
    assert store.cursor_incarnation(observation['target']) is None
    assert store.load_dht_checkpoint('signed.example') == (False, None)
    assert store._known_additions(obs(['192.0.2.2']), BINDINGS) == {'misp': 0, 'teams': 0}
    assert store.record_domain(obs(['192.0.2.2']), AUTH, BINDINGS)['outcome'] == 'gap'
    assert not store.claim_next(BINDINGS[0], 100)
    assert not store.finish_step({}, provider_result(), 100)['applied']
    assert not store.retire_dht('absent')
    assert not store.prune_dht(set())
    assert store.begin_dht('signed.example', {'highwater': 1}, lambda: False) is None
    assert not store.finish_dht('signed.example', 'ticket', {}, lambda: False)
    assert not store.abort_dht('signed.example', 'ticket')
    assert not store.seal_cycle(None)['ledger_committed']
    assert not store.seal_due_batches(1000)['ledger_committed']
    assert not store.configuration_applied()['ledger_committed']
    assert not store.refresh_configuration(AUTH, {})['ledger_committed']
    assert not store.retire_target_cursor('speculative')['ledger_committed']
    assert not store.cancel_force_positive(AUTH, ['192.0.2.1'])['ledger_committed']
    assert not store.rebaseline_absence(AUTH, {}, 100, BINDINGS)['ledger_committed']
    store.health_snapshot()
    store.diagnostics_snapshot()
    assert statements == [], 'quarantined same-connection reads are not durable evidence'
    assert store._unresolved is pending
    assert durable(store) == before
    store._fault = lambda _: None
    for _ in range(2):
        store._monotonic = lambda: store._recovery_next
        attempts = wrapper.rollbacks
        assert store.recover_delivery(100)['state'] == 'uncertain'
        assert wrapper.rollbacks == attempts + 1
        assert native.in_transaction and store._unresolved is pending
        assert not store.dispatch_available()
        assert durable(store) == before
    attempts = wrapper.rollbacks
    assert not store.recover_gap(AUTH, {}, {'active_map': {}, 'completed_at': 100})['ready']
    assert wrapper.rollbacks == attempts + 1
    assert statements == []
    assert store._owner is owner and not owner.closed
    assert store._db is wrapper
    wrapper.rollback_mode = 'normal'
    assert store.recover_delivery(100)['state'] == 'ready'
    assert not native.in_transaction and store._unresolved is None
    assert store.dispatch_available()
    assert store._checkpoint == {'misp': 1, 'teams': 0}
    assert not any(store._volatile.values())
    assert store.health_snapshot()['missed_total'] == 1
    assert store.health_snapshot()['acked_total'] == store.health_snapshot()['failed_total'] == 0
    assert not store.health_snapshot()['accounting_complete']
    saved = durable(store)
    assert saved['receipt'] == saved['cursor'] == []
    assert store.recover_delivery(100)['state'] == 'ready'
    assert durable(store) == saved
    assert store._owner is owner and store._db is wrapper
    assert not statements.dropped


@pytest.mark.parametrize('rollback', ['normal', 'after', 'refuse'])
@pytest.mark.parametrize('committed', [False, True])
def test_native_closure_and_durable_winner_are_separate(ledger, rollback, committed):
    store, native = ledger
    observation = obs(['192.0.2.1'])
    wrapper = ConnectionFault(native, rollback=rollback, commit=committed)
    store._db = wrapper
    if not committed:
        store._fault = fail_before
    outcome = store.record_domain(observation, AUTH, BINDINGS)
    saved = durable(store)
    assert wrapper.rollbacks >= 1
    assert bool(saved['receipt']) == committed
    assert bool(saved['cursor']) == committed
    assert outcome['ledger_committed'] == committed
    assert saved['terminal'] == []
    if committed:
        assert not native.in_transaction
        assert store._unresolved is None
        assert store.dispatch_available()
        assert outcome['admitted_receipts'] == 1
        assert store.diagnostics_snapshot()['storage_error']['stage'] == 'transaction_commit'
    elif rollback == 'refuse':
        assert native.in_transaction and store._unresolved is not None
        assert not store.dispatch_available()
    else:
        assert not native.in_transaction and store._unresolved is None
        assert store._volatile['misp'] == 1
    if not committed:
        assert store.diagnostics_snapshot()['storage_error']['code'] == 'sqlite_full'


@pytest.mark.parametrize('invalid', ['unreadable', 'epoch', 'malformed', 'binding'])
@pytest.mark.parametrize('committed', [False, True])
def test_optional_invalid_readback_needs_closure_and_valid_identity(ledger, monkeypatch, invalid, committed):
    store, native = ledger
    wrapper = ConnectionFault(native)
    store._db = wrapper
    observation = obs(['192.0.2.1'])
    seen = []
    real_read = store._read_control
    faults = []

    def read():
        faults.append(invalid)
        saved = real_read()
        if invalid == 'unreadable':
            raise sqlite3.OperationalError('readback unavailable')
        return {**saved, **{'epoch': {'epoch': 'wrong'},
                          'malformed': {'missed_total': True},
                          'binding': {'binding_key': 'wrong'}}[invalid]}

    def optional(point):
        if point == 'before_commit':
            seen.append(point)
            if len(seen) == 2:
                wrapper.commit_raises = committed
                if not committed:
                    fail_before(point)

    store._fault = optional
    monkeypatch.setattr(store, '_read_control', read)
    outcome = store.record_domain(observation, AUTH, TEAMS)
    saved = durable(store)
    assert len(seen) == 2 and faults == [invalid]
    assert outcome['ledger_committed'] and outcome['admitted_receipts'] == 1
    assert len(saved['receipt']) == 1 and saved['receipt'][0]['state'] == 'unsealed'
    assert native.in_transaction == (not committed)
    pending = store._unresolved
    assert pending and pending['losses'] == {}
    assert store.diagnostics_snapshot()['storage_error']['stage'] == 'transaction_readback'
    store._fault = lambda _: None
    wrapper.commit_raises = False
    wrapper.rollback_mode = 'normal'
    assert store.recover_delivery(100)['state'] == 'uncertain'
    assert not native.in_transaction
    assert store._unresolved is pending and not store.dispatch_available()
    assert durable(store) == saved
    monkeypatch.setattr(store, '_read_control', real_read)
    store._monotonic = lambda: store._recovery_next
    assert store.recover_delivery(100)['state'] == 'ready'
    assert store._unresolved is None and store.dispatch_available()
    after = durable(store)
    assert {k: v for k, v in after.items() if k != 'control'} == {k: v for k, v in saved.items() if k != 'control'}
    assert store.health_snapshot()['missed_total'] == 0
    assert not store._gap and not any(store._volatile.values())


@pytest.mark.parametrize('operation', ['claim', 'ack', 'dht_begin', 'dht_finish', 'recovery'])
def test_supported_caller_ownership_survives_cleanup_refusal(ledger, operation):
    store, native = ledger
    store.record_domain(obs(['192.0.2.1']), AUTH, BINDINGS)
    claim = store.claim_next(BINDINGS[0], 100) if operation == 'ack' else None
    token = store.begin_dht('signed.example', {'highwater': 7}, lambda: False) if operation == 'dht_finish' else None
    if operation == 'recovery':
        store.enter_gap('delivery_storage', {'teams': 3})
    before = durable(store)
    wrapper = ConnectionFault(native)
    store._db = wrapper
    store._fault = fail_before
    if operation == 'claim':
        assert store.claim_next(BINDINGS[0], 100) is None
    elif operation == 'ack':
        assert not store.finish_step(claim, provider_result(), 100)['applied']
    elif operation == 'dht_begin':
        assert store.begin_dht('signed.example', {'highwater': 7}, lambda: False) is None
    elif operation == 'dht_finish':
        assert not store.finish_dht('signed.example', token, {'highwater': 8}, lambda: False)
    else:
        assert store.recover_delivery(100)['state'] == 'failed'
    assert durable(store) == before
    assert native.in_transaction and not store.dispatch_available()
    assert store._unresolved['kind'] == ('checkpoint' if operation.startswith('dht_') else operation)
    store.enter_gap('delivery_storage', {'teams': 5, 'misp': 2})
    if operation == 'recovery':
        assert store._unresolved['captured'] == {'teams': 3, 'misp': 0}
        assert store._unresolved['checkpoint'] == {'teams': 3, 'misp': 0}
        assert store._unresolved['newer_losses'] == {'teams': 5, 'misp': 2}
    store._fault = lambda _: None
    wrapper.rollback_mode = 'normal'
    store._monotonic = lambda: store._recovery_next
    assert store.recover_delivery(100)['state'] == 'ready'
    assert not native.in_transaction and store._unresolved is None
    saved = durable(store)
    assert saved['dht_state'] == before['dht_state']
    assert saved['cursor'] == before['cursor']
    assert saved['terminal'] == []
    row = saved['receipt'][0]
    assert row['state'] == ('retry_wait' if operation == 'ack' else 'pending')
    assert row['attempt'] == row['provider_calls'] == int(operation == 'ack')
    assert store.health_snapshot()['acked_total'] == store.health_snapshot()['failed_total'] == 0
    assert store.health_snapshot()['missed_total'] == (10 if operation == 'recovery' else 7)
    assert store._checkpoint == {'teams': 8 if operation == 'recovery' else 5, 'misp': 2}
    assert not any(store._volatile.values())
    assert store.recover_delivery(100)['state'] == 'ready'
    assert durable(store) == saved


@pytest.mark.parametrize('rollback', ['normal', 'after', 'refuse'])
@pytest.mark.parametrize('primary', ['cancelled', 'body'])
def test_cancellation_does_not_hide_storage_failure_or_reverse_precedence(ledger, rollback, primary):
    store, native = ledger
    wrapper = ConnectionFault(native, rollback=rollback)
    store._db = wrapper
    cancelled = [False]
    before = durable(store)

    def fault(point):
        if point == 'before_commit':
            cancelled[0] = True
            if primary == 'body':
                raise ValueError('primary body failure')

    store._fault = fault
    outcome = store.record_domain(obs(['192.0.2.1']), AUTH, BINDINGS,
                                  cancelled=lambda: cancelled[0])
    assert durable(store) == before
    assert wrapper.rollbacks == 1
    assert native.in_transaction == (rollback == 'refuse')
    if primary == 'cancelled' and rollback == 'normal':
        assert outcome['outcome'] == 'stale'
        assert store.diagnostics_snapshot()['storage_error'] is None
        assert not store._gap
    else:
        assert outcome['outcome'] == 'gap'
        error = store.diagnostics_snapshot()['storage_error']
        assert error['stage'] == 'transaction_body'
        assert error['code'] == ('invalid_state' if primary == 'body' else 'sqlite_error')
    if rollback == 'refuse':
        assert not store.dispatch_available() and store._unresolved is not None


@pytest.mark.parametrize('actionable', [False, True])
def test_normal_optional_transaction_keeps_both_markers_and_full_delete(tmp_path, actionable):
    store = store_at(tmp_path, limits={'batch_items': 1} if actionable else None)
    assert store.bootstrap({}, {}, AUTH)['ready']
    trace = SQLTrace()
    hooks = []
    store._db.set_trace_callback(trace.append)
    store._fault = hooks.append
    observation = obs(['192.0.2.1'])
    try:
        result = store.record_domain(observation, AUTH, TEAMS)
        saved = durable(store)
        assert result['ledger_committed'] and result['admitted_receipts'] == 1
        assert sum(s == 'BEGIN IMMEDIATE' for s in trace) == 2
        assert sum(s == 'COMMIT' for s in trace) == 2
        assert sum(s.startswith('INSERT OR REPLACE INTO control') for s in trace) == (2 if actionable else 1)
        assert hooks == ['before_commit', 'after_commit', 'before_commit', 'after_commit']
        assert (json.loads(saved['control'][0]['data'])['last_transaction'] != observation['source_operation_id']) == actionable
        assert len(saved['batch']) == int(actionable)
        assert saved['receipt'][0]['state'] == ('pending' if actionable else 'unsealed')
        assert not store._db.in_transaction
        assert store._one('PRAGMA synchronous')[0] == 2
        assert store._one('PRAGMA journal_mode')[0] == 'delete'
        assert not trace.dropped
    finally:
        store._db.set_trace_callback(None)
        store.close(clean=False)


@pytest.mark.parametrize('operation', ['claim', 'ack'])
def test_real_worker_never_calls_provider_through_live_cleanup_fence(tmp_path, monkeypatch, operation):
    from test_delivery_adapters_steps import Response, Transport
    from test_stage3_core_runtime import app_factory, scan

    class FaultAfterProvider(Transport):
        def request(self, *args, **kwargs):
            response = super().request(*args, **kwargs)
            if operation == 'ack' and len(self.calls) == 1:
                store._fault = fail_before
            return response

    transport = FaultAfterProvider(Response(status=200), Response(status=200))
    app = app_factory(tmp_path, transport=transport)
    store = app.delivery.store
    native = store._db
    try:
        assert scan(app, monkeypatch, ['192.0.2.1'])[0]
        before = durable(store)
        wrapper = ConnectionFault(native)
        store._db = wrapper
        if operation == 'claim':
            store._fault = fail_before
        app.delivery.worker.run_pass()
        saved = durable(store)
        assert native.in_transaction and not store.dispatch_available()
        assert len(transport.calls) == int(operation == 'ack')
        assert saved['receipt'][0]['state'] == ('in_flight' if operation == 'ack' else 'pending')
        assert saved['terminal'] == []
        assert saved['cursor'] == before['cursor']
        assert not store._gap and not any(store._volatile.values())
        assert app.delivery.worker.run_pass()['provider_calls'] == 0
        assert durable(store) == saved and native.in_transaction
        store._fault = lambda _: None
        wrapper.rollback_mode = 'normal'
        store._monotonic = lambda: store._recovery_next
        app.delivery.worker.run_pass(max_provider_calls=0)
        assert not native.in_transaction and store.dispatch_available()
        if operation == 'ack':
            app.clock.now = durable(store)['receipt'][0]['due']
        app.delivery.worker.run_pass()
        assert durable(store)['receipt'] == []
        assert store.health_snapshot()['acked_total'] == 1
        assert store.health_snapshot()['missed_total'] == store.health_snapshot()['failed_total'] == 0
    finally:
        store._fault = lambda _: None
        store._db = native
        native.rollback()
        app.delivery.stop()
