"""Optional source-seal inspection keeps durability without a marker-only write."""
from contextlib import contextmanager
import copy
import json
import sqlite3

import pytest

from monitor.delivery_runtime import render_batch
from monitor.delivery_types import TeamsPayloadTooLarge, encode_body
from test_delivery_store_atomic import AUTH, BINDINGS, obs, store_at
from test_delivery_transaction_cleanup import ConnectionFault, SQLTrace, TEAMS, durable


def control(saved):
    return json.loads(saved['control'][0]['data'])


def control_writes(trace):
    assert not trace.dropped
    return sum(s.startswith('INSERT OR REPLACE INTO control') for s in trace)


@pytest.mark.parametrize('channels', ['teams', 'misp', 'mixed', 'backlog'])
def test_public_admission_elides_only_optional_control_write(tmp_path, channels):
    renders = []

    def render(*args):
        renders.append(args)
        return render_batch(*args)

    store = store_at(tmp_path, render=render, clock=lambda: 100)
    assert store.bootstrap({}, {}, AUTH)['ready']
    native = store._db
    try:
        if channels == 'backlog':
            assert store.record_domain(obs(['192.0.2.99'], target='backlog'), AUTH, TEAMS)['ledger_committed']
        bindings = TEAMS if channels == 'teams' else BINDINGS if channels in ('misp', 'backlog') else TEAMS + BINDINGS
        for index in (1, 2):
            trace, hooks = SQLTrace(), []
            renders.clear()
            native.set_trace_callback(trace.append)
            store._fault = hooks.append
            before = durable(store)
            observation = obs([f'192.0.2.{index}'], target=f'target-{index}')
            result = store.record_domain(observation, AUTH, bindings)
            saved = durable(store)  # before closing, rolling back or reopening writer
            assert result == {'outcome': 'admitted', 'admitted_receipts': len(bindings),
                              'missed_receipts': 0, 'ledger_committed': True, 'accounting_complete': True}
            assert len(saved['receipt']) == len(before['receipt']) + len(bindings)
            fresh = [r for r in saved['receipt'] if r['operation'] == observation['source_operation_id']]
            assert {r['channel'] for r in fresh} == {b['channel'] for b in bindings}
            for row in fresh:
                assert row['binding'] == next(b['binding_id'] for b in bindings if b['channel'] == row['channel'])
                assert row['reserved'] > len(row['payload'].encode())
                assert row['source_target'] == observation['target']
                assert row['source_signature'] == observation['projection_signature']
                cursor = next(c for c in saved['cursor'] if c['target'] == observation['target'])
                assert cursor['operation'] == row['operation']
                assert cursor['incarnation'] == row['source_incarnation']
                assert cursor['addition_epoch'] == control(saved)['addition_epoch']
                assert row['state'] == ('unsealed' if row['channel'] == 'teams' else 'pending')
            assert saved['batch'] == saved['terminal'] == []
            assert control(saved)['epoch'] == control(before)['epoch']
            assert all(control(saved)[key] == 0 for key in ('acked_total', 'missed_total', 'failed_total'))
            expected_renders = index if channels in ('teams', 'mixed') else int(channels == 'backlog')
            assert len(renders) == expected_renders
            assert all(args[1:] == ('Added', 100) for args in renders)
            assert hooks == ['before_commit', 'after_commit', 'before_commit', 'after_commit']
            assert trace.count('BEGIN IMMEDIATE') == trace.count('COMMIT') == 2
            assert not native.in_transaction
            assert native.execute('PRAGMA synchronous').fetchone()[0] == 2
            assert native.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
            assert control_writes(trace) == 1, 'optional inspection still writes control'
            assert control(saved)['last_transaction'] == observation['source_operation_id']
    finally:
        store._fault = lambda _: None
        native.set_trace_callback(None)
        store.close(clean=False)


@contextmanager
def production_store(tmp_path, **kwargs):
    store = store_at(tmp_path, clock=lambda: 100, render=render_batch, **kwargs)
    assert store.bootstrap({}, {}, AUTH)['ready']
    native = store._db
    try:
        yield store, native
    finally:
        store._fault = lambda _: None
        store._db = native
        native.set_trace_callback(None)
        native.rollback()
        store.close(clean=False)


def observe_transactions(store, monkeypatch):
    real = store._transaction
    calls = []

    def transaction(operation, fn, **kwargs):
        result = real(operation, fn, **kwargs)
        calls.append((operation, kwargs, result))
        return result

    monkeypatch.setattr(store, '_transaction', transaction)
    return calls


@pytest.mark.parametrize('shape', ['count', 'full_tail', 'bytes', 'singleton', 'singleton_tail'])
def test_mutating_seal_keeps_optional_write_even_when_batch_count_zero(tmp_path, monkeypatch, shape):
    entries = [[f'192.0.2.{i}', 'label', 'A'] for i in (1, 2)]
    byte_limit = len(encode_body(render_batch(entries[:1], 'Added', 100)))
    assert len(encode_body(render_batch(entries, 'Added', 100))) > byte_limit
    limits = {'batch_items': 2} if shape in ('count', 'full_tail') else {'batch_bytes': byte_limit} if shape == 'bytes' else None
    with production_store(tmp_path, limits=limits) as (store, native):
        if shape == 'singleton_tail':
            assert store.record_domain(obs(['192.0.2.1'], label='label'), AUTH, TEAMS)['ledger_committed']
        typed_hits = []
        if shape.startswith('singleton'):
            def render(candidate, action, created):
                if candidate[0][0] == '192.0.2.1':
                    typed_hits.append(candidate)
                    raise TeamsPayloadTooLarge('payload_limit')
                return render_batch(candidate, action, created)
            store._render = render
        ips = ['192.0.2.2'] if shape == 'singleton_tail' else ['192.0.2.1'] if shape == 'singleton' else [e[0] for e in entries]
        if shape == 'full_tail':
            ips.append('192.0.2.3')
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        calls = observe_transactions(store, monkeypatch)
        observation = obs(ips, target='new', label='label')
        assert store.record_domain(observation, AUTH, TEAMS)['admitted_receipts'] == len(ips)
        saved = durable(store)
        assert control_writes(trace) == 2
        assert control(saved)['last_transaction'] == calls[1][0] != observation['source_operation_id']
        assert calls[0][1].get('allow_noop', False) is False
        assert calls[1][1]['allow_noop'] is True
        assert calls[1][2] == (True, 0 if shape.startswith('singleton') else 1, False)
        assert trace.count('BEGIN IMMEDIATE') == trace.count('COMMIT') == 2
        assert not native.in_transaction
        assert control(saved)['acked_total'] == control(saved)['missed_total'] == 0
        if shape.startswith('singleton'):
            assert len(typed_hits) == 1
            assert saved['batch'] == []
            assert len(saved['terminal']) == control(saved)['failed_total'] == 1
            assert saved['terminal'][0]['reason'] == 'payload_limit'
            assert len(saved['receipt']) == int(shape == 'singleton_tail')
            if saved['receipt']:
                assert saved['receipt'][0]['ip'] == '192.0.2.2' and saved['receipt'][0]['state'] == 'unsealed'
        else:
            assert saved['terminal'] == [] and control(saved)['failed_total'] == 0
            batch = saved['batch'][0]
            members = [r for r in saved['receipt'] if r['state'] == 'pending']
            expected = entries[:1] if shape == 'bytes' else entries
            payload = json.loads(batch['payload'])
            assert payload == {'entries': expected, 'body': render_batch(expected, 'Added', 100)}
            assert batch['id'] == members[0]['id'] and batch['created'] == 100
            assert all(r['batch_id'] == batch['id'] for r in members)
            assert len(members) == len(expected)
            assert len([r for r in saved['receipt'] if r['state'] == 'unsealed']) == int(shape in ('bytes', 'full_tail'))
            # Retry must use the frozen payload, not a new render.
            from test_delivery_store_claims import result as provider_result
            claim = store.claim_next(TEAMS[0], 100)
            assert claim['payload'] == payload
            assert store.finish_step(claim, provider_result('retry'), 100)['applied']
            retry = store.claim_next(TEAMS[0], 130)
            assert retry['payload'] == payload


def test_first_fitting_group_still_blocks_later_full_group(tmp_path):
    with production_store(tmp_path, limits={'batch_items': 2}) as (store, native):
        first = obs(['192.0.2.1'], target='first')
        store.record_domain(first, AUTH, TEAMS)
        other = [{**TEAMS[0], 'binding_id': 'b' * 64}]
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        later = obs(['192.0.2.2', '192.0.2.3'], target='later')
        assert store.record_domain(later, AUTH, other)['admitted_receipts'] == 2
        saved = durable(store)
        assert control_writes(trace) == 1
        assert control(saved)['last_transaction'] == later['source_operation_id']
        assert saved['batch'] == []
        assert [r['state'] for r in saved['receipt']] == ['unsealed'] * 3
        assert [r['binding'] for r in saved['receipt']] == [TEAMS[0]['binding_id']] + [other[0]['binding_id']] * 2


def test_optin_deep_control_mutation_requires_write(tmp_path):
    with production_store(tmp_path) as (store, native):
        store._control['nested_probe'] = {'items': [0]}
        assert store._transaction('seed-nested', lambda: None)[0]
        before = native.total_changes
        trace = SQLTrace()
        native.set_trace_callback(trace.append)

        def mutate():
            store._control['nested_probe']['items'].append(1)
            assert native.total_changes == before
            return 0

        assert store._transaction('control-only', mutate, allow_noop=True) == (True, 0, False)
        saved = durable(store)
        assert control_writes(trace) == 1
        assert control(saved)['nested_probe'] == {'items': [0, 1]}
        assert control(saved)['last_transaction'] == 'control-only'


@pytest.mark.parametrize('boundary', ['before', 'after'])
@pytest.mark.parametrize('fault', ['attribute', 'sqlite', 'os', 'value', 'type', 'boolean', 'negative'])
def test_unavailable_counter_falls_back_to_real_write(tmp_path, monkeypatch, boundary, fault):
    with production_store(tmp_path) as (store, native):
        class MissingCounter(ConnectionFault):
            reads = 0

            def __getattr__(self, name):
                if name == 'total_changes':
                    self.reads += 1
                    if self.reads == (1 if boundary == 'before' else 2):
                        if fault == 'boolean':
                            return False
                        if fault == 'negative':
                            return -1
                        raise {'attribute': AttributeError, 'sqlite': sqlite3.OperationalError,
                               'os': OSError, 'value': ValueError, 'type': TypeError}[fault]('counter unavailable')
                return getattr(self.native, name)

        wrapper = MissingCounter(native, rollback='normal')
        store._db = wrapper
        calls = observe_transactions(store, monkeypatch)
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        assert store.record_domain(obs(['192.0.2.1']), AUTH, TEAMS)['ledger_committed']
        saved = durable(store)
        assert wrapper.reads == (1 if boundary == 'before' else 2)
        assert control_writes(trace) == 2
        assert control(saved)['last_transaction'] == calls[1][0]
        assert calls[1][2] == (True, 0, False)
        assert saved['receipt'][0]['state'] == 'unsealed' and not native.in_transaction


@pytest.mark.parametrize('boundary', ['begin', 'query', 'body', 'runtime', 'value', 'malformed', 'save'])
def test_optional_fault_actual_boundary_retains_source(tmp_path, monkeypatch, boundary):
    with production_store(tmp_path, limits={'batch_items': 1} if boundary == 'save' else None) as (store, native):
        hits, hooks = [], []
        real_execute, real_one, real_save = store._execute, store._one, store._save_control
        begins = []

        def execute(sql, *args):
            if sql == 'BEGIN IMMEDIATE':
                begins.append(sql)
                if boundary == 'begin' and len(begins) == 2:
                    hits.append(boundary)
                    raise sqlite3.OperationalError('private injected begin error')
            return real_execute(sql, *args)

        def one(sql, *args):
            if boundary == 'query' and "SELECT * FROM receipt WHERE state='unsealed'" in sql:
                hits.append(boundary)
                raise sqlite3.OperationalError('private injected query error')
            return real_one(sql, *args)

        class BodyFault(ConnectionFault):
            def execute(self, sql, *args):
                if "SELECT * FROM receipt WHERE state='unsealed' AND cycle=" in sql:
                    hits.append(boundary)
                    raise sqlite3.OperationalError('private injected body error')
                return native.execute(sql, *args)

        def render(*args):
            hits.append(boundary)
            if boundary == 'malformed':
                return {'title': 'missing text'}
            raise (RuntimeError if boundary == 'runtime' else ValueError)('payload_limit')

        def save():
            if len(begins) == 2:
                hits.append(boundary)
                raise sqlite3.OperationalError('private injected save error')
            return real_save()

        monkeypatch.setattr(store, '_execute', execute)
        monkeypatch.setattr(store, '_one', one)
        if boundary == 'body':
            store._db = BodyFault(native, rollback='normal')
        if boundary in ('runtime', 'value', 'malformed'):
            store._render = render
        if boundary == 'save':
            monkeypatch.setattr(store, '_save_control', save)
        store._fault = hooks.append
        calls = observe_transactions(store, monkeypatch)
        observation = obs(['192.0.2.1'])
        result = store.record_domain(observation, AUTH, TEAMS)
        saved = durable(store)
        assert hits == [boundary] and len(begins) == 2
        assert hooks == ['before_commit', 'after_commit']
        assert result['ledger_committed'] and result['admitted_receipts'] == 1 and result['missed_receipts'] == 0
        assert calls[1][2] == (False, None, False)
        assert saved['cursor'][0]['operation'] == observation['source_operation_id']
        assert control(saved)['last_transaction'] == observation['source_operation_id']
        assert saved['receipt'][0]['state'] == 'unsealed'
        assert saved['batch'] == saved['terminal'] == []
        assert all(control(saved)[key] == 0 for key in ('acked_total', 'failed_total', 'missed_total'))
        assert not native.in_transaction and store._unresolved is None
        assert not store._gap and not any(store._volatile.values())
        error = store.diagnostics_snapshot()['storage_error']
        assert error['stage'] == ('transaction_begin' if boundary == 'begin' else 'transaction_body')
        assert error['code'] == ('invalid_state' if boundary in ('runtime', 'value', 'malformed') else 'sqlite_error')
        assert 'private injected' not in json.dumps(error) and 'payload_limit' not in json.dumps(error)


@pytest.mark.parametrize('actionable', [False, True])
@pytest.mark.parametrize('boundary', ['before_commit', 'refuse', 'commit_then_raise', 'after_commit'])
def test_optional_commit_distinctions_keep_private_result_truthful(tmp_path, monkeypatch, actionable, boundary):
    with production_store(tmp_path, limits={'batch_items': 1} if actionable else None) as (store, native):
        hits, hooks = [], []

        class CommitFault(ConnectionFault):
            def commit(self):
                self.commits += 1
                if self.commits == 2 and boundary == 'refuse':
                    hits.append(boundary)
                    raise sqlite3.OperationalError('commit refused')
                native.commit()
                if self.commits == 2 and boundary == 'commit_then_raise':
                    hits.append(boundary)
                    raise sqlite3.OperationalError('commit reply lost')

        wrapper = CommitFault(native, rollback='normal')
        store._db = wrapper

        def hook(point):
            hooks.append(point)
            if boundary == point and hooks.count(point) == 2:
                hits.append(boundary)
                raise sqlite3.OperationalError('private hook error')

        store._fault = hook
        calls = observe_transactions(store, monkeypatch)
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        observation = obs(['192.0.2.1'])
        result = store.record_domain(observation, AUTH, TEAMS)
        saved = durable(store)
        committed = actionable and boundary in ('commit_then_raise', 'after_commit')
        assert hits == [boundary]
        assert hooks == ['before_commit', 'after_commit', 'before_commit'] + (['after_commit'] if boundary == 'after_commit' else [])
        assert wrapper.commits == (1 if boundary == 'before_commit' else 2)
        assert wrapper.rollbacks == 1
        assert trace.count('COMMIT') == (2 if boundary in ('commit_then_raise', 'after_commit') else 1)
        assert control_writes(trace) == (2 if actionable else 1)
        assert result['ledger_committed'] and result['admitted_receipts'] == 1 and result['missed_receipts'] == 0
        assert calls[1][2] == ((True, 1, False) if committed else (False, None, False))
        assert control(saved)['last_transaction'] == (calls[1][0] if committed else observation['source_operation_id'])
        assert saved['cursor'][0]['operation'] == observation['source_operation_id']
        assert saved['receipt'][0]['state'] == ('pending' if committed else 'unsealed')
        assert len(saved['batch']) == int(committed)
        assert saved['terminal'] == []
        assert all(control(saved)[key] == 0 for key in ('acked_total', 'failed_total', 'missed_total'))
        assert not native.in_transaction and store._unresolved is None and store.dispatch_available()
        assert not store._gap and not any(store._volatile.values())
        assert store.diagnostics_snapshot()['storage_error']['stage'] == ('transaction_body' if boundary == 'before_commit' else 'transaction_commit')


@pytest.mark.parametrize('boundary', ['before_commit', 'after_commit'])
@pytest.mark.parametrize('invalid', ['unreadable', 'epoch', 'typed', 'binding'])
def test_noop_unresolved_keeps_marker_identity_and_newer_loss_owner(tmp_path, monkeypatch, boundary, invalid):
    with production_store(tmp_path) as (store, native):
        real_read = store._read_control
        reads, hooks, hits = [], [], []

        def read():
            reads.append(invalid)
            saved = real_read()
            if invalid == 'unreadable':
                raise sqlite3.OperationalError('private unreadable')
            saved.update({'epoch': {'epoch': 'wrong'}, 'typed': {'failed_total': True},
                          'binding': {'binding_key': 'wrong'}}[invalid])
            return saved

        def hook(point):
            hooks.append(point)
            if point == boundary and hooks.count(point) == 2:
                hits.append(point)
                raise sqlite3.OperationalError('private optional failure')

        monkeypatch.setattr(store, '_read_control', read)
        store._fault = hook
        calls = observe_transactions(store, monkeypatch)
        observation = obs(['192.0.2.1'])
        result = store.record_domain(observation, AUTH, TEAMS)
        saved = durable(store)
        assert result['ledger_committed'] and result['admitted_receipts'] == 1 and result['missed_receipts'] == 0
        assert reads == [invalid] and hits == [boundary]
        assert calls[1][2] == (False, None, True)
        pending = store._unresolved
        assert pending['operation'] == calls[1][0] != control(saved)['last_transaction']
        assert control(saved)['last_transaction'] == observation['source_operation_id']
        assert pending['losses'] == {} and pending['checkpoint'] is pending['captured'] is None
        assert not native.in_transaction and not store.dispatch_available()
        assert store.diagnostics_snapshot()['storage_error']['stage'] == 'transaction_readback'
        store._fault = lambda _: None
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        assert store._transaction('forbidden', lambda: pytest.fail('unresolved body ran')) == (False, None, True)
        assert store.claim_next(TEAMS[0], 100) is None
        assert trace == []
        later = obs(['192.0.2.2'], target='later')
        assert store.record_domain(later, AUTH, TEAMS)['outcome'] == 'gap'
        assert store._volatile == {'teams': 1, 'misp': 0}
        assert store._unresolved is pending and pending['losses'] == {}
        # A later independent tracking diagnostic must also remain sticky.
        store._tracking_loss()
        assert not store._control['tracking_complete'] and not store._control['accounting_complete']
        assert store.recover_delivery(100)['state'] == 'uncertain'
        assert store._unresolved is pending and not store.dispatch_available()
        assert durable(store) == saved and control_writes(trace) == 0
        assert not any(s.startswith(('BEGIN', 'INSERT', 'UPDATE', 'DELETE')) for s in trace)
        monkeypatch.setattr(store, '_read_control', real_read)
        with store._lock:
            store._resolve_unresolved()
            assert store._unresolved is None
            assert store._volatile == {'teams': 1, 'misp': 0}
            assert store._checkpoint == {'teams': 0, 'misp': 0}
            assert store._control['last_transaction'] == observation['source_operation_id']
            assert not store._control['tracking_complete'] and not store._control['accounting_complete']
            store._resolve_unresolved()  # idempotent, no second loss restoration
            assert store._volatile == {'teams': 1, 'misp': 0}
        assert durable(store) == saved
        store._monotonic = lambda: store._recovery_next
        assert store.recover_delivery(100)['state'] == 'ready'
        after = durable(store)
        assert {k: v for k, v in after.items() if k != 'control'} == {k: v for k, v in saved.items() if k != 'control'}
        assert store._checkpoint == {'teams': 1, 'misp': 0} and not any(store._volatile.values())
        assert control(after)['missed_total'] == 1
        assert control(after)['acked_total'] == control(after)['failed_total'] == 0
        assert not control(after)['accounting_complete'] and not control(after)['tracking_complete']
        assert store.recover_delivery(100)['state'] == 'ready'
        assert durable(store) == after and not native.in_transaction


@pytest.mark.parametrize('operation', ['generic', 'public_seal'])
def test_default_transactions_persist_preexisting_dirty_control(tmp_path, monkeypatch, operation):
    with production_store(tmp_path) as (store, native):
        before = durable(store)
        store.enter_gap('delivery_storage', {})
        assert control(before)['accounting_complete'] and not store._control['accounting_complete']
        calls = observe_transactions(store, monkeypatch)
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        if operation == 'generic':
            assert store._transaction('default-generic', lambda: None) == (True, None, False)
        else:
            assert store.seal_cycle(None) == {'ledger_committed': True, 'sealed_batches': 0}
        saved = durable(store)
        assert control_writes(trace) == 1
        assert calls[0][1].get('allow_noop', False) is False
        assert not control(saved)['accounting_complete']
        assert control(saved)['last_transaction'] == calls[0][0] != control(before)['last_transaction']


@pytest.mark.parametrize('boundary', ['cancelled', 'stale', 'begin', 'uncertain', 'commit_then_raise'])
def test_only_proved_successful_source_may_optin(tmp_path, monkeypatch, boundary):
    with production_store(tmp_path) as (store, native):
        hits = []
        if boundary == 'begin':
            real = store._execute

            def execute(sql, *args):
                if sql == 'BEGIN IMMEDIATE':
                    hits.append(boundary)
                    raise sqlite3.OperationalError('source begin failed')
                return real(sql, *args)

            monkeypatch.setattr(store, '_execute', execute)
        if boundary in ('uncertain', 'commit_then_raise'):
            class SourceCommitFault(ConnectionFault):
                def commit(self):
                    self.commits += 1
                    native.commit()
                    if self.commits == 1:
                        hits.append(boundary)
                        raise sqlite3.OperationalError('source reply unavailable')
            store._db = SourceCommitFault(native, rollback='normal')
            if boundary == 'uncertain':
                def read():
                    raise sqlite3.OperationalError('source readback unavailable')
                monkeypatch.setattr(store, '_read_control', read)
        calls = observe_transactions(store, monkeypatch)
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        observation = obs(['192.0.2.1'], **({'expected_operation_id': 'wrong'} if boundary == 'stale' else {}))
        result = store.record_domain(observation, AUTH, TEAMS, cancelled=lambda: boundary == 'cancelled')
        saved = durable(store)
        opted = [call for call in calls if call[1].get('allow_noop', False)]
        assert len(opted) == int(boundary == 'commit_then_raise')
        if boundary == 'commit_then_raise':
            assert opted[0][2] == (True, 0, False)
            assert result['ledger_committed'] and result['admitted_receipts'] == 1
            assert control_writes(trace) == 1
            assert control(saved)['last_transaction'] == observation['source_operation_id']
        else:
            assert not result['ledger_committed'] and result['admitted_receipts'] == 0
        assert bool(saved['receipt']) == (boundary in ('uncertain', 'commit_then_raise'))
        assert (store._unresolved is not None) == (boundary == 'uncertain')
        assert not native.in_transaction
        assert hits == ([boundary] if boundary in ('begin', 'uncertain', 'commit_then_raise') else [])


@pytest.mark.parametrize('fault', ['sql', 'wall', 'mono'])
def test_post_source_refresh_failure_does_not_create_dirty_control(tmp_path, monkeypatch, fault):
    with production_store(tmp_path) as (store, native):
        store._note_storage_error(sqlite3.OperationalError('database is locked'), 'health_refresh')
        old_error = copy.deepcopy(store._storage_error)
        old_anchors = store._health_cache[1]
        old_diagnostics = store._diagnostics
        real_one = store._one
        hits = []

        def one(sql, *args):
            value = real_one(sql, *args)
            if sql.startswith('SELECT id,created FROM receipt'):
                hits.append(fault)
                if fault == 'sql':
                    raise sqlite3.OperationalError('database is locked')
                if fault == 'wall':
                    store._clock = lambda: float('nan')
                else:
                    store._monotonic = lambda: float('nan')
            return value

        monkeypatch.setattr(store, '_one', one)
        calls = observe_transactions(store, monkeypatch)
        trace = SQLTrace()
        native.set_trace_callback(trace.append)
        observation = obs(['192.0.2.1'])
        assert store.record_domain(observation, AUTH, TEAMS)['ledger_committed']
        saved = durable(store)
        assert hits == [fault, fault]  # source AND real read-only seal refresh
        assert calls[1][2] == (True, 0, False) and calls[1][1]['allow_noop'] is True
        assert control_writes(trace) == 1
        assert control(saved)['last_transaction'] == observation['source_operation_id']
        assert store._health_cache[1] is old_anchors and store._diagnostics is old_diagnostics
        assert store._storage_error == old_error and store.health_snapshot()['counts_stale']
        assert saved['receipt'][0]['state'] == 'unsealed'
        assert not native.in_transaction and store._unresolved is None
        store._clock = lambda: 100
        store._monotonic = lambda: 100
