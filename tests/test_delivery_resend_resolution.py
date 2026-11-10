"""Exact uncertain-resend resolution survives independent store callers."""
import builtins
from concurrent.futures import ThreadPoolExecutor
import gc
import io
import os
from pathlib import Path
import sqlite3
import weakref

import pytest

from monitor.runtime_state import state_lock
from test_delivery_resend_admission import preview, confirm
from test_delivery_resend_vertical import rpc_app, preserved
from test_delivery_review_components import rows
from test_delivery_transaction_cleanup import ConnectionFault


def uncertain(runtime, token, monkeypatch, point='before_commit'):
    store = runtime.store
    read = store._read_control
    faults = []
    def fault(actual):
        if actual == point:
            faults.append(actual)
            raise sqlite3.OperationalError('database or disk is full')
    def unavailable():
        faults.append('readback_unavailable')
        raise sqlite3.OperationalError('database is locked')
    monkeypatch.setattr(store, '_fault', fault)
    monkeypatch.setattr(store, '_read_control', unavailable)
    assert confirm(runtime, token)['status'] == 'unknown'
    assert faults == [point, 'readback_unavailable']
    assert store._unresolved is not None and not store.dispatch_available()
    monkeypatch.setattr(store, '_fault', lambda _: None)
    return read


@pytest.mark.parametrize('resolver', ['worker', 'other_token'])
def test_exact_rollback_survives_foreign_resolution_and_repeated_status(tmp_path, monkeypatch, resolver):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime, store = app.delivery, app.delivery.store
    try:
        token = preview(runtime, target)
        before = preserved(app)
        missed = store.health_snapshot()['missed_total']
        read = uncertain(runtime, token, monkeypatch)
        monkeypatch.setattr(store, '_read_control', read)
        if resolver == 'worker':
            runtime.worker.run_pass()
        else:
            assert runtime.resend_target('f' * 32, actor_id='other')['reason'] == 'preview_expired'
        assert store._unresolved is None
        monkeypatch.setattr(store, 'admit_resend', lambda *a, **k: pytest.fail('consumed token readmitted'))
        assert runtime.resend_target(token['request_id'], actor_id='other')['reason'] == 'invalid_request'
        for _ in range(3):
            result = confirm(runtime, token)
            assert (result['status'], result['reason']) == ('not_queued', 'delivery_storage')
            assert result['ip_count'] == result['receipt_count'] == 0 and result['channels'] == []
        assert preserved(app) == before
        assert store.health_snapshot()['missed_total'] == missed
        assert not rows(store, 'manual_resend') and not rows(store, 'receipt') and not rows(store, 'batch')
        assert not transport.calls
    finally:
        runtime.stop()


@pytest.mark.parametrize('fixture_kind', ['rpc', 'source_types'])
def test_resend_fixture_isolates_sightings_without_launcher_override(tmp_path, monkeypatch, fixture_kind):
    # Deny reads AND writes before they reach any real default file. The hook
    # swallows storage failures, so assert the attempted-access log as well.
    monkeypatch.delenv('MISP_SIGHTING_BATCH_FILE', raising=False)
    attempted = []
    accesses = []
    def guarded(original):
        def call(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                name = Path(os.fsdecode(path)).name
                if name in ('misp_sighting_batch.json', 'misp_sighting_batch.json.tmp'):
                    attempted.append(name)
                    raise PermissionError('default sightings state is protected')
                if name in ('sightings.json', 'sightings.json.tmp'):
                    accesses.append(Path(os.fsdecode(path)))
            return original(path, *args, **kwargs)
        return call
    for module, name in ((builtins, 'open'), (io, 'open'), (os, 'open')):
        monkeypatch.setattr(module, name, guarded(getattr(module, name)))
    if fixture_kind == 'source_types':
        from test_delivery_resend_sources import (
            test_all_source_types_use_canonical_identity_and_configured_provider_only as source_case)
        source_case(tmp_path, monkeypatch, 'A', {'name': 'example.test', 'type': 'A'}, 'fake')
    else:
        app, _, target = rpc_app(tmp_path, monkeypatch)
        try:
            token = preview(app.delivery, target)
            assert confirm(app.delivery, token)['status'] == 'queued'
            app.delivery.worker.run_pass()
        finally:
            app.delivery.stop()
    assert attempted == []
    side_stream = tmp_path / 'side-stream' / 'sightings.json'
    assert os.environ['MISP_SIGHTING_BATCH_FILE'] == str(side_stream)
    assert accesses and all(p.parent == side_stream.parent for p in accesses)
    assert side_stream.is_file()
    assert side_stream.name not in {p.name for p in tmp_path.glob('*.json')}


@pytest.mark.parametrize('resolver', ['worker', 'other_token'])
def test_committed_resolution_still_uses_durable_marker_after_ack(tmp_path, monkeypatch, resolver):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime, store = app.delivery, app.delivery.store
    try:
        token = preview(runtime, target)
        before = preserved(app)
        read = uncertain(runtime, token, monkeypatch, 'after_commit')
        assert len(rows(store, 'receipt')) == 2 and len(rows(store, 'manual_resend')) == 1
        monkeypatch.setattr(store, '_read_control', read)
        if resolver == 'other_token':
            assert runtime.resend_target('f' * 32, actor_id='other')['reason'] == 'preview_expired'
        runtime.worker.run_pass()
        assert store._unresolved is None and not rows(store, 'receipt')
        assert len(rows(store, 'manual_resend')) == 1
        calls = len(transport.calls)
        assert calls > 0
        monkeypatch.setattr(store, 'admit_resend', lambda *a, **k: pytest.fail('committed token readmitted'))
        assert runtime.resend_target(token['request_id'], actor_id='other')['reason'] == 'invalid_request'
        for _ in range(3):
            result = confirm(runtime, token)
            assert result['status'] == 'already_queued' and result['reason'] is None
            assert result['ip_count'] == 1 and result['receipt_count'] == 2
            assert result['channels'] == ['teams', 'misp']
        assert not rows(store, 'receipt') and len(transport.calls) == calls
        assert preserved(app) == before
    finally:
        runtime.stop()


@pytest.mark.parametrize('failure', ['control_unavailable', 'invalid_control', 'native_cleanup', 'marker_unavailable'])
def test_failed_resolution_never_publishes_rollback_proof(tmp_path, monkeypatch, failure):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime, store = app.delivery, app.delivery.store
    native = store._db
    try:
        token = preview(runtime, target)
        before = preserved(app)
        committed = failure == 'marker_unavailable'
        if failure == 'native_cleanup':
            store._db = ConnectionFault(native)
        read = uncertain(runtime, token, monkeypatch, 'after_commit' if committed else 'before_commit')
        proof = runtime._resend_coordinator().intents[token['request_id']].resolution
        marker_read = store.read_resend
        if failure != 'control_unavailable':
            monkeypatch.setattr(store, '_read_control', read)
        hits = []
        if failure == 'invalid_control':
            def invalid():
                hits.append('control')
                return {**read(), 'epoch': 'foreign-ledger'}
            monkeypatch.setattr(store, '_read_control', invalid)
        elif committed:
            def unavailable(request_id):
                hits.append(request_id)
                raise sqlite3.OperationalError('marker temporarily unavailable')
            monkeypatch.setattr(store, 'read_resend', unavailable)
        for _ in range(2):
            runtime.worker.run_pass()
            result = confirm(runtime, token)
            assert (result['status'], result['reason']) == ('unknown', 'delivery_unknown')
            assert store._unresolved is not None and not proof.rolled_back
            assert not store.dispatch_available() and not transport.calls
        if failure in ('invalid_control', 'marker_unavailable'):
            assert hits
        if failure == 'native_cleanup':
            assert native.in_transaction and store._db.rollbacks >= 3
            store._db.rollback_mode = 'normal'
        else:
            assert len(rows(store, 'receipt')) == (2 if committed else 0)
            assert preserved(app) == before
        monkeypatch.setattr(store, '_read_control', read)
        monkeypatch.setattr(store, 'read_resend', marker_read)
        monkeypatch.setattr(store, '_monotonic', lambda: store._recovery_next)
        runtime.worker.run_pass()
        result = confirm(runtime, token)
        assert result['status'] == ('already_queued' if committed else 'not_queued')
        assert result['reason'] == (None if committed else 'delivery_storage')
        assert proof.rolled_back is not committed
        assert store._unresolved is None and not rows(store, 'receipt')
        assert len(rows(store, 'manual_resend')) == int(committed)
        assert preserved(app) == before
    finally:
        store._db = native
        native.rollback()
        runtime.stop()


def test_owned_resolution_publishes_once_without_foreign_locks(tmp_path, monkeypatch):
    app, _, target = rpc_app(tmp_path, monkeypatch)
    runtime, store = app.delivery, app.delivery.store
    try:
        token, sibling = preview(runtime, target), preview(runtime, target)
        coordinator = runtime._resend_coordinator()
        proof = coordinator.intents[token['request_id']].resolution
        other = coordinator.intents[sibling['request_id']].resolution
        assert proof is not other
        read = uncertain(runtime, token, monkeypatch)
        writes = []
        def observe(self, name, value):
            if self is proof:
                assert store._lock._is_owned()
                writes.append((name, value))
            object.__setattr__(self, name, value)
        monkeypatch.setattr(type(proof), '__setattr__', observe)
        monkeypatch.setattr(store, '_read_control', read)
        with ThreadPoolExecutor(max_workers=1) as pool:
            # These locks precede the store lock during confirmation. Recovery
            # must finish without acquiring them in the opposite order.
            with runtime.config.lock, runtime.repository._coord, state_lock():
                recovered = pool.submit(store.recover_delivery, runtime.clock())
                assert recovered.result(timeout=5)['state'] == 'ready'
        for _ in range(3):
            assert confirm(runtime, token)['reason'] == 'delivery_storage'
            store.recover_delivery(runtime.clock())
        assert writes == [('rolled_back', True)]
        assert not other.rolled_back and not coordinator.intents[sibling['request_id']].uncertain
        assert not rows(store, 'manual_resend') and not rows(store, 'receipt')
    finally:
        runtime.stop()


@pytest.mark.parametrize('resolve_before_expiry', [False, True])
def test_resolution_lifetime_is_bounded_by_intents_and_single_pending_owner(tmp_path, monkeypatch, resolve_before_expiry):
    app, transport, target = rpc_app(tmp_path, monkeypatch)
    runtime, store = app.delivery, app.delivery.store
    try:
        coordinator = runtime._resend_coordinator()
        now = [0]
        monkeypatch.setattr(coordinator, 'monotonic', lambda: now[0])
        tokens = [preview(runtime, target) for _ in range(128)]
        assert all(token['status'] == 'ready' for token in tokens)
        assert preview(runtime, target)['reason'] == 'preview_capacity'
        intent_refs = [weakref.ref(intent) for intent in coordinator.intents.values()]
        proof_refs = [weakref.ref(intent.resolution) for intent in coordinator.intents.values()]
        read = uncertain(runtime, tokens[0], monkeypatch)
        if resolve_before_expiry:
            monkeypatch.setattr(store, '_read_control', read)
            runtime.worker.run_pass()
            assert confirm(runtime, tokens[0])['reason'] == 'delivery_storage'
        now[0] = 300  # Original monotonic TTL, never extended by uncertainty.
        replacement = preview(runtime, target)
        assert replacement['status'] == ('ready' if resolve_before_expiry else 'not_ready')
        assert len(coordinator.intents) == int(resolve_before_expiry)
        gc.collect()
        assert all(ref() is None for ref in intent_refs)
        assert sum(ref() is not None for ref in proof_refs) == int(not resolve_before_expiry)
        monkeypatch.setattr(store, '_read_control', read)
        runtime.worker.run_pass()
        gc.collect()
        assert all(ref() is None for ref in proof_refs)
        assert confirm(runtime, tokens[0])['reason'] == 'preview_expired'
        assert not rows(store, 'manual_resend') and not rows(store, 'receipt') and not transport.calls
    finally:
        runtime.stop()
