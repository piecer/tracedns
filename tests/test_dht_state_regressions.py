"""DHT admission regressions: real stop and real owned persistence faults."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dht_state_helpers import application, scan, rows, offline as offline, ROOT
from test_dht_monitor import observation, target
from config_manager import domain_storage_name
from history_manager import load_history_files
from monitor import engine
from monitor.scheduler import MonitorScheduler


def test_scheduler_stop_must_cancel_active_lookup_and_block_late_withdrawal(tmp_path):
    first, key = observation(7)
    empty, _ = observation(8, ips=())
    dom = target(key); name = domain_storage_name(dom)
    app = application(tmp_path / 'runtime', [dom])
    scan(app, first)
    entered, release = threading.Event(), threading.Event()
    seen, result, errors = [], [], []
    def fetch(*args, cancelled=None, **kwargs):
        entered.set()
        assert release.wait(4)
        seen.append(cancelled())
        return empty
    def worker():
        try:
            result.append(scan(app))
        except BaseException as exc:
            errors.append(exc)
    with patch('dht_query.fetch_dht_records', side_effect=fetch):
        thread = threading.Thread(target=worker)
        thread.start()
        try:
            assert entered.wait(2)
            # This is the exact stop callback used by dns_monitor.main's signal bridge.
            MonitorScheduler(app.cfg).stop()
            assert app.cfg.raw['_monitor_stopped']
            release.set(); thread.join(5)
            assert not thread.is_alive() and not errors
            receipt = {'cancelled_seen': seen, 'accepted': result[0][0],
                       'complete': result[0][1].complete, 'active_ips': sorted(result[0][1]),
                       'snapshot_ips': app.current[name]['DHT']['decoded_ips'],
                       'persisted_seq': load_history_files(app.repo.history_dir)[name]['meta']['dht_state']['highest_seq'],
                       'grace_rows': len(rows(app, 'grace'))}
            print('STOP_RECEIPT=' + json.dumps(receipt))
            assert seen == [True] and app.current[name]['DHT']['decoded_ips'] == ['192.0.2.123'], receipt
        finally:
            release.set(); thread.join(5); app.delivery.stop()


def test_actual_history_replace_failure_does_not_allow_replayed_empty(tmp_path):
    first, key = observation(5)
    dom = target(key); name = domain_storage_name(dom)
    path = tmp_path / 'runtime'
    app = application(path, [dom])
    scan(app, first)
    invalid, _ = observation(7, value=b'not DNS')
    replay, _ = observation(6, ips=())
    try:
        with patch.object(app.repo, 'commit_history', side_effect=OSError('synthetic owned-file failure')) as fail:
            scan(app, invalid)
            scan(app, replay)
            assert fail.call_count == 2
            assert app.history[name]['meta']['dht_state']['highest_seq'] == '7'
            assert load_history_files(str(path))[name]['meta']['dht_state']['highest_seq'] == '5'
            assert app.delivery.store.health_snapshot()['last_error'] == 'history_persistence'
    finally:
        app.delivery.stop()
    app = application(path, [dom], restart=True)
    try:
        health_before = app.delivery.store.health_snapshot()
        scan(app, replay)
        app.clock.now += 86401
        scan(app, replay)
        removed = [r for r in rows(app, 'receipt') if r['action'] == 'Removed']
        receipt = {'health_after_restart': {k:health_before.get(k) for k in ('coverage', 'last_error')},
                   'current_ips': app.current[name]['DHT']['decoded_ips'],
                   'highest_seq': app.history[name]['meta']['dht_state']['highest_seq'],
                   'removed_payloads': [json.loads(r['payload']) for r in removed]}
        print('ACTUAL_WRITE_FAILURE=' + json.dumps(receipt))
        assert app.current[name]['DHT']['decoded_ips'] == ['192.0.2.123'] and not removed, receipt
    finally:
        app.delivery.stop()


def test_real_main_sigterm_fences_dht_before_final_snapshot(tmp_path):
    script = Path(__file__).with_name('dht_state_signal_child.py')
    completed = subprocess.run([sys.executable, str(script), str(tmp_path)], cwd=ROOT,
                               text=True, capture_output=True, timeout=15)
    print(completed.stdout)
    print(completed.stderr)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_signal_latch_alone_fences_final_owned_admission(tmp_path):
    first, key = observation(7)
    empty, _ = observation(8, ips=())
    dom = target(key)
    name = domain_storage_name(dom)
    app = application(tmp_path / 'runtime', [dom])
    try:
        scan(app, first)
        before = deepcopy(app.history[name])
        original = app.repo.accept_observation
        fired = []
        def request_then_admit(*args, **kwargs):
            # Coordinator has not acquired the config lock yet.
            app.cfg.raw['_signal_stop'] = SimpleNamespace(requested=True)
            fired.append(True)
            return original(*args, **kwargs)
        with patch.object(app.repo, 'accept_observation', side_effect=request_then_admit):
            accepted, result = scan(app, empty)
        assert fired == [True]
        assert not accepted and not result.complete
        assert app.history[name] == before
        assert app.current[name]['DHT']['decoded_ips'] == ['192.0.2.123']
        assert not rows(app, 'grace')
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('kind', ['invalid', 'conflict'])
def test_failed_history_commit_preserves_evidence_not_just_ips(tmp_path, kind):
    first, key = observation(5)
    dom = target(key)
    name = domain_storage_name(dom)
    path = tmp_path / 'runtime'
    app = application(path, [dom])
    try:
        scan(app, first)
        later, _ = observation(7, value=b'not DNS') if kind == 'invalid' else observation(5, ips=())
        with patch.object(app.repo, 'commit_history', side_effect=OSError('owned write fault')) as failed:
            scan(app, later)
        assert failed.call_count == 1
        expected = deepcopy(app.history[name]['meta']['dht_state'])
        assert expected['highest_seq'] == ('7' if kind == 'invalid' else '5')
        assert expected['conflict'] is (kind == 'conflict')
    finally:
        app.delivery.stop()
    app = application(path, [dom], restart=True)
    try:
        # Restore conflict before supplying either variant again. Replaying the
        # conflicting variant alone could recreate a lost conflict and hide loss.
        assert app.history[name]['meta']['dht_state'] == expected
        replay = observation(6, ips=())[0] if kind == 'invalid' else first
        _, result = scan(app, replay)
        assert not result.complete and set(result) == {'192.0.2.123'}
        assert app.history[name]['meta']['dht_state'] == expected
        assert not rows(app, 'grace')
        # A genuinely newer verified empty is still authoritative.
        newer, _ = observation(8, ips=())
        _, result = scan(app, newer)
        assert result.complete and not result
        assert len(rows(app, 'grace')) == 1
        app.clock.now += 86401
        scan(app, newer)
        assert len([r for r in rows(app, 'receipt') if r['action'] == 'Removed']) == 1
    finally:
        app.delivery.stop()


def test_durable_admission_failure_retains_restart_fence(tmp_path):
    first, key = observation(5)
    later, _ = observation(7, value=b'not DNS')
    replay, _ = observation(6, ips=())
    dom = target(key)
    name = domain_storage_name(dom)
    path = tmp_path / 'runtime'
    app = application(path, [dom])
    fired = []
    try:
        scan(app, first)
        before = deepcopy(app.history[name])
        def fault(point):
            if point == 'before_commit' and not fired:
                fired.append(point)
                raise OSError('owned ledger commit failure')
        def fetch(*args, **kwargs):
            # Inject only AFTER acquisition: the pending fence can be durable.
            app.delivery.store._fault = fault
            return later
        with patch('dht_query.fetch_dht_records', side_effect=fetch):
            _, result = scan(app)
        assert fired == ['before_commit']
        assert not result.complete and set(result) == {'192.0.2.123'}
        assert app.history[name] == before
        assert not rows(app, 'grace')
    finally:
        app.delivery.store._fault = lambda point: None
        app.delivery.stop()
    app = application(path, [dom], restart=True)
    try:
        with patch('dht_query.fetch_dht_records', return_value=replay) as fetch:
            _, result = scan(app)
        assert not result.complete and set(result) == {'192.0.2.123'}
        assert not fetch.called  # Unknown failed admission needs explicit retirement.
        assert not rows(app, 'grace')
    finally:
        app.delivery.stop()


def test_first_lookup_cancel_does_not_poison_restart(tmp_path):
    first, key = observation(5)
    dom = target(key)
    path = tmp_path / 'runtime'
    app = application(path, [dom])
    def stopped(*args, **kwargs):
        MonitorScheduler(app.cfg).stop()
        return first
    try:
        with patch('dht_query.fetch_dht_records', side_effect=stopped):
            accepted, result = scan(app)
        assert not accepted and not result.complete and not result
    finally:
        app.delivery.stop()
    app = application(path, [dom], restart=True)
    try:
        _, result = scan(app, first)
        assert result.complete and set(result) == {'192.0.2.123'}
    finally:
        app.delivery.stop()


def test_stop_at_durable_commit_rolls_back_and_skips_following_target(tmp_path):
    first, key = observation(5)
    empty, _ = observation(6, ips=())
    dom = target(key)
    sibling = {**dom, 'name': 'Other label'}
    name = domain_storage_name(dom)
    path = tmp_path / 'runtime'
    app = application(path, [dom, sibling])
    fired = []
    try:
        scan(app, first)
        before = deepcopy(app.history)
        def fault(point):
            if point == 'before_commit' and not fired:
                fired.append(point)
                # Same already-published signal latch as the real handler;
                # deliberately no coordinator/config lock acquisition here.
                app.cfg.raw['_signal_stop'] = SimpleNamespace(requested=True)
        def fetch(*args, **kwargs):
            app.delivery.store._fault = fault
            return empty
        with patch('dht_query.fetch_dht_records', side_effect=fetch) as fetched:
            accepted, result = scan(app)
        assert fired == ['before_commit'] and fetched.call_count == 1
        assert not accepted and not result.complete
        assert app.history == before and not rows(app, 'grace')
        for row in rows(app, 'dht_state'):
            assert row['pending'] is None
            assert json.loads(row['data'])['state']['highest_seq'] == '5'
    finally:
        app.delivery.store._fault = lambda point: None
        app.delivery.stop()
    app = application(path, [dom, sibling], restart=True)
    try:
        _, result = scan(app, empty)
        assert result.complete and not result
        assert app.history[name]['meta']['dht_state']['highest_seq'] == '6'
    finally:
        app.delivery.stop()


def test_last_confirmed_restores_from_ledger_without_history_save(tmp_path):
    first, key = observation(5)
    newer, _ = observation(7, ips=('198.51.100.2',))
    dom = target(key)
    name = domain_storage_name(dom)
    path = tmp_path / 'runtime'
    app = application(path, [dom])
    try:
        scan(app, first)
        current_identity, history_identity = app.current[name], app.history[name]
        with patch.object(app.repo, 'commit_history', side_effect=OSError('owned file fault')) as failed:
            scan(app, newer)
        assert failed.call_count == 1
        assert app.current[name] is current_identity and app.history[name] is history_identity
        assert load_history_files(str(path))[name]['meta']['dht_state']['highest_seq'] == '5'
    finally:
        app.delivery.stop()
    app = application(path, [dom], restart=True)
    try:
        assert app.current[name]['DHT']['decoded_ips'] == ['198.51.100.2']
        assert app.history[name]['meta']['dht_state']['highest_seq'] == '7'
        _, result = scan(app, observation(6, ips=())[0])
        assert not result.complete and set(result) == {'198.51.100.2'}
    finally:
        app.delivery.stop()


def test_retirement_cleans_checkpoint_and_retains_unrelated_caller_state(tmp_path):
    first, key = observation(5)
    dom = target(key)
    sibling = {**dom, 'name': 'Other label'}
    name, other = domain_storage_name(dom), domain_storage_name(sibling)
    app = application(tmp_path / 'runtime', [dom, sibling])
    try:
        scan(app, first)
        retained = deepcopy(app.history[other])
        app.service.commit('config', {'domains': [sibling]}, expected_revision=0)
        assert {row['target'] for row in rows(app, 'dht_state')} == {other}
        assert name not in app.current and name not in app.history
        assert app.history[other] == retained
        app.service.commit('config', {'domains': [dom, sibling]}, expected_revision=1)
        scan(app, observation(1)[0])
        assert app.history[name]['meta']['dht_state']['highest_seq'] == '1'
        assert app.history[other]['meta']['dht_state']['highest_seq'] == '5'
    finally:
        app.delivery.stop()


def test_checkpoint_capacity_denies_lookup_without_evicting_evidence(tmp_path):
    first, key = observation(5)
    dom = target(key)
    sibling = {**dom, 'name': 'Other label'}
    name = domain_storage_name(dom)
    app = application(tmp_path / 'runtime', [dom, sibling])
    try:
        # Existing public store limit; no unbounded fallback map or eviction.
        app.delivery.store.limits['cursor_targets'] = 1
        with patch('dht_query.fetch_dht_records', return_value=first) as fetched:
            _, result = scan(app)
        assert fetched.call_count == 1
        assert not result.complete and set(result) == {'192.0.2.123'}
        assert [r['target'] for r in rows(app, 'dht_state')] == [name]
        assert app.delivery.store.health_snapshot()['last_error'] == 'delivery_storage'
    finally:
        app.delivery.stop()


def test_no_runtime_failure_is_not_a_complete_full_cycle(tmp_path):
    first, key = observation(5)
    dom = target(key)
    current, history = {}, {}
    def run(obs):
        with patch.dict(engine._ALERT_DEDUPE, {}, clear=True), \
                patch('dht_query.fetch_dht_records', return_value=obs), patch('monitor.engine.alert_new_ips'):
            return engine.run_full_cycle(domains_raw=[dom], servers=[], current_results=current,
                history=history, history_dir=str(tmp_path), query_fail_counts={})
    assert run(first).complete
    result = run({'records': [], 'coverage': {}})
    assert set(result) == {'192.0.2.123'}
    assert result.complete is False
