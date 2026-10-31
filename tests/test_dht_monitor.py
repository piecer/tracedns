"""Synthetic signed records through the actual collector/monitor/history path."""
import copy
import threading
from unittest.mock import patch
import pytest

from config_manager import domain_identity, domain_storage_name
from dns_monitor import restore_current_results
from history_manager import load_history_files
from models import DomainSpec
from monitor.collect import collect_snapshot
from monitor.engine import run_domain_cycle, run_full_cycle
from test_dht_query import signed_fixture


@pytest.fixture(autouse=True)
def no_dns_network():
    with patch('monitor.collect.query_dns', side_effect=AssertionError('not conventional DNS')):
        yield


def observation(seq=7, ips=('192.0.2.123',), value=None):
    raw, key = signed_fixture(seq, ips, value)
    # Supply independently signed evidence, not precomputed derived IP claims.
    return {'records': [{'public_key': key.hex(), 'seq': str(seq),
                         'signature': raw[b'sig'].hex(), 'value_hex': raw[b'v'].hex()}],
            'coverage': {'termination': 'queue_exhausted', 'queries_sent': 2}}, key.hex()


def target(key):
    return {'name': 'DHT research.', 'type': 'DHT', 'dht_public_key': key,
            'dht_options': {'duration': 1, 'max_queries': 4}}


def cycle(tmp_path, domain, obs, current, history, failures):
    with patch('dht_query.fetch_dht_records', return_value=obs), \
         patch('monitor.collect.query_dns', side_effect=AssertionError('not conventional DNS')):
        return run_domain_cycle(domain=DomainSpec(**domain), servers=['DHT'],
                                current_results=current, history=history,
                                history_dir=str(tmp_path), query_fail_counts=failures, max_workers=1)


def test_dht_display_label_identity_is_literal_not_dns_normalization():
    _, key = observation()
    domain = target(key)
    assert domain_identity(domain) == 'dht research.|DHT|' + key
    assert domain_storage_name(domain) == 'DHT research. [DHT:' + key + ']'
    assert domain_identity(domain) != domain_identity({**domain, 'name': 'DHT research'})


def test_collector_reverifies_evidence_and_never_uses_dns():
    obs, key = observation(2**53 + 1)
    with patch('dht_query.fetch_dht_records', return_value=obs) as fetch, \
         patch('monitor.collect.query_dns', side_effect=AssertionError('not DNS')):
        result = collect_snapshot(DomainSpec(**target(key)), 'DHT')
    assert fetch.call_count == 1
    assert result.query.status == 'ok'
    assert result.snapshot.dht_record['seq'] == str(2**53 + 1)
    assert result.snapshot.managed_ips() == {'192.0.2.123'}
    assert result.snapshot.values == [obs['records'][0]['value_hex']]
    assert result.dht_observation == obs


def test_three_misses_keep_confirmed_ips_and_surface_latest_attempt(tmp_path):
    obs, key = observation()
    domain = target(key)
    name = domain_storage_name(domain)
    current, history, failures = {}, {}, {}
    cycle(tmp_path, domain, obs, current, history, failures)
    for _ in range(4):
        cycle(tmp_path, domain, {'records': [], 'coverage': {}}, current, history, failures)
    assert current[name]['DHT']['decoded_ips'] == ['192.0.2.123']
    attempt = history[name]['meta']['dht_observation']
    assert attempt['status'] == 'no_verified_record'
    assert attempt['confirmed_in_this_run'] is False
    loaded = load_history_files(str(tmp_path))
    assert loaded[name]['meta']['dht_state']['highest_seq'] == '7'
    assert restore_current_results(loaded)[name]['DHT']['decoded_ips'] == ['192.0.2.123']


def test_conflict_highwater_restart_and_newer_empty_withdrawal(tmp_path):
    first, key = observation()
    domain = target(key)
    name = domain_storage_name(domain)
    current, history, failures = {}, {}, {}
    cycle(tmp_path, domain, first, current, history, failures)
    conflict, _ = observation(ips=('198.51.100.1',))
    cycle(tmp_path, domain, conflict, current, history, failures)
    assert history[name]['meta']['dht_observation']['status'] == 'same_seq_conflict'
    history = load_history_files(str(tmp_path))
    current = restore_current_results(history)
    cycle(tmp_path, domain, first, current, history, failures)
    assert history[name]['meta']['dht_observation']['status'] == 'same_seq_conflict'
    assert current[name]['DHT']['decoded_ips'] == ['192.0.2.123']
    bad, _ = observation(8, value=b'not DNS')
    cycle(tmp_path, domain, bad, current, history, failures)
    assert history[name]['meta']['dht_state']['highest_seq'] == '8'
    cycle(tmp_path, domain, first, current, history, failures)
    assert history[name]['meta']['dht_observation']['status'] == 'stale_only'
    empty, _ = observation(9, ips=())
    cycle(tmp_path, domain, empty, current, history, failures)
    assert current[name]['DHT']['decoded_ips'] == []
    assert history[name]['events'][-1]['old']['decoded_ips'] == ['192.0.2.123']
    assert history[name]['events'][-1]['new']['decoded_ips'] == []


def test_restore_does_not_trust_derived_ips_or_wrong_key_signature(tmp_path):
    obs, key = observation()
    domain = target(key)
    name = domain_storage_name(domain)
    current, history = {}, {}
    cycle(tmp_path, domain, obs, current, history, {})
    stored = load_history_files(str(tmp_path))
    stored[name]['current']['DHT']['decoded_ips'] = ['198.51.100.99']
    assert restore_current_results(stored)[name]['DHT']['decoded_ips'] == ['192.0.2.123']
    bad = copy.deepcopy(stored)
    bad[name]['current']['DHT']['dht_record']['signature'] = '00' * 64
    assert not restore_current_results(bad).get(name)


def test_full_cycle_has_one_provider_and_existing_alert_path(tmp_path):
    obs, key = observation()
    domain = target(key)
    name = domain_storage_name(domain)
    current, history = {}, {}
    with patch('dht_query.fetch_dht_records', return_value=obs) as fetch, \
         patch('monitor.engine.alert_new_ips') as alert:
        result = run_full_cycle(domains_raw=[domain], servers=['8.8.8.8', '1.1.1.1'],
                                current_results=current, history=history, history_dir=str(tmp_path),
                                query_fail_counts={})
    assert fetch.call_count == 1
    assert result == {'192.0.2.123': {name}}
    assert result.complete is True
    assert alert.call_args.args[0][0][2] == 'DHT'


def test_deleted_target_cancels_lookup_and_cannot_publish(tmp_path):
    from monitor.repository import MonitorStateRepository
    obs, key = observation()
    domain = target(key)
    name = domain_storage_name(domain)
    current, history = {}, {}
    repository = MonitorStateRepository(current, history, str(tmp_path), [domain])
    lease = repository.capture()[name]
    entered, release = threading.Event(), threading.Event()
    seen = []

    def fetch(*args, cancelled=None, **kwargs):
        assert callable(cancelled)
        entered.set()
        assert release.wait(3)
        seen.append(cancelled())
        return obs  # A late provider ignores cancellation; publication still must fail.

    with patch('dht_query.fetch_dht_records', side_effect=fetch):
        worker = threading.Thread(target=run_domain_cycle, kwargs={
            'domain': DomainSpec(**domain), 'servers': ['DHT'], 'current_results': current,
            'history': history, 'history_dir': str(tmp_path), 'query_fail_counts': {},
            'state_repository': repository, 'target_lease': lease})
        worker.start()
        try:
            assert entered.wait(2)
            repository.configure({'domains': [], 'servers': []}, removed=[name])
        finally:
            release.set()
            worker.join(4)
    assert not worker.is_alive()
    assert seen == [True]
    assert name not in current and name not in history


def test_production_ledger_admits_signed_snapshot_and_failure_metadata(tmp_path):
    from test_stage3_core_runtime import app_factory, rows
    from monitor.engine import reconcile_scan
    obs, key = observation()
    domain = target(key)
    name = domain_storage_name(domain)
    app = app_factory(tmp_path, config={'domains': [domain], 'servers': [],
        'alerts': {'teams_webhook': 'https://teams.invalid/hook'}, 'config_revision': 0})
    operations = set()
    try:
        for value, expected_complete in [(obs, True), ({'records': [], 'coverage': {}}, False)]:
            snap = app.cfg.snapshot()
            with patch('dht_query.fetch_dht_records', return_value=value), \
                 patch('monitor.engine.alert_new_ips', side_effect=AssertionError('no legacy delivery')):
                result = run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
                    current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
                    query_fail_counts={}, state_repository=app.repo, target_leases=snap.target_leases)
            accepted, _ = reconcile_scan(app.cfg, snap, {}, result, None)
            assert accepted is True
            assert result.complete is expected_complete
            assert app.current[name]['DHT']['decoded_ips'] == ['192.0.2.123']
            operations.add(rows(app, 'cursor')[0]['operation'])
        assert len(operations) == 1  # Failed lookup persists metadata, never fabricates a positive observation.
        assert len(rows(app, 'receipt')) == 1  # Only the original addition, no resend/removal.
        assert rows(app, 'receipt')[0]['action'] == 'Added'
        assert rows(app, 'grace') == []
        saved = load_history_files(str(tmp_path))
        assert saved[name]['meta']['dht_observation']['status'] == 'no_verified_record'
        assert saved[name]['meta']['dht_state']['highest_seq'] == '7'
    finally:
        app.delivery.stop()
