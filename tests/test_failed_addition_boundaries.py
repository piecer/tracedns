"""Exact failure proof boundaries; real SQLite, registry, worker and HTTP fakes."""
import json

import pytest

from test_delivery_review_components import (
    AUTH, MISP, TEAMS, Response, Transport, bindings, close, make_components,
    observation, projection, rows, worker,
)

IP = '192.0.2.9'
NEW = '192.0.2.11'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('real network forbidden'))
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('real DNS forbidden'))


def failed(path, *, limits=None, channels=('teams', 'misp'), ips=(IP,)):
    failures = set(channels)
    transport = Transport(callback=lambda m, u, k: Response(status=400)
                          if ('teams' if 'teams.invalid' in u else 'misp') in failures else None)
    store, reg, transport, clock = make_components(path, config={**MISP, **TEAMS},
                                                  transport=transport, limits=limits)
    assert store.record_domain(observation(ips), AUTH, bindings(reg))['admitted_receipts'] == len(ips) * 2
    assert store.seal_cycle(None)['ledger_committed']
    worker(store, reg, clock).run_pass()
    assert rows(store, 'receipt') == []
    failures.clear()
    return store, reg, transport, clock


def disappear(store, reg, clock, ips=()):
    clock[0] += 120
    return store.record_domain(observation(ips, now=clock[0]), AUTH, bindings(reg))


def return_ips(store, reg, clock, ips=(IP,)):
    clock[0] += 120
    return store.record_domain(observation(ips, now=clock[0]), AUTH, bindings(reg))


@pytest.mark.parametrize('mode', ['admit', 'capacity', 'recent', 'grace', 'disabled'])
def test_return_consumes_failure_opportunity_even_without_delivery(tmp_path, mode):
    store, reg, transport, clock = failed(tmp_path, channels=('teams',))
    try:
        assert len(rows(store, 'failed_addition')) == 1
        if mode == 'recent':
            clock[0] = -19  # disappear at 101; recent has not expired
        disappear(store, reg, clock)
        if mode == 'capacity':
            store.limits['receipts'] = 1
        if mode == 'grace':
            assert store.reconcile_full(AUTH, {IP: ['example.test']}, clock[0], bindings(reg))['ledger_committed']
            assert store.reconcile_full(AUTH, {}, clock[0], bindings(reg))['ledger_committed']
        if mode == 'disabled':
            reg.apply({}, revision=2)
        clock[0] += 1 if mode == 'recent' else 120
        result = store.record_domain(observation([IP, NEW] if mode == 'capacity' else [IP], now=clock[0]),
                                     AUTH, bindings(reg))
        assert result['ledger_committed']
        assert rows(store, 'failed_addition') == []
        assert len(rows(store, 'receipt')) == (1 if mode == 'admit' else 0)
        if mode == 'capacity':
            assert result['missed_receipts'] == 3
            control = json.loads(rows(store, 'control')[0]['data'])
            assert control['missed_by_reason']['delivery_capacity'] == {'teams': 2, 'misp': 1}
    finally:
        close(store)


@pytest.mark.parametrize('change', ['retire', 'delete_readd', 'projection', 'untracked', 'rebase'])
def test_authority_loss_prunes_proof_without_discarding_admitted_work(tmp_path, change):
    store, reg, transport, clock = failed(tmp_path)
    try:
        assert len(rows(store, 'failed_addition')) == 2
        assert store.record_domain(observation([IP, NEW], now=200), AUTH, bindings(reg))['admitted_receipts'] == 2
        retained = rows(store, 'receipt')
        if change == 'retire':
            assert store.retire_target_cursor(store.cursor_incarnation('example.test'))['ledger_committed']
        elif change == 'delete_readd':
            assert store.refresh_configuration(AUTH, {})['ledger_committed']
            assert store.refresh_configuration(AUTH, projection())['ledger_committed']
        elif change == 'projection':
            assert store.record_domain(observation([IP, NEW], now=300, projection_signature='dns-v2',
                                                   before_ips=[IP, NEW]), AUTH, bindings(reg))['ledger_committed']
        elif change == 'untracked':
            store.limits['target_ips'] = 1
            assert store.record_domain(observation([IP, NEW], now=300), AUTH, bindings(reg))['ledger_committed']
        else:
            store.enter_gap('delivery_storage', {})
            assert store.recover_gap(AUTH, projection([IP, NEW]),
                                     {'active_map': {IP: ['example.test'], NEW: ['example.test']},
                                      'completed_at': 300})['ready']
        assert rows(store, 'failed_addition') == []
        assert rows(store, 'receipt') == retained
    finally:
        close(store)


@pytest.mark.parametrize('positive', [True, False])
def test_gap_target_rebaseline_consumes_only_positive_failure_proof(tmp_path, positive):
    store, reg, transport, clock = failed(tmp_path)
    try:
        if not positive:
            disappear(store, reg, clock)
        proof = rows(store, 'failed_addition')
        store.enter_gap('delivery_storage', {})
        assert store.recover_delivery(clock[0])['ledger_committed']
        clock[0] += 120
        result = store.record_domain(observation([IP] if positive else [], now=clock[0],
                                                 target_complete=True, fresh_positive_ips=[IP] if positive else []),
                                     AUTH, bindings(reg))
        assert result['ledger_committed']
        assert result['admitted_receipts'] == 0
        assert rows(store, 'receipt') == []
        assert rows(store, 'failed_addition') == ([] if positive else proof)
        if not positive:
            assert return_ips(store, reg, clock)['admitted_receipts'] == 2
    finally:
        close(store)


@pytest.mark.parametrize('clean', [True, False])
@pytest.mark.parametrize('positive', [True, False])
def test_restart_preserves_absent_authority_but_never_replays_positive(tmp_path, clean, positive):
    store, reg, transport, clock = failed(tmp_path)
    if not positive:
        disappear(store, reg, clock)
    proof = rows(store, 'failed_addition')
    epoch = json.loads(rows(store, 'control')[0]['data'])['epoch']
    assert store.close(clean=clean)
    store = type(store)(tmp_path, clock=lambda: clock[0])
    try:
        assert store.bootstrap(projection([IP] if positive else []), {}, AUTH)['ready']
        assert rows(store, 'failed_addition') == proof
        clock[0] += 120
        assert store.record_domain(observation([IP] if positive else [], now=clock[0], target_complete=True,
                                               fresh_positive_ips=[IP] if positive else []),
                                   AUTH, bindings(reg))['admitted_receipts'] == 0
        assert rows(store, 'failed_addition') == ([] if positive and not clean else proof)
        assert json.loads(rows(store, 'control')[0]['data'])['epoch'] == epoch
        assert rows(store, 'receipt') == []
        if not positive:
            assert return_ips(store, reg, clock)['admitted_receipts'] == 2
    finally:
        close(store)


@pytest.mark.parametrize('field', ['target', 'projection_signature'])
def test_new_source_context_is_validated_before_admission(tmp_path, field):
    store, reg, transport, clock = make_components(tmp_path)
    try:
        result = store.record_domain(observation([IP], **{field: ''}), AUTH, bindings(reg))
        assert not result['ledger_committed']
        assert rows(store, 'receipt') == []
        assert rows(store, 'failed_addition') == []
    finally:
        close(store)
