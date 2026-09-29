"""C05 regression recipes: real producer/repository/store/worker/registry.

Only collection and provider transport are fixtures. No SQL mutations, reservation
changes, limit increases, provider adapters, or worker outcomes are fabricated.
Run with source root and source/tests on PYTHONPATH; -p no:cacheprovider.
C05_EVIDENCE_DIR optionally persists complete observations and source provenance.
"""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
from types import SimpleNamespace

import pytest

from history_manager import load_history_files
from monitor.config_service import ConfigService
from monitor.delivery_runtime import DeliveryRuntime
from monitor.delivery_types import DEFAULT_LIMITS
from monitor.repository import MonitorStateRepository
from monitor.stores import ConfigStore
from test_delivery_review_components import MISP, TEAMS, Transport
from test_stage3_core_runtime import Clock, scan


EXPECTED_DEFAULTS = {
    'receipts': 4096, 'payload_bytes': 8388608,
    'unit_items': 256, 'unit_bytes': 65536, 'label_bytes': 1024,
    'cursor_targets': 4096, 'cursor_members': 16384, 'cursor_bytes': 4194304,
    'target_ips': 4096, 'baseline_items': 8192, 'baseline_bytes': 2097152,
    'grace_items': 8192, 'grace_bytes': 2097152,
    'recent_items': 4096, 'recent_bytes': 1048576,
    'terminal_items': 256, 'terminal_bytes': 131072,
    'batch_items': 60, 'batch_bytes': 24576, 'pages': 16384,
}
DOMAIN = 'test.example'
CONFIG = {'domains': [{'name': DOMAIN, 'type': 'A'}], 'servers': ['fake'],
          'alerts': {**MISP, **TEAMS}, 'config_revision': 0}


def encoded(value):
    # Independent UTF-8 byte oracle, not the production size helper.
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def make_app(path, transport, clock, limits=None):
    # Same production owners as app_factory, but genuine disk hydration on reopen.
    history = load_history_files(str(path))
    current = {name: copy.deepcopy(value['current']) for name, value in history.items()}
    config = copy.deepcopy(CONFIG)
    lock = threading.RLock()
    repo = MonitorStateRepository(current, history, str(path), config['domains'])
    cfg = ConfigStore(config, lock, repo)
    service = ConfigService(config, lock, str(path / 'config'), state_repository=repo,
                            current_results=current, history=history, history_dir=str(path))
    delivery = DeliveryRuntime(cfg, history_dir=str(path), clock=clock,
                               limits=limits, transport=transport)
    service.delivery_runtime = delivery
    return SimpleNamespace(delivery=delivery, repo=repo, cfg=cfg, service=service,
                           current=current, history=history, clock=clock)


def read_rows(app, table):
    assert table in {'receipt', 'batch', 'cursor', 'baseline', 'grace', 'recent'}
    with sqlite3.connect(app.delivery.store.path.as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        return sorted([dict(r) for r in db.execute('SELECT * FROM ' + table)], key=encoded)


def assert_limits(app, count_cap):
    assert DEFAULT_LIMITS == EXPECTED_DEFAULTS
    expected = {**EXPECTED_DEFAULTS, 'receipts': count_cap}
    assert app.delivery.store.limits == expected
    health = app.delivery.store.health_snapshot()
    assert health['capacity']['max_receipts'] == count_cap
    assert health['capacity']['max_payload_bytes'] == 8388608
    assert health['storage_ok'] and health['coverage'] == 'covered'
    assert health['tracking_complete'] and not health['counts_stale']
    assert app.delivery.history_persistence == 'saved'
    return health


def snapshot(app, count_cap, transport):
    health = assert_limits(app, count_cap)
    receipts, batches = read_rows(app, 'receipt'), read_rows(app, 'batch')
    assert health['capacity']['used_receipts'] == len(receipts)
    assert health['capacity']['used_payload_bytes'] == sum(r['reserved'] for r in receipts)
    by_channel = {}
    for channel in ('teams', 'misp'):
        selected = [r for r in receipts if r['channel'] == channel]
        by_channel[channel] = {'count': len(selected), 'reserved': sum(r['reserved'] for r in selected)}
    path = Path(app.repo.history_dir) / (DOMAIN + '.json')
    raw_text = path.read_text() if path.exists() else None
    raw = json.loads(raw_text) if raw_text is not None else None
    return {'defaults': dict(DEFAULT_LIMITS), 'effective_limits': dict(app.delivery.store.limits),
            'health': health, 'receipts': receipts, 'batches': batches,
            'old_work_hash': digest({'receipts': receipts, 'batches': batches}),
            'by_channel': by_channel, 'cursor': read_rows(app, 'cursor'),
            'baseline': read_rows(app, 'baseline'), 'grace': read_rows(app, 'grace'),
            'recent': read_rows(app, 'recent'), 'current': copy.deepcopy(app.current),
            'history': copy.deepcopy(app.history), 'raw_exact': raw,
            'raw_text': raw_text, 'raw_sha256': hashlib.sha256(raw_text.encode()).hexdigest() if raw_text else None,
            'provider_call_count': len(transport.calls)}


def assert_observation(app, ips):
    raw = json.loads((Path(app.repo.history_dir) / (DOMAIN + '.json')).read_text())
    assert raw == app.history[DOMAIN]
    assert raw['current'] == app.current[DOMAIN]
    assert raw['current']['fake']['values'] == ips
    assert raw['current']['fake']['type'] == 'A'
    assert raw['current']['fake']['decoded_ips'] == []
    assert json.loads(read_rows(app, 'cursor')[0]['ips']) == sorted(ips)
    assert read_rows(app, 'cursor')[0]['tracked'] == 1
    assert len(raw['events']) <= 1000
    assert len(ips) <= DEFAULT_LIMITS['target_ips']
    assert len(ips) <= DEFAULT_LIMITS['cursor_members']
    assert read_rows(app, 'grace') == []


def assert_pending(app):
    receipts, batches = read_rows(app, 'receipt'), read_rows(app, 'batch')
    assert receipts and batches
    assert all(r['state'] == 'pending' and r['attempt'] == 0 and r['provider_calls'] == 0
               for r in receipts)
    teams = [r for r in receipts if r['channel'] == 'teams']
    assert all(r['batch_id'] is not None for r in teams)
    assert sum(len(json.loads(b['payload'])['entries']) for b in batches) == len(teams)
    for batch in batches:
        payload = json.loads(batch['payload'])
        assert len(payload['entries']) <= DEFAULT_LIMITS['batch_items']
        assert len(encoded(payload['body'])) <= DEFAULT_LIMITS['batch_bytes']


def candidate_cost(ip):
    # The reservation rule is intentionally checked against all real admitted rows.
    payload_bytes = len(encoded({'entries': [[ip, DOMAIN, 'A']]}))
    return {'misp': payload_bytes + 4096,
            'teams': payload_bytes + 4096 + DEFAULT_LIMITS['batch_bytes']}


def check_costs(receipts):
    for row in receipts:
        assert row['payload'].encode() == encoded({'entries': [[row['ip'], DOMAIN, 'A']]})
        assert row['reserved'] == candidate_cost(row['ip'])[row['channel']]


def provider_records(transport):
    # Fake fixture URLs/keys only; encode wire bytes without inventing responses.
    return [{key: value.decode() if isinstance(value, bytes) else value
             for key, value in call.items()} for call in transport.calls]


def save_result(name_of_result, value):
    output = os.environ.get('C05_EVIDENCE_DIR')
    if output:
        value['source_manifest_sha256'] = os.environ['C05_SOURCE_MANIFEST_SHA256']
        value['recipe_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        source = Path(os.environ['C05_SOURCE_ROOT']).resolve()
        origins = {}
        for name in ('monitor.engine', 'monitor.repository', 'monitor.delivery_runtime',
                     'monitor.delivery_store', 'monitor.delivery_worker', 'monitor.delivery_adapters',
                     'monitor.delivery_types', 'alerts', 'history_manager', 'mispupdate_code',
                     'test_stage3_core_runtime', 'test_delivery_review_components'):
            path = Path(sys.modules[name].__file__).resolve()
            relative = str(path.relative_to(source))
            origins[name] = {'path': str(path), 'relative_path': relative,
                             'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        value['executed_module_origins'] = origins
        (Path(output) / (name_of_result + '.json')).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def finish_and_reopen(app, path, monkeypatch, ips, rejected_ip, before, count_cap, transport, clock, limits):
    """Free only through real metered delivery, then expire dedupe and reopen."""
    result = {}
    old_count = before['health']['capacity']['used_receipts']
    expected_calls = len(before['batches']) + 2 * before['by_channel']['misp']['count']
    passes = []
    # Each MISP addition has GET+validated add; Teams uses a sealed request.
    pass_bound = (3 * old_count + 31) // 32 + 2
    for _ in range(pass_bound):
        if app.delivery.store.health_snapshot()['capacity']['used_receipts'] == 0:
            break
        previous = len(transport.calls)
        outcome = app.delivery.worker.run_pass()
        actual = len(transport.calls) - previous
        assert 0 < actual <= 32
        assert outcome['provider_calls'] == actual and outcome['steps'] <= 256
        passes.append({'result': outcome, 'actual_transport_calls': actual,
                       'remaining': app.delivery.store.health_snapshot()['capacity']})
    else:
        pytest.fail('real worker exceeded bounded drain passes')
    drained = snapshot(app, count_cap, transport)
    assert drained['health']['capacity']['used_receipts'] == 0
    assert drained['health']['capacity']['used_payload_bytes'] == 0
    assert drained['receipts'] == drained['batches'] == []
    assert drained['health']['acked_total'] == old_count
    assert drained['health']['failed_total'] == 0
    assert drained['health']['missed_total'] == 2
    assert len(transport.calls) == expected_calls
    assert {a['value'] for a in transport.attrs} == set(ips) - {rejected_ip}
    assert rejected_ip not in {a['value'] for a in transport.attrs}
    # Wire bytes must be exactly the frozen batch bodies, not a reconstructed oracle.
    team_calls = [call for call in transport.calls if 'teams.invalid' in call['url']]
    assert sorted(call['data'] for call in team_calls) == sorted(
        encoded(json.loads(batch['payload'])['body']) for batch in before['batches'])
    assert all('/sightings/' not in c['url'] for c in transport.calls)
    result.update(drain_pass_bound=pass_bound, drain_passes=passes,
                  expected_provider_calls=expected_calls, drained=drained)
    clock.now += 61
    assert scan(app, monkeypatch, ips)[0]
    assert_observation(app, ips)
    assert app.delivery.worker.run_pass()['provider_calls'] == 0
    repeated = snapshot(app, count_cap, transport)
    assert repeated['health']['missed_total'] == 2
    assert repeated['health']['acked_total'] == old_count
    assert repeated['receipts'] == repeated['batches'] == []
    assert repeated['recent'] == []  # no reliance on 60-second suppression
    assert len(transport.calls) == expected_calls
    result['identical_after_61_seconds'] = repeated
    old_store, old_registry = app.delivery.store, app.delivery.registry
    stopped = app.delivery.stop()
    assert stopped['stopped'] and stopped['closed']
    reopened = make_app(path, transport, clock, limits)
    try:
        assert reopened.delivery.store is not old_store
        assert reopened.delivery.registry is not old_registry
        assert reopened.history[DOMAIN] == repeated['raw_exact']
        result['reopen_before_repeat'] = snapshot(reopened, count_cap, transport)
        assert scan(reopened, monkeypatch, ips)[0]
        assert_observation(reopened, ips)
        assert reopened.delivery.worker.run_pass()['provider_calls'] == 0
        final = snapshot(reopened, count_cap, transport)
        assert final['health']['missed_total'] == 2
        assert final['health']['acked_total'] == old_count
        assert final['health']['failed_total'] == 0
        assert final['receipts'] == final['batches'] == final['recent'] == []
        assert not final['health']['accounting_complete']  # reopened epoch remains lower-bound
        assert len(transport.calls) == expected_calls
        result['reopen_after_repeat'] = final
    finally:
        stopped = reopened.delivery.stop()
        assert stopped['stopped'] and stopped['closed']
    result['provider_calls'] = provider_records(transport)
    return result


def assert_whole_unit_loss(app, ips, before, after, transport, count_cap):
    assert after['receipts'] == before['receipts']
    assert after['batches'] == before['batches']
    assert after['old_work_hash'] == before['old_work_hash']
    assert after['health']['capacity'] == before['health']['capacity']
    assert before['health']['missed_total'] == 0
    assert after['health']['missed_total'] == 2
    assert after['health']['failed_total'] == after['health']['acked_total'] == 0
    assert before['cursor'][0]['operation'] != after['cursor'][0]['operation']
    assert set(json.loads(after['cursor'][0]['ips'])) - set(json.loads(before['cursor'][0]['ips'])) == {ips[-1]}
    assert after['raw_sha256'] != before['raw_sha256']
    assert after['history'][DOMAIN]['events'] != before['history'][DOMAIN]['events']
    assert len(after['history'][DOMAIN]['events']) == len(before['history'][DOMAIN]['events']) + 1
    assert_observation(app, ips)
    assert_pending(app)
    assert len(transport.calls) == 0
    assert_limits(app, count_cap)


def test_C05_exact_defaults_first_binding_capacity(tmp_path, monkeypatch):
    transport, clock = Transport(), Clock()
    app = make_app(tmp_path, transport, clock)  # no limits argument/override
    evidence = {'fixture': 'exact simultaneous defaults, first-binding byte capacity',
                'limits_overrides': None, 'verdict': 'RUNNING'}
    try:
        assert_limits(app, 4096)
        # First unit leaves room for singles; never build a huge cumulative history.
        prefix_count = min(240, DEFAULT_LIMITS['unit_items'])
        max_ips = min(DEFAULT_LIMITS['receipts'] // 2 + 1,
                      DEFAULT_LIMITS['target_ips'], DEFAULT_LIMITS['cursor_members'],
                      DEFAULT_LIMITS['baseline_items'])
        pool = [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.128.1')) + i))
                for i in range(max_ips)]
        ips = pool[:prefix_count]
        assert scan(app, monkeypatch, ips)[0]
        assert_observation(app, ips)
        assert_pending(app)
        assert app.delivery.store.health_snapshot()['missed_total'] == 0
        assert app.delivery.store.health_snapshot()['capacity']['used_receipts'] == 2 * prefix_count
        fill_trace = []
        for index in range(prefix_count, max_ips):
            before = snapshot(app, 4096, transport)
            check_costs(before['receipts'])
            new_ip = pool[index]
            needed = candidate_cost(new_ip)
            ips = pool[:index + 1]
            assert len(set(ips) - set(json.loads(before['cursor'][0]['ips']))) == 1
            assert len(encoded([[new_ip, DOMAIN, 'A']])) <= DEFAULT_LIMITS['unit_bytes']
            assert scan(app, monkeypatch, ips)[0]
            after = snapshot(app, 4096, transport)
            fill_trace.append({'ips': len(ips), 'before_capacity': before['health']['capacity'],
                               'after_capacity': after['health']['capacity'],
                               'missed': after['health']['missed_total'], 'unit_reservation': needed})
            if after['health']['missed_total']:
                break
            assert after['health']['capacity']['used_receipts'] == before['health']['capacity']['used_receipts'] + 2
            assert after['health']['capacity']['used_payload_bytes'] == before['health']['capacity']['used_payload_bytes'] + sum(needed.values())
        else:
            pytest.fail('did not reach first-binding default capacity inside cap-derived bound')
        capacity = before['health']['capacity']
        remaining = DEFAULT_LIMITS['payload_bytes'] - capacity['used_payload_bytes']
        assert capacity['used_receipts'] + 2 <= DEFAULT_LIMITS['receipts']
        assert 0 <= remaining < sum(needed.values())
        # Stronger than original C05: at least MISP alone fits but whole pair cannot.
        assert any(cost <= remaining for cost in needed.values())
        assert_whole_unit_loss(app, ips, before, after, transport, 4096)
        evidence.update(fill_trace=fill_trace, max_ips=max_ips, producer_cycles=len(fill_trace) + 1,
                        actual_filled_receipts=capacity['used_receipts'], first_binding='payload_bytes',
                        unused_payload_bytes=remaining, next_unit_reservation=needed,
                        individually_fitting_channels=[channel for channel, cost in needed.items() if cost <= remaining],
                        before=before, after=after, rejected_ip=new_ip)
        evidence.update(finish_and_reopen(app, tmp_path, monkeypatch, ips, new_ip,
                                         before, 4096, transport, clock, None))
        evidence['verdict'] = 'PASS'
    finally:
        if not app.delivery.stopping:
            app.delivery.stop()
        save_result('default-capacity', evidence)


def test_C05_smaller_count_cap_isolates_count_dimension(tmp_path, monkeypatch):
    transport, clock = Transport(), Clock()
    limits = {'receipts': 3}
    app = make_app(tmp_path, transport, clock, limits)
    evidence = {'fixture': 'contract:69 smaller receipt cap only, all other defaults unchanged',
                'limits_overrides': limits, 'verdict': 'RUNNING'}
    try:
        assert_limits(app, 3)
        ips = ['198.18.128.1']
        assert scan(app, monkeypatch, ips)[0]
        assert_observation(app, ips)
        before = snapshot(app, 3, transport)
        check_costs(before['receipts'])
        assert before['health']['capacity']['used_receipts'] == 2
        ips.append('198.18.128.2')
        needed = candidate_cost(ips[-1])
        assert before['health']['capacity']['used_payload_bytes'] + sum(needed.values()) <= 8388608
        assert before['health']['capacity']['used_receipts'] + 1 <= 3
        assert before['health']['capacity']['used_receipts'] + 2 > 3
        assert scan(app, monkeypatch, ips)[0]
        after = snapshot(app, 3, transport)
        assert_whole_unit_loss(app, ips, before, after, transport, 3)
        evidence.update(before=before, after=after, first_binding='receipts',
                        actual_filled_receipts=2, next_unit_reservation=needed, rejected_ip=ips[-1])
        evidence.update(finish_and_reopen(app, tmp_path, monkeypatch, ips, ips[-1],
                                         before, 3, transport, clock, limits))
        evidence['verdict'] = 'PASS'
    finally:
        if not app.delivery.stopping:
            app.delivery.stop()
        save_result('count-capacity', evidence)
