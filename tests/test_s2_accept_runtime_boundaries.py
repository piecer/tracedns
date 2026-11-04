"""External, finite deterministic acceptance schedules; no product edits."""
import copy
import json  # noqa: F401 - preserve promoted independent probe AST
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace  # noqa: F401 - preserve independent probe AST

import pytest
import decoder_registry
from config_manager import domain_storage_name
from monitor import collect, engine
from monitor.lookup_runtime import LookupRuntime
from test_stage3_core_runtime import app_factory, rows
from test_lookup_liveness import owned_scan, background_scan, success, wait_for
from test_dht_monitor import observation, target

CANDIDATE = Path(__file__).resolve().parents[1]


class Clock:
    now = 100.0
    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def isolation(monkeypatch):
    for module in (engine, collect, decoder_registry):
        assert Path(module.__file__).resolve().is_relative_to(CANDIDATE)
    original = decoder_registry.snapshot_registry()
    def deny(*args, **kwargs):
        raise AssertionError('external network forbidden')
    monkeypatch.setattr(socket.socket, 'connect', deny)
    monkeypatch.setattr(socket.socket, 'connect_ex', deny)
    monkeypatch.setattr(socket.socket, 'sendto', deny)
    monkeypatch.setattr(socket, 'getaddrinfo', deny)
    yield
    decoder_registry.publish(original)


def app_at(path, *, domains=None, clock=None, servers=None):
    path.mkdir(parents=True, exist_ok=True)
    app = app_factory(path, config={'domains': domains or ['test.example'],
        'servers': servers or ['fixture'], 'max_workers': 2,
        'ens_rpc_url': 'https://ens.invalid', 'DEFAULT_SNS_PROXY_HOSTS': ['sns.invalid'],
        'alerts': {'teams_webhook': 'https://teams.invalid/hook'}})
    app.cfg.raw['_decoder_registry_snapshot'] = decoder_registry.snapshot_registry
    app.lookup = LookupRuntime(app.repo, clock=clock or time.monotonic)
    return app


def cleanup(app, thread=None, *events):
    for event in events:
        event.set()
    if thread is not None:
        thread.join(5)
    assert app.lookup.stop()['stopped'], 'fixture left an owned lookup thread alive'
    assert app.delivery.stop()['closed']
    if thread is not None:
        assert not thread.is_alive()


def native_fixture(monkeypatch, kind, entered, release):
    obs, key = observation(7)
    domain = target(key) if kind == 'DHT' else {'name': 'test.example', 'type': kind}
    if kind == 'DHT':
        domain['dht_options'] = {'duration': 1, 'max_queries': 4}
    calls = []
    def transport(*args, **kwargs):
        calls.append(kind)
        entered.set()
        assert release.wait(12), 'fixture transport rescue'
        return obs if kind == 'DHT' else ({'status': 'ok', 'values': ['192.0.2.22']} if kind == 'A' else 'fixture')
    if kind == 'DHT':
        monkeypatch.setattr('dht_query.fetch_dht_records', transport)
    elif kind == 'A':
        monkeypatch.setattr(collect, 'query_dns', transport)
    else:
        monkeypatch.setattr(collect, 'fetch_ens_text_record' if kind == 'ENS' else 'fetch_sns_record', transport)
        monkeypatch.setattr(collect, 'decode_ens_hidden_ips', lambda *a, **k: ['192.0.2.22'])
        monkeypatch.setattr(collect, 'decode_ens_endpoints', lambda *a, **k: [])
    return domain, calls


@pytest.mark.parametrize('kind,budget', [('A', 5), ('ENS', 30), ('SNS', 20), ('DHT', 6)])
@pytest.mark.parametrize('delta', [-.001, 0, .001], ids=['before', 'exact', 'after'])
def test_original_provider_deadline(tmp_path, monkeypatch, kind, budget, delta):
    clock = Clock()
    entered, release = threading.Event(), threading.Event()
    domain, calls = native_fixture(monkeypatch, kind, entered, release)
    app = app_at(tmp_path, domains=[domain], clock=clock)
    thread, results, errors = background_scan(app)
    name = domain_storage_name(domain)
    try:
        assert entered.wait(2)
        ticket = app.lookup.active_providers[0]
        assert ticket.deadline == 100 + budget
        clock.now = 100 + budget + delta
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert calls == [kind]
        on_time = delta < 0
        assert bool(app.current[name]) == on_time
        assert bool(rows(app, 'receipt')) == on_time
        assert results[0].complete == on_time
        assert bool(results[0].positive) == on_time
        assert rows(app, 'grace') == []
    finally:
        cleanup(app, thread, release)


@pytest.mark.parametrize('delta', [-.001, 0, .001], ids=['before', 'exact', 'after'])
def test_original_target_deadline_includes_queue(tmp_path, monkeypatch, delta):
    clock = Clock()
    entered, release = threading.Event(), threading.Event()
    queued, dispatch = threading.Event(), threading.Event()
    domain, calls = native_fixture(monkeypatch, 'A', entered, release)
    app = app_at(tmp_path, domains=[domain], clock=clock)
    original = engine.run_domain_cycle
    deadlines = []
    def delay_controller(**kwargs):
        if kwargs.get('lookup_runtime') is app.lookup:
            deadlines.append(kwargs['target_deadline'])
            queued.set()
            assert dispatch.wait(12)
        return original(**kwargs)
    monkeypatch.setattr(engine, 'run_domain_cycle', delay_controller)
    thread, results, errors = background_scan(app)
    try:
        assert queued.wait(2) and deadlines == [175]
        clock.now = 174
        dispatch.set()
        assert entered.wait(2)
        assert app.lookup.active_providers[0].deadline == 175
        clock.now = 175 + delta
        release.set()
        thread.join(3)
        assert not thread.is_alive() and not errors
        assert wait_for(lambda: app.lookup.status()['active'] == 0 and app.lookup.status()['controllers'] == 0)
        assert bool(app.current['test.example']) == (delta < 0)
        assert bool(rows(app, 'receipt')) == (delta < 0)
        assert results[0].complete == (delta < 0)
        assert rows(app, 'grace') == [] and calls == ['A']
    finally:
        cleanup(app, thread, release, dispatch)


@pytest.mark.parametrize('jump', [-1000000000, 1000000000])
def test_wallclock_jump_does_not_rebase_lookup_deadline(tmp_path, monkeypatch, jump):
    clock = Clock()
    entered, release = threading.Event(), threading.Event()
    domain, calls = native_fixture(monkeypatch, 'A', entered, release)
    app = app_at(tmp_path, domains=[domain], clock=clock)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        original = app.lookup.active_providers[0].deadline
        monkeypatch.setattr(time, 'time', lambda: 2000000000 + jump)
        clock.now = 104.999
        release.set()
        thread.join(3)
        assert not errors and not thread.is_alive()
        assert original == 105 and results[0].complete
        assert len(rows(app, 'receipt')) == 1 and app.current['test.example']
    finally:
        cleanup(app, thread, release)


@pytest.mark.parametrize('stop', [False, True], ids=['expiry', 'stop'])
def test_blocked_native_decoder_cannot_publish_on_return(tmp_path, monkeypatch, stop):
    clock = Clock()
    app = app_at(tmp_path, domains=[{'name': 'test.example', 'type': 'TXT'}], clock=clock)
    entered, release = threading.Event(), threading.Event()
    calls = []
    monkeypatch.setattr(collect, 'query_dns', lambda *a, **k: {'status': 'ok', 'values': ['fixture']})
    def decode(*a, **k):
        calls.append('decode')
        entered.set()
        assert release.wait(12)
        return ['192.0.2.99']
    monkeypatch.setattr(collect, 'decode_txt_hidden_ips', decode)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        if stop:
            status = app.lookup.stop(join_seconds=0)
            assert not status['stopped']
        else:
            clock.now = 105
        thread.join(2)
        assert not thread.is_alive() and not errors and not results[0].complete
        assert app.lookup.status()['active'] == 1
        assert not app.delivery.stop(producers_stopped=False, join_seconds=0)['closed']
        assert not release.is_set()
        release.set()
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert calls == ['decode'] and not app.current['test.example']
        assert rows(app, 'receipt') == [] and results[0].positive == {}
    finally:
        cleanup(app, thread, release)


def test_live_custom_publication_keeps_original_callable_registry(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    seen = []
    def old(values, **kwargs):
        entered.set()
        assert release.wait(12)
        seen.append(decoder_registry.TXT_METHODS['acceptance_helper'](values))
        return seen[-1]
    view = decoder_registry.snapshot_registry()
    maps = dict(view.txt, acceptance_live=old, acceptance_helper=lambda v: ['192.0.2.1'])
    decoder_registry.publish(decoder_registry.RegistryView(maps, view.a))
    app = app_at(tmp_path, domains=[{'name': 'test.example', 'type': 'TXT', 'txt_decode': 'acceptance_live'}])
    monkeypatch.setattr(collect, 'query_dns', lambda *a, **k: {'status': 'ok', 'values': ['fixture']})
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        decoder_registry.publish(decoder_registry.RegistryView(dict(maps,
            acceptance_live=lambda v, **k: ['192.0.2.2'], acceptance_helper=lambda v: ['192.0.2.2']), view.a))
        release.set()
        thread.join(3)
        assert not errors and results[0].complete
        assert seen == [['192.0.2.1']]
        assert app.current['test.example']['fixture']['decoded_ips'] == ['192.0.2.1']
        assert owned_scan(app).complete
        assert app.current['test.example']['fixture']['decoded_ips'] == ['192.0.2.2']
        assert len(rows(app, 'receipt')) == 2
    finally:
        cleanup(app, thread, release)


@pytest.mark.parametrize('boundary', ['candidate', 'admission', 'history'])
@pytest.mark.parametrize('change', ['delete_readd', 'provider', 'decoder'])
def test_original_lease_at_candidate_admission_history(tmp_path, monkeypatch, boundary, change):
    app = app_at(tmp_path)
    old = app.repo.capture()['test.example']
    entered, release = threading.Event(), threading.Event()
    method = {'candidate': 'observation_candidate', 'admission': 'accept_observation', 'history': 'commit_history'}[boundary]
    original = getattr(app.repo, method)
    fired = []
    def delay(*args, **kwargs):
        if not fired:
            fired.append(True)
            # Candidate is copied before authority is revoked in this schedule.
            value = original(*args, **kwargs) if boundary == 'candidate' else None
            entered.set()
            assert release.wait(12)
            if boundary == 'candidate':
                return value
        return original(*args, **kwargs)
    monkeypatch.setattr(app.repo, method, delay)
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        if change == 'delete_readd':
            app.service.commit('config', {'domains': []}, expected_revision=0)
            app.service.commit('config', {'domains': ['test.example']}, expected_revision=1)
        elif change == 'provider':
            app.service.commit('config', {'servers': ['replacement']}, expected_revision=0)
        else:
            app.service.commit('config', {'domains': [{'name': 'test.example', 'type': 'TXT'}]}, expected_revision=0)
        replacement = app.repo.capture()['test.example']
        assert replacement.target is not old.target and not app.repo.valid(old)
        before = copy.deepcopy(replacement.current)
        counts = {table: rows(app, table) for table in ('receipt', 'cursor', 'recent', 'grace')}
        destination = tmp_path / 'test.example.json'
        destination.write_text('{"replacement_generation":true}\n')
        release.set()
        thread.join(3)
        assert not errors and not thread.is_alive()
        assert replacement.current == before and replacement.target.failures == {}
        assert destination.read_text() == '{"replacement_generation":true}\n'
        assert all(rows(app, table) == value for table, value in counts.items())
        if boundary != 'history':
            assert rows(app, 'receipt') == [] and not results[0].positive
    finally:
        cleanup(app, thread, release)


@pytest.mark.parametrize('completion', [104.999, 105, 105.001], ids=['before', 'exact', 'after'])
def test_original_deadline_at_actual_ledger_begin(tmp_path, monkeypatch, completion):
    clock = Clock()
    app = app_at(tmp_path, clock=clock)
    entered, release = threading.Event(), threading.Event()
    original = app.delivery.store._execute
    calls = []
    def delay(sql, *args, **kwargs):
        if sql == 'BEGIN IMMEDIATE' and not calls:
            calls.append(sql)
            entered.set()
            assert release.wait(12)
        return original(sql, *args, **kwargs)
    monkeypatch.setattr(app.delivery.store, '_execute', delay)
    monkeypatch.setattr(engine, 'collect_snapshot', success)
    before = rows(app, 'cursor')
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        clock.now = completion
        release.set()
        thread.join(3)
        assert not errors and not thread.is_alive() and calls == ['BEGIN IMMEDIATE']
        on_time = completion < 105
        # Do not count a hidden durable late receipt as a successful fence.
        assert bool(rows(app, 'receipt')) == on_time, 'original deadline failed at real ledger BEGIN: late durable receipt'
        assert (rows(app, 'cursor') != before) == on_time, 'late detector cursor transition'
        assert bool(app.current['test.example']) == on_time
        assert results[0].complete == on_time
    finally:
        cleanup(app, thread, release)
