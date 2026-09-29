"""Regression tests for monitor state ownership across HTTP mutations."""
import threading
import json
from unittest.mock import patch
import pytest

from http_server import purge_removed_domains_state
from models import Snapshot
from monitor.state_utils import collect_active_ip_map


def _collected(domain, server):
    from models import QueryResult
    from monitor.collect import Collected
    return Collected(QueryResult(server, domain.name, 'A', 'ok', ['192.0.2.10']),
                     Snapshot(type='A', values=['192.0.2.10'], ts=1))


def test_active_ip_aggregation_uses_a_private_snapshot_during_purge(tmp_path):
    current = {
        name: {'resolver': Snapshot(type='A', values=['192.0.2.10'], ts=1).to_dict()}
        for name in ('a.example', 'b.example')
    }
    history = {name: {'meta': {}, 'events': [], 'current': value} for name, value in current.items()}
    entered, release = threading.Event(), threading.Event()
    original = Snapshot.from_legacy
    result = {}

    def paused(snapshot):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return original(snapshot)

    def aggregate():
        try:
            result['value'] = collect_active_ip_map(current)
        except Exception as exc:
            result['error'] = exc

    with patch('monitor.state_utils.Snapshot.from_legacy', side_effect=paused):
        thread = threading.Thread(target=aggregate, daemon=True)
        thread.start()
        try:
            assert entered.wait(5)
            purge_removed_domains_state(current, history, str(tmp_path), ['b.example'])
        finally:
            release.set()
            thread.join(5)
    assert not thread.is_alive()
    assert 'error' not in result, repr(result.get('error'))
    assert result['value'] == {'192.0.2.10': {'a.example', 'b.example'}}
    assert 'b.example' not in current


def test_full_cycle_does_not_recreate_a_target_deleted_before_its_query(tmp_path):
    from monitor.engine import run_full_cycle
    from history_manager import load_history_files
    current, history, queried = {}, {}, []

    def collect(domain, server):
        queried.append(domain.name)
        if domain.name == 'a.example':
            purge_removed_domains_state(current, history, str(tmp_path), ['b.example'])
        return _collected(domain, server)

    with patch('monitor.engine.collect_snapshot', side_effect=collect), \
            patch('monitor.engine.alert_new_ips') as alerts:
        run_full_cycle(domains_raw=['a.example', 'b.example'], servers=['resolver'],
                       current_results=current, history=history, history_dir=str(tmp_path),
                       query_fail_counts={})
    assert queried == ['a.example']
    assert 'b.example' not in current
    assert 'b.example' not in load_history_files(str(tmp_path))
    assert all(entry[1] != 'b.example' for call in alerts.call_args_list for entry in call.args[0])


def test_history_prepared_before_purge_cannot_replace_the_deleted_file(tmp_path):
    import json
    from history_manager import load_history_files
    from models import DomainSpec
    from monitor.engine import run_domain_cycle
    current, history = {}, {}
    dump = json.dump

    def purge_while_serializing(value, stream, **kwargs):
        purge_removed_domains_state(current, history, str(tmp_path), ['a.example'])
        return dump(value, stream, **kwargs)

    with patch('monitor.engine.collect_snapshot', side_effect=_collected), \
            patch('history_manager.json.dump', side_effect=purge_while_serializing):
        run_domain_cycle(domain=DomainSpec('a.example'), servers=['resolver'],
                         current_results=current, history=history, history_dir=str(tmp_path),
                         query_fail_counts={})
    assert current == {}
    assert load_history_files(str(tmp_path)) == {}
    assert list(tmp_path.iterdir()) == []


def test_configuration_capture_cannot_gain_a_readded_targets_new_lease(tmp_path):
    from http_api.config_post import handle_config_post
    from http_api.context import HttpContext
    from monitor.engine import run_full_cycle
    from monitor.repository import MonitorStateRepository
    from monitor.stores import ConfigStore
    from tests.test_settings_handlers import FakeHandler

    current, history = {}, {}
    shared = {'domains': [{'name': 'a.example', 'type': 'A'}], 'servers': ['resolver']}
    lock = threading.RLock()
    repo = MonitorStateRepository(current, history, str(tmp_path), shared['domains'])
    store = ConfigStore(shared, lock)
    store.state_repository = repo
    captured = store.snapshot()
    ctx = HttpContext('', shared, lock, '', str(tmp_path), current, history,
                      purge_removed_domains_state)
    ctx.state_repository = repo
    for domains in ([], [{'name': 'a.example', 'type': 'A'}]):
        handler = FakeHandler(json.dumps({'domains': domains}).encode())
        handle_config_post(ctx, handler)
        assert handler.status == 200

    with patch('monitor.engine.collect_snapshot', side_effect=_collected) as collect, \
            patch('monitor.engine.alert_new_ips') as alerts:
        run_full_cycle(domains_raw=captured.domains, servers=captured.servers,
                       current_results=current, history=history, history_dir=str(tmp_path),
                       query_fail_counts={}, state_repository=repo,
                       target_leases=getattr(captured, 'target_leases', None))
    collect.assert_not_called()
    alerts.assert_not_called()


@pytest.mark.parametrize('outcome', ['ok', 'error', 'exception'])
def test_late_collection_cannot_mutate_readded_state_or_failure_counts(tmp_path, outcome):
    from models import DomainSpec, QueryResult
    from monitor.collect import Collected
    from monitor.engine import run_domain_cycle
    current, history = {}, {}
    failures = {('a.example', 'resolver', 'A'): 2}
    replacement = Snapshot(type='A', values=['203.0.113.20'], ts=2).to_dict()

    def replace_during_query(domain, server):
        purge_removed_domains_state(current, history, str(tmp_path), ['a.example'])
        current['a.example'] = {'resolver': replacement}
        history['a.example'] = {'meta': {}, 'events': [], 'current': {'resolver': replacement}}
        if outcome == 'exception':
            raise RuntimeError('old worker failed')
        if outcome == 'error':
            return Collected(QueryResult(server, domain.name, 'A', 'error', []), None)
        return _collected(domain, server)

    with patch('monitor.engine.collect_snapshot', side_effect=replace_during_query):
        returned = run_domain_cycle(domain=DomainSpec('a.example'), servers=['resolver'],
                                    current_results=current, history=history, history_dir=str(tmp_path),
                                    query_fail_counts=failures)
    assert current['a.example']['resolver'] == replacement
    assert history['a.example']['current']['resolver'] == replacement
    assert failures == {('a.example', 'resolver', 'A'): 2}
    assert returned == []


def test_revocation_before_notification_admission_does_not_consume_dedupe(tmp_path):
    from monitor.engine import run_full_cycle
    current, history = {}, {}

    def collect(domain, server):
        if domain.name == 'b.example':
            purge_removed_domains_state(current, history, str(tmp_path), ['a.example'])
        return _collected(domain, server)

    with patch('monitor.engine.collect_snapshot', side_effect=collect), \
            patch('monitor.engine._dedupe_alert', side_effect=lambda action, entries: entries) as dedupe, \
            patch('monitor.engine.alert_new_ips') as alerts:
        run_full_cycle(domains_raw=[{'name': 'a.example'}, {'name': 'b.example'}],
                       servers=['resolver'], current_results=current, history=history,
                       history_dir=str(tmp_path), query_fail_counts={})
    assert all(entry[1] != 'a.example' for call in dedupe.call_args_list for entry in call.args[1])
    assert all(entry[1] != 'a.example' for call in alerts.call_args_list for entry in call.args[0])


@pytest.mark.parametrize('definitions', [
    ['a.example,b.example'], ['a.example\nb.example'],
    ['a.example', 'b.example'], [{'name': 'a.example'}, {'name': 'b.example'}],
])
def test_production_capture_normalizes_supported_target_definitions(tmp_path, definitions):
    from config_manager import normalize_domains
    from monitor.engine import run_full_cycle
    from monitor.repository import MonitorStateRepository
    from monitor.stores import ConfigStore
    current, history = {}, {}
    shared = {'domains': definitions, 'servers': ['resolver']}
    repo = MonitorStateRepository(current, history, str(tmp_path), definitions)
    captured = ConfigStore(shared, threading.Lock(), repo).snapshot()
    with patch('monitor.engine.collect_snapshot', side_effect=_collected) as collect, \
            patch('monitor.engine.alert_new_ips'):
        run_full_cycle(domains_raw=normalize_domains(captured.domains), servers=captured.servers,
                       current_results=current, history=history, history_dir=str(tmp_path),
                       query_fail_counts={}, state_repository=repo, target_leases=captured.target_leases)
    assert [call.args[0].name for call in collect.call_args_list] == ['a.example', 'b.example']
    assert captured.target_leases is not None
    assert set(captured.target_leases) == {'a.example', 'b.example'}
