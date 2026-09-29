"""One configured target/provider view excludes retired votes, not evidence."""
from copy import deepcopy
from unittest.mock import patch

from config_manager import domain_storage_name
from monitor.engine import run_full_cycle


def test_full_projection_excludes_retired_dns_ens_sns_providers(tmp_path):
    domains = [{'name': 'dns.test'}, {'name': 'x.eth', 'type': 'ENS'},
               {'name': 'x.sol', 'type': 'SNS'}]
    current = {}
    for d, provider in zip(domains, ['dns-new', 'rpc-new', 'sns-new']):
        key = domain_storage_name(d)
        current[key] = {'retired': {'type': 'A', 'values': ['192.0.2.1']},
                        provider: {'type': 'A', 'values': ['192.0.2.2']}}
    raw = deepcopy(current)
    with patch('monitor.engine.run_domain_cycle', return_value=[]):
        result = run_full_cycle(domains_raw=domains, servers=['dns-new'],
                                ens_rpc_url='rpc-new', sns_proxy_hosts=['sns-new'],
                                current_results=current, history={}, history_dir=str(tmp_path),
                                query_fail_counts={})
    assert result == {'192.0.2.2': set(current)}
    assert current == raw


def test_retired_provider_cannot_suppress_active_provider_additions(tmp_path):
    from tests.test_monitor_state_ownership import _collected
    current = {'a.example': {'retired': {'type': 'A', 'values': ['192.0.2.10']}}}
    history = {'a.example': {'meta': {}, 'events': [], 'current': deepcopy(current['a.example'])}}
    with patch('monitor.engine.collect_snapshot', side_effect=_collected), \
            patch('monitor.engine._dedupe_alert', side_effect=lambda action, entries: entries), \
            patch('monitor.engine.alert_new_ips') as alerts:
        run_full_cycle(domains_raw=['a.example'], servers=['new'], current_results=current,
                       history=history, history_dir=str(tmp_path), query_fail_counts={})
    alerts.assert_called_once()
    assert alerts.call_args.args[0] == [('192.0.2.10', 'a.example', 'A')]
    assert 'retired' in current['a.example']
