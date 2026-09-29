"""Production bootstrap keeps complete config and wires scheduler ownership."""

import threading
from contextlib import ExitStack

from unittest.mock import Mock, patch

import pytest

import dns_monitor
import security.startup  # noqa: F401 - keep the patch target loaded across sys.modules restoration.


def test_bootstrap_preserves_unknown_keys_effective_cli_and_shutdown_audits(tmp_path):
    cfg = {'domains': ['file.test'], 'servers': ['file-dns'], 'interval': 90,
           'max_workers': 2, 'config_revision': 7, 'future_setting': {'keep': [1]},
           '_untrusted_runtime': 'must not load',
           'custom_decoders': [{'name': 'valid_startup', 'steps': [{'op': 'ascii'}], 'note': 'keep'}],
           'custom_a_decoders': [],
           'DEFAULT_SNS_PROXY_HOSTS': []}
    captured = {}
    server = Mock()
    stop = threading.Event()
    audit = Mock()
    pending = {'actor': {'id': 1}, '_security_store': audit, 'job_id': 'pending',
               'request_id': 'request', 'source_ip': 'local', 'domains': []}

    def handler(shared, *args, **kwargs):
        captured['cfg'] = shared
        captured['repo'] = kwargs['state_repository']
        return Mock()

    def fail_cycle(**kwargs):
        captured['cycle'] = kwargs
        captured['cfg']['_force_resolve_queue'] = [pending]
        raise RuntimeError('fixture stop')

    with ExitStack() as stack:
        stack.enter_context(patch('sys.argv', ['dns_monitor.py', '--config', str(tmp_path / 'cfg'),
                                             '--domains=cli.test', '--servers=cli-dns', '--interval=10', '--max-workers=3']))
        stack.enter_context(patch('security.startup.open_security', return_value=Mock()))
        stack.enter_context(patch('security.startup.start_housekeeping', return_value=stop))
        stack.enter_context(patch('dns_monitor.read_config', return_value=cfg))
        stack.enter_context(patch('dns_monitor.alerts_init', return_value=False))
        stack.enter_context(patch('dns_monitor.make_handler', side_effect=handler))
        stack.enter_context(patch('dns_monitor.ThreadingHTTPServer', return_value=server))
        stack.enter_context(patch('dns_monitor.threading.Thread', return_value=Mock()))
        stack.enter_context(patch('dns_monitor.signal.signal'))
        stack.enter_context(patch('dns_monitor.run_full_cycle', side_effect=fail_cycle))
        with pytest.raises(RuntimeError, match='fixture stop'):
            dns_monitor.main()
    shared = captured['cfg']
    assert shared['future_setting'] == {'keep': [1]}
    assert shared['custom_decoders'] == cfg['custom_decoders']

    assert '_untrusted_runtime' not in shared
    assert captured['cycle']['domains_raw'] == [{'name': 'cli.test', 'type': 'A'}]
    assert shared['servers'] == ['cli-dns']
    assert shared['DEFAULT_SNS_PROXY_HOSTS'] == []
    assert shared['interval'] == 10 and shared['max_workers'] == 3
    assert shared['_config_revision'] == shared['config_revision'] == 7
    assert shared['_monitor_stopped']
    assert [c.kwargs['outcome'] for c in audit.audit.call_args_list] == ['failure']
    assert stop.is_set()
    server.server_close.assert_called_once()


@pytest.mark.parametrize('kind', ['ENS', 'SNS'])
def test_restart_baseline_uses_chain_storage_keys_and_active_providers(tmp_path, kind):
    from config_manager import domain_storage_name
    from history_manager import persist_history_entry
    from monitor.scheduler import MonitorScheduler
    import json
    import sqlite3
    domain = {'name': 'x.eth' if kind == 'ENS' else 'x.sol', 'type': kind,
              'ens_text_key': 'record'}
    cfg = {'domains': [domain], 'servers': [], 'ens_rpc_url': 'rpc',
           'DEFAULT_SNS_PROXY_HOSTS': ['sns']}
    path = str(tmp_path / 'cfg')
    history_dir = path + '.history'
    key = domain_storage_name(domain)
    provider = 'rpc' if kind == 'ENS' else 'sns'
    persist_history_entry(history_dir, key, {'events': [], 'current': {
        provider: {'type': kind, 'decoded_ips': ['192.0.2.71']},
        'retired': {'type': kind, 'decoded_ips': ['192.0.2.72']}}})
    original_completed = MonitorScheduler.completed

    def completed(scheduler, snap, *, accepted):
        original_completed(scheduler, snap, accepted=accepted)
        scheduler.stop()

    with ExitStack() as stack:
        stack.enter_context(patch('sys.argv', ['dns_monitor.py', '--config', path]))
        stack.enter_context(patch('security.startup.open_security', return_value=Mock()))
        stack.enter_context(patch('security.startup.start_housekeeping', return_value=threading.Event()))
        stack.enter_context(patch('dns_monitor.read_config', return_value=cfg))
        stack.enter_context(patch('dns_monitor.alerts_init', return_value=False))
        stack.enter_context(patch('dns_monitor.make_handler', return_value=Mock()))
        stack.enter_context(patch('dns_monitor.ThreadingHTTPServer', return_value=Mock()))
        stack.enter_context(patch('dns_monitor.threading.Thread', return_value=Mock()))
        stack.enter_context(patch('dns_monitor.signal.signal'))
        stack.enter_context(patch('dns_monitor.run_full_cycle', return_value={}))
        stack.enter_context(patch.object(MonitorScheduler, 'completed', completed))
        dns_monitor.main()
    # Stage 3 moves production grace authority to SQLite, not a second JSON
    # writer. Preserve the exact chain-key/active-provider baseline assertion.
    with sqlite3.connect(history_dir + '/delivery.sqlite') as ledger:
        pending = dict(ledger.execute('SELECT ip, labels FROM grace'))
    assert set(pending) == {'192.0.2.71'}
    assert json.loads(pending['192.0.2.71']) == [key]
