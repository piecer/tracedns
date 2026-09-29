"""Main startup/cleanup uses real core/store; only services/transports are fake."""
from unittest.mock import Mock
import threading

import pytest

import dns_monitor
from monitor import delivery_runtime
from test_delivery_adapters_steps import Response, Transport


@pytest.mark.parametrize('failure', [None, 'local', 'handler', 'bind', 'signal'])
def test_main_owns_delivery_startup_health_and_cleanup(tmp_path, monkeypatch, failure):
    captured = {}
    monkeypatch.setattr('sys.argv', ['dns_monitor.py', '--config', str(tmp_path / 'cfg')])
    monkeypatch.setattr('security.startup.open_security', lambda args: Mock())
    monkeypatch.setattr('security.startup.start_housekeeping', lambda store: threading.Event())
    monkeypatch.setattr(dns_monitor, 'read_config', lambda path: {
        'domains': [], 'servers': [], 'alerts': {}, 'config_revision': 4})
    monkeypatch.setattr(dns_monitor, 'alerts_init', lambda *a, **k: pytest.fail('legacy INI fallback'))
    monkeypatch.setattr(dns_monitor, 'alerts_init_from_dict', lambda *a, **k: pytest.fail('legacy client bootstrap'))
    real_runtime = delivery_runtime.DeliveryRuntime
    def runtime(*args, **kwargs):
        value = real_runtime(*args, **kwargs, transport=Transport(Response()))
        captured['runtime'] = value
        if failure == 'local':
            value.apply_local_settings = lambda *a: (_ for _ in ()).throw(RuntimeError('fixture local'))
        return value
    monkeypatch.setattr(delivery_runtime, 'DeliveryRuntime', runtime)
    def handler(*args, **kwargs):
        captured.update(kwargs)
        if failure == 'handler':
            raise RuntimeError('fixture handler')
        return Mock()
    monkeypatch.setattr(dns_monitor, 'make_handler', handler)
    server = Mock()
    def http(*args):
        if failure == 'bind':
            raise RuntimeError('fixture bind')
        return server
    monkeypatch.setattr(dns_monitor, 'ThreadingHTTPServer', http)
    real_start = dns_monitor.SignalStopBridge.start
    def signal_start(self, signals):
        if failure == 'signal':
            raise RuntimeError('fixture signal')
        return real_start(self, signals)
    monkeypatch.setattr(dns_monitor.SignalStopBridge, 'start', signal_start)
    real_run = dns_monitor.run_full_cycle
    def run(**kwargs):
        result = real_run(**kwargs)
        captured['runtime'].config.raw['_monitor_stopped'] = True
        return result
    monkeypatch.setattr(dns_monitor, 'run_full_cycle', run)
    if failure:
        with pytest.raises(RuntimeError, match='fixture'):
            dns_monitor.main()
    else:
        dns_monitor.main()
    assert 'runtime' in captured, 'actual startup must create per-app delivery owner'
    owner = captured['runtime']
    if failure != 'local':
        assert captured['delivery_health'].__self__ is owner.store
        assert captured['config_service'].delivery_runtime is owner
    assert owner.stopping
    assert owner.store._closed
    assert owner.worker._thread is None or not owner.worker._thread.is_alive()
