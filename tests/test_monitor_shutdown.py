"""Owned runtime resources close on startup and monitor exceptions."""
from contextlib import ExitStack
import signal
import threading
from unittest.mock import MagicMock, patch

import pytest
import dns_monitor


@pytest.mark.parametrize('failure', ['cycle', 'bind'])
def test_main_stops_owned_resources_on_failure(tmp_path, failure):
    server = MagicMock()
    stop = threading.Event()
    with ExitStack() as stack:
        stack.enter_context(patch('sys.argv', ['dns_monitor.py', '--config', str(tmp_path / 'config.json')]))
        stack.enter_context(patch('security.startup.open_security', return_value=MagicMock()))
        start_housekeeping = stack.enter_context(patch('security.startup.start_housekeeping', return_value=stop))
        stack.enter_context(patch('dns_monitor.read_config', return_value={'domains': []}))
        stack.enter_context(patch('dns_monitor.alerts_init', return_value=False))
        stack.enter_context(patch('dns_monitor.make_handler', return_value=MagicMock()))
        constructor = stack.enter_context(patch('dns_monitor.ThreadingHTTPServer', return_value=server))
        stack.enter_context(patch('dns_monitor.threading.Thread', return_value=MagicMock()))
        signals = stack.enter_context(patch('dns_monitor.signal.signal'))
        stack.enter_context(patch('dns_monitor.run_full_cycle', side_effect=RuntimeError('cycle failed')))
        if failure == 'bind':
            constructor.side_effect = RuntimeError('bind failed')
        with pytest.raises(RuntimeError, match=failure + ' failed'):
            dns_monitor.main()
    assert not start_housekeeping.called or stop.is_set()
    if failure == 'cycle':
        server.shutdown.assert_called_once()
        server.server_close.assert_called_once()
        assert signal.SIGTERM in [call.args[0] for call in signals.call_args_list]
