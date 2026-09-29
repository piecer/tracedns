"""Integrated bootstrap uses the same compiler/service as HTTP mutations."""
from contextlib import ExitStack
import threading
from unittest.mock import Mock, patch

import decoder_registry
import dns_monitor
import pytest


@pytest.mark.parametrize('invalid', [False, True])
def test_bootstrap_publishes_one_validated_registry_before_starting_services(tmp_path, invalid):
    previous = decoder_registry.snapshot_registry()
    definitions = [{'name': 'startup_owned', 'steps': [{'op': 'ascii'}]}]
    if invalid:
        definitions.append({'name': 'startup_invalid', 'steps': [{'op': 'not_an_op'}]})
    config = {'domains': [], 'custom_decoders': definitions, 'custom_a_decoders': [],
              'future_setting': {'keep': [1]}, 'config_revision': 7}
    captured = {}

    def handler(*args, **kwargs):
        captured.update(kwargs)
        captured['registry'] = decoder_registry.snapshot_registry()
        return Mock()

    try:
        with ExitStack() as stack:
            stack.enter_context(patch('sys.argv', ['dns_monitor.py', '--config', str(tmp_path / 'cfg')]))
            stack.enter_context(patch('security.startup.open_security', return_value=Mock()))
            stack.enter_context(patch('security.startup.start_housekeeping', return_value=threading.Event()))
            stack.enter_context(patch('dns_monitor.read_config', return_value=config))
            alerts = stack.enter_context(patch('dns_monitor.alerts_init', return_value=False))
            make = stack.enter_context(patch('dns_monitor.make_handler', side_effect=handler))
            stack.enter_context(patch('dns_monitor.ThreadingHTTPServer', return_value=Mock()))
            stack.enter_context(patch('dns_monitor.threading.Thread', return_value=Mock()))
            stack.enter_context(patch('dns_monitor.signal.signal'))
            stack.enter_context(patch('dns_monitor.run_full_cycle', side_effect=RuntimeError('fixture stop')))
            caught = None
            try:
                dns_monitor.main()
            except (SystemExit, RuntimeError) as exc:
                caught = exc
        if invalid:
            assert isinstance(caught, SystemExit) and caught.code == 2
            make.assert_not_called()
            alerts.assert_not_called()
            assert dict(decoder_registry.snapshot_registry().txt) == dict(previous.txt)
            assert dict(decoder_registry.snapshot_registry().a) == dict(previous.a)
        else:
            assert isinstance(caught, RuntimeError)
            service = captured.get('config_service')
            assert service is not None, 'bootstrap must inject its initialized commit service'
            assert service.state_repository is captured['state_repository']
            assert service.snapshot()['future_setting'] == {'keep': [1]}
            assert service.catalog()['revision'] == 7
            assert 'startup_owned' in captured['registry'].txt
    finally:
        decoder_registry.publish(previous)
