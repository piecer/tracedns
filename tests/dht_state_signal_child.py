"""Disposable subprocess: real main/SignalStopBridge with synthetic DHT only."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import socket
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
import dns_monitor
from config_manager import write_config, domain_storage_name
from history_manager import load_history_files
from test_dht_monitor import cycle, observation, target

scratch = Path(sys.argv[1])
config = scratch / 'owned-config'
history_dir = Path(str(config) + '.history')
first, key = observation(7)
empty, _ = observation(8, ips=())
domain = target(key)
name = domain_storage_name(domain)
current, history = {}, {}
cycle(history_dir, domain, first, current, history, {})
write_config(str(config), {'domains': [domain], 'servers': [], 'interval': 60, 'alerts': {}})
captured, cancellations = {}, []


def attach(shared, lock, *args, **kwargs):
    captured.update(shared=shared, lock=lock)
    return Mock()


def fetch(*args, cancelled=None, **kwargs):
    # main installs real SIGTERM handler before its first run_full_cycle.
    assert captured['shared']['_signal_stop']
    os.kill(os.getpid(), signal.SIGTERM)
    end = time.monotonic() + 3
    while not captured['shared'].get('_monitor_stopped') and time.monotonic() < end:
        time.sleep(.005)
    assert captured['shared']['_monitor_stopped']
    cancellations.append(cancelled())
    return empty


with ExitStack() as stack:
    stack.enter_context(patch('sys.argv', ['dns_monitor.py', '--config', str(config)]))
    stack.enter_context(patch('security.startup.open_security', return_value=Mock()))
    stack.enter_context(patch('security.startup.start_housekeeping', return_value=threading.Event()))
    stack.enter_context(patch('dns_monitor.make_handler', side_effect=attach))
    stack.enter_context(patch('dns_monitor.ThreadingHTTPServer', return_value=Mock()))
    stack.enter_context(patch('dns_monitor.threading', SimpleNamespace(RLock=threading.RLock,
        Thread=lambda *a, **kw: Mock(is_alive=Mock(return_value=False)))))
    stack.enter_context(patch('dht_query.fetch_dht_records', side_effect=fetch))
    stack.enter_context(patch('monitor.collect.query_dns', side_effect=AssertionError('no DNS permitted')))
    stack.enter_context(patch.object(socket.socket, 'connect', side_effect=AssertionError('no network permitted')))
    stack.enter_context(patch.object(socket.socket, 'sendto', side_effect=AssertionError('no network permitted')))
    stack.enter_context(patch('socket.getaddrinfo', side_effect=AssertionError('no DNS permitted')))
    dns_monitor.main()

saved = load_history_files(str(history_dir))[name]
receipt = {'sigterm_callback_completed': captured['shared']['_monitor_stopped'],
           'cancelled_seen': cancellations, 'saved_seq': saved['meta']['dht_state']['highest_seq'],
           'saved_ips': saved['current']['DHT']['decoded_ips']}
print('MAIN_SIGTERM_RECEIPT=' + json.dumps(receipt), flush=True)
assert cancellations == [True] and saved['current']['DHT']['decoded_ips'] == ['192.0.2.123'], receipt
