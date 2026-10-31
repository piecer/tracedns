"""Read-only reviewer probes; imports frozen candidate, writes owned tmp_path only."""
from copy import deepcopy
import ipaddress
from pathlib import Path
import socket
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from dns_monitor import restore_current_results
from history_manager import load_history_files
from monitor import engine
from monitor.config_service import ConfigService
from monitor.delivery_runtime import DeliveryRuntime
from monitor.repository import MonitorStateRepository
from monitor.stores import ConfigStore
from test_stage3_core_runtime import Clock, rows as rows
from test_delivery_adapters_steps import Transport, Response


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    original_connect = socket.socket.connect
    original_sendto = socket.socket.sendto
    original_resolve = socket.getaddrinfo
    def allowed(address):
        if isinstance(address, tuple):
            assert ipaddress.ip_address(address[0]).is_loopback, 'external network forbidden'
    def connect(sock, address):
        allowed(address)
        return original_connect(sock, address)
    def sendto(sock, data, *args):
        allowed(args[-1])
        return original_sendto(sock, data, *args)
    def resolve(host, *args, **kwargs):
        assert host in ('localhost', '127.0.0.1', '::1'), 'external DNS forbidden'
        return original_resolve(host, *args, **kwargs)
    monkeypatch.setattr(socket.socket, 'connect', connect)
    monkeypatch.setattr(socket.socket, 'sendto', sendto)
    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    monkeypatch.setattr('monitor.collect.query_dns', lambda *a, **k: pytest.fail('ordinary DNS invoked'))


def application(path, domains, *, restart=False):
    path.mkdir(exist_ok=True)
    config = {'domains': deepcopy(domains), 'servers': [], 'config_revision': 0,
              'alerts': {'teams_webhook': 'https://teams.invalid/hook'}}
    history = load_history_files(str(path)) if restart else {}
    current = restore_current_results(history)
    lock = threading.RLock()
    repository = MonitorStateRepository(current, history, str(path), domains, startup=restart)
    config_store = ConfigStore(config, lock, repository)
    service = ConfigService(config, lock, str(path.parent / (path.name + '-config')),
                            state_repository=repository, current_results=current,
                            history=history, history_dir=str(path))
    clock = Clock()
    delivery = DeliveryRuntime(config_store, history_dir=str(path), clock=clock,
                               transport=Transport(*[Response() for _ in range(20)]),
                               ini_path=str(path.parent / 'absent-fixture-ini'))
    service.delivery_runtime = delivery
    return SimpleNamespace(cfg=config_store, service=service, repo=repository,
                           current=current, history=history, delivery=delivery, clock=clock)


def scan(app, obs=None):
    snapshot = app.cfg.snapshot()
    def run():
        result = engine.run_full_cycle(domains_raw=snapshot.domains, servers=snapshot.servers,
            current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
            query_fail_counts={}, state_repository=app.repo, target_leases=snapshot.target_leases)
        accepted, _ = engine.reconcile_scan(app.cfg, snapshot, {}, result, None)
        return accepted, result
    if obs is None:
        return run()
    with patch('dht_query.fetch_dht_records', return_value=obs):
        return run()
