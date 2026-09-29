from copy import deepcopy
from types import SimpleNamespace

import pytest

from config_manager import domain_storage_name
from models import Snapshot
from monitor import engine
from monitor.repository import MonitorStateRepository
from test_stage3_core_runtime import app_factory


@pytest.mark.parametrize('kind', ['A', 'TXT', 'ENS', 'SNS'])
def test_private_domain_publication_preserves_raw_history_and_lifecycle(kind, tmp_path, monkeypatch):
    domain = {'name': 'x.eth' if kind == 'ENS' else 'x.sol' if kind == 'SNS' else 'test.example',
              'type': kind}
    if kind == 'ENS':
        domain['ens_text_key'] = 'record'
    config = {'domains': [domain], 'servers': ['fake'], 'ens_rpc_url': 'rpc',
              'DEFAULT_SNS_PROXY_HOSTS': ['sns'], 'alerts': {}, 'config_revision': 0}
    app = app_factory(tmp_path / 'production', config=config)
    legacy_current, legacy_history = {}, {}
    legacy = MonitorStateRepository(legacy_current, legacy_history, str(tmp_path / 'legacy'), [domain])
    legacy.configure(config)
    name = domain_storage_name(domain)
    provider = 'rpc' if kind == 'ENS' else 'sns' if kind == 'SNS' else 'fake'
    monkeypatch.setattr(engine.time, 'time', app.clock)
    try:
        for status, ips in [('ok', ['1.2.3.4']), ('ok', ['2.3.4.5']), ('error', []),
                            ('error', []), ('error', []), ('nxdomain', []), ('ok', ['3.4.5.6'])]:
            def collect(spec, server):
                return SimpleNamespace(query=SimpleNamespace(server=server, status=status, error='fixture'),
                    snapshot=None if status == 'error' else Snapshot(type=kind,
                        values=ips if kind == 'A' else ['raw-evidence'] if ips else [],
                        decoded_ips=ips if kind != 'A' else [], ts=app.clock.now,
                        decoded_endpoints=[ip + ':443' for ip in ips] if kind != 'A' else []))
            monkeypatch.setattr(engine, 'collect_snapshot', collect)
            for repo in (legacy, app.repo):
                lease = repo.capture()[name]
                engine.run_domain_cycle(domain=lease.target.definition, servers=[provider],
                    active_servers=[provider], current_results=repo.current, history=repo.history,
                    history_dir=repo.history_dir, query_fail_counts={}, state_repository=repo, target_lease=lease)
            assert deepcopy(app.current) == deepcopy(legacy_current)
            assert deepcopy(app.history) == deepcopy(legacy_history)
            app.clock.now += 1
    finally:
        app.delivery.stop()
