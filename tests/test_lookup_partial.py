"""Incomplete coverage cannot manufacture authoritative absence."""
from monitor import engine
from monitor.collect import Collected
from models import QueryResult, Snapshot
from test_lookup_liveness import owned_app, owned_scan
from test_stage3_core_runtime import rows


def test_partial_nxdomain_keeps_last_good_and_never_activates_absence(tmp_path, monkeypatch):
    current = {'test.example': {'slow': {'type': 'A', 'values': ['192.0.2.9'], 'ts': 1}}}
    app = owned_app(tmp_path, current=current)
    called = []
    def collect(domain, server):
        called.append(server)
        status = 'error' if server == 'slow' else 'nxdomain'
        return Collected(QueryResult(server=server, domain=domain.name, rtype='A', status=status, values=[]),
                         None if status == 'error' else Snapshot(type='A', values=[], decoded_ips=[], ts=2))
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    try:
        for _ in range(3):
            result = owned_scan(app)
            assert not result.complete and result.target_complete == {'test.example': False}
            assert app.current['test.example']['slow']['values'] == ['192.0.2.9']
            assert not app.history['test.example']['meta'].get('nxdomain_active')
            assert result.positive == {}
            assert rows(app, 'grace') == []
        assert called.count('slow') == called.count('healthy') == 3
        assert app.repo.capture()['test.example'].target.failures[('test.example', 'slow', 'A')] == 3
        # Genuine complete empty evidence remains distinct from retained-old facts.
        def empty(domain, server):
            return Collected(QueryResult(server=server, domain=domain.name, rtype='A',
                                         status='nxdomain', values=[]),
                             Snapshot(type='A', values=[], decoded_ips=[], ts=3))
        monkeypatch.setattr(engine, 'collect_snapshot', empty)
        result = owned_scan(app)
        assert result.complete and result.target_complete == {'test.example': True}
        assert result == {} and result.positive == {}
        assert app.history['test.example']['meta']['nxdomain_active']
        assert app.history['test.example']['meta']['dns_cycle_total'] == 2
    finally:
        app.lookup.stop()
        app.delivery.stop()


def test_incremental_positive_evidence_contains_all_fresh_providers(tmp_path, monkeypatch):
    from test_lookup_liveness import success
    app = owned_app(tmp_path, current={'test.example': {
        'cached': {'type': 'A', 'values': ['192.0.2.90'], 'ts': 1}}})
    monkeypatch.setattr(engine, 'collect_snapshot', lambda domain, server: success(
        domain, server, '192.0.2.1' if server == 'slow' else '192.0.2.2'))
    try:
        result = owned_scan(app)
        assert set(result.positive) == {'192.0.2.1', '192.0.2.2'}
        assert result.target_complete == {'test.example': True}
    finally:
        app.lookup.stop()
        app.delivery.stop()
