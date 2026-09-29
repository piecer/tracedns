import json

import pytest

from monitor.removal_grace import IP_REMOVAL_GRACE_STATE_FILENAME
from test_stage3_core_runtime import Clock, app_factory, rows, scan


@pytest.mark.parametrize('corrupt', [False, True])
def test_bootstrap_imports_legacy_grace_once_without_rewriting_file(tmp_path, corrupt):
    path = tmp_path / IP_REMOVAL_GRACE_STATE_FILENAME
    raw = 'broken' if corrupt else json.dumps({'version': 1, 'pending': {
        '1.2.3.4': {'missing_since': 100, 'labels': ['test.example']}}})
    path.write_text(raw)
    app = app_factory(tmp_path)
    try:
        if corrupt:
            assert not app.delivery.store.health_snapshot()['accounting_complete']
        else:
            assert rows(app, 'grace')[0]['missing_since'] == 100
        assert path.read_text() == raw
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('clean', [True, False])
def test_full_absence_grace_clean_or_unclean_restart(tmp_path, monkeypatch, clean):
    clock = Clock()
    initial = {'test.example': {'fake': {'values': ['1.2.3.4']}}}
    app = app_factory(tmp_path, current=initial, clock=clock)
    scan(app, monkeypatch, [])
    since = rows(app, 'grace')[0]['missing_since']
    if clean:
        app.delivery.stop()
    else:
        app.delivery.store.close(clean=False)
    clock.now += 86399
    app = app_factory(tmp_path, clock=clock)
    try:
        scan(app, monkeypatch, [])
        if clean:
            assert rows(app, 'receipt') == []
            clock.now += 1
            scan(app, monkeypatch, [])
            assert rows(app, 'receipt')[0]['action'] == 'Removed'
            assert rows(app, 'grace') == []
        else:
            assert rows(app, 'receipt') == []
            assert rows(app, 'grace')[0]['missing_since'] == since
            assert rows(app, 'grace')[0]['not_before'] >= clock.now + 86400
    finally:
        app.delivery.stop()


def test_partial_full_only_cancels_fresh_positive_without_absence(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from models import Snapshot
    from monitor import engine
    cfg = {'domains': [{'name': 'test.example', 'type': 'A'}], 'servers': ['fake', 'failed'],
           'alerts': {}, 'config_revision': 0}
    app = app_factory(tmp_path, config=cfg, current={'test.example': {'fake': {'values': ['1.2.3.4', '2.3.4.5']}}})
    try:
        scan(app, monkeypatch, [])
        baseline = rows(app, 'baseline')
        def collect(domain, server):
            return SimpleNamespace(query=SimpleNamespace(server=server,
                status='ok' if server == 'fake' else 'error', error='fixture'),
                snapshot=Snapshot(type='A', values=['1.2.3.4'], ts=app.clock.now) if server == 'fake' else None)
        monkeypatch.setattr(engine, 'collect_snapshot', collect)
        snap = app.cfg.snapshot()
        result = engine.run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
            current_results=app.current, history=app.history, history_dir=app.repo.history_dir,
            query_fail_counts={}, state_repository=app.repo, target_leases=snap.target_leases)
        assert not result.complete
        accepted, _ = engine.reconcile_scan(app.cfg, snap, {}, result, None)
        assert accepted
        assert {row['ip'] for row in rows(app, 'grace')} == {'2.3.4.5'}
        assert rows(app, 'baseline') == baseline
        assert rows(app, 'receipt') == []
    finally:
        app.delivery.stop()


def test_forced_positive_cancels_only_fresh_evidence_without_absence(tmp_path, monkeypatch):
    app = app_factory(tmp_path, current={'test.example': {'fake': {'values': ['1.2.3.4', '2.3.4.5']}}})
    try:
        scan(app, monkeypatch, [])
        baseline = rows(app, 'baseline')
        force = {'domains': app.cfg.raw['domains'], '_target_leases': app.repo.capture()}
        app.clock.now += 86400
        scan(app, monkeypatch, ['1.2.3.4'], force=force)
        assert {row['ip'] for row in rows(app, 'grace')} == {'2.3.4.5'}
        assert rows(app, 'baseline') == baseline
        assert rows(app, 'receipt') == []
    finally:
        app.delivery.stop()
