"""Reappearance admission through real core/ledger; only DNS is simulated."""
from types import SimpleNamespace

import pytest

from models import Snapshot
from monitor import engine
from test_stage3_core_runtime import app_factory, rows


IP = '192.0.2.9'
PEER_IP = '192.0.2.10'
NEW_IP = '192.0.2.11'
TARGET = 'target.example'
PEER = 'peer.example'


def make_app(tmp_path, **kwargs):
    config = {'domains': [{'name': TARGET, 'type': 'A'}, {'name': PEER, 'type': 'A'}],
              'servers': ['fake'], 'alerts': {'teams_webhook': 'https://teams.invalid/hook'},
              'config_revision': 0}
    return app_factory(tmp_path, config=config, **kwargs)


def scan(app, monkeypatch, ips, *, peer_error=False, force=False):
    def collect(domain, server):
        failed = domain.name == PEER and peer_error
        values = ips if domain.name == TARGET else [PEER_IP]
        return SimpleNamespace(
            query=SimpleNamespace(server=server, status='error' if failed else 'ok', error='fixture'),
            snapshot=None if failed else Snapshot(type='A', values=list(values), ts=int(app.clock())))

    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    snapshot = app.cfg.snapshot()
    if force:
        snapshot.force_req = {'domains': [app.cfg.raw['domains'][0]],
                              '_target_leases': {TARGET: app.repo.capture()[TARGET]}}
    result = engine.run_full_cycle(
        domains_raw=snapshot.domains, servers=snapshot.servers, current_results=app.current,
        history=app.history, history_dir=app.repo.history_dir, query_fail_counts={},
        state_repository=app.repo, target_leases=snapshot.target_leases, force_req=snapshot.force_req)
    accepted, _ = engine.reconcile_scan(app.cfg, snapshot, {}, result, None)
    assert accepted
    return result


def added(app, ip=IP):
    return [row for row in rows(app, 'receipt') if row['action'] == 'Added' and row['ip'] == ip]


@pytest.mark.parametrize('mode', ['partial', 'force'])
def test_reappearance_without_complete_full_scan_is_suppressed(tmp_path, monkeypatch, mode):
    app = make_app(tmp_path)
    try:
        scan(app, monkeypatch, [IP])
        original = added(app)
        baseline = rows(app, 'baseline')
        assert len(original) == 1
        app.clock.now += 120
        scan(app, monkeypatch, [], peer_error=mode == 'partial', force=mode == 'force')
        # Missing data cannot become removal evidence on an incomplete/subset scan.
        assert rows(app, 'grace') == []
        assert rows(app, 'baseline') == baseline
        app.clock.now += 120
        scan(app, monkeypatch, [IP, NEW_IP], peer_error=mode == 'partial')
        assert added(app) == original
        assert len(added(app, NEW_IP)) == 1
        assert not any(row['action'] == 'Removed' for row in rows(app, 'receipt'))
        assert app.delivery.store.health_snapshot()['missed_total'] == 0
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('clean', [True, False])
@pytest.mark.parametrize('mode', ['partial', 'force'])
def test_reappearance_hold_survives_restart(tmp_path, monkeypatch, clean, mode):
    from history_manager import load_history_files
    app = make_app(tmp_path)
    try:
        scan(app, monkeypatch, [IP])
        original = added(app)
        app.clock.now += 120
        scan(app, monkeypatch, [], peer_error=mode == 'partial', force=mode == 'force')
        hold = rows(app, 'reappearance')
        assert len(hold) == 1
        if clean:
            app.delivery.stop()
        else:
            app.delivery.store.close(clean=False)
        history = load_history_files(str(tmp_path))
        current = {name: entry['current'] for name, entry in history.items()}
        app = make_app(tmp_path, current=current, clock=app.clock)
        assert rows(app, 'reappearance') == hold
        app.clock.now += 120
        scan(app, monkeypatch, [IP], peer_error=mode == 'partial')
        assert added(app) == original
        assert rows(app, 'reappearance') == []
        assert app.delivery.store.health_snapshot()['missed_total'] == 0
    finally:
        app.delivery.stop()


@pytest.mark.parametrize('delay,expected', [(86399, 1), (86400, 2), (86401, 2)])
@pytest.mark.parametrize('mode', ['partial', 'force'])
def test_window_expires_from_disappearance_not_first_alert(tmp_path, monkeypatch, delay, expected, mode):
    app = make_app(tmp_path)
    try:
        scan(app, monkeypatch, [IP])
        app.clock.now += 2 * 86400
        scan(app, monkeypatch, [], peer_error=mode == 'partial', force=mode == 'force')
        missing_at = app.clock.now
        original = rows(app, 'reappearance')
        app.clock.now += 3600
        scan(app, monkeypatch, [], peer_error=mode == 'partial', force=mode == 'force')
        assert rows(app, 'reappearance') == original  # no sliding deadline on absence
        app.clock.now = missing_at + delay
        scan(app, monkeypatch, [IP], peer_error=mode == 'partial')
        assert len(added(app)) == expected
        assert rows(app, 'reappearance') == []
        assert not any(row['action'] == 'Removed' for row in rows(app, 'receipt'))
    finally:
        app.delivery.stop()


def test_suppressed_return_starts_fresh_window_on_next_disappearance(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    try:
        scan(app, monkeypatch, [IP])
        app.clock.now += 120
        scan(app, monkeypatch, [], force=True)
        first = rows(app, 'reappearance')[0]['expires']
        app.clock.now = first - 1
        scan(app, monkeypatch, [IP], force=True)
        assert len(added(app)) == 1
        app.clock.now += 120
        scan(app, monkeypatch, [], force=True)
        second = rows(app, 'reappearance')[0]['expires']
        assert second > first
        app.clock.now = second - 1
        scan(app, monkeypatch, [IP], force=True)
        assert len(added(app)) == 1
    finally:
        app.delivery.stop()


def test_complete_full_still_requires_its_own_removal_deadline(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    try:
        scan(app, monkeypatch, [IP])
        app.clock.now += 120
        scan(app, monkeypatch, [], force=True)
        assert rows(app, 'grace') == []
        app.clock.now += 3600
        scan(app, monkeypatch, [])
        since = app.clock.now
        assert rows(app, 'grace')[0]['missing_since'] == since
        app.clock.now = since + 86399
        scan(app, monkeypatch, [])
        assert not any(row['action'] == 'Removed' for row in rows(app, 'receipt'))
        app.clock.now += 1
        scan(app, monkeypatch, [])
        assert len([row for row in rows(app, 'receipt') if row['action'] == 'Removed']) == 1
        scan(app, monkeypatch, [IP])
        assert len(added(app)) == 2
    finally:
        app.delivery.stop()



def test_gap_positive_recovery_resets_only_returned_ips_window(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    try:
        scan(app, monkeypatch, [IP, NEW_IP])
        original = added(app)
        app.clock.now += 200
        scan(app, monkeypatch, [], force=True)
        holds = {row['ip']: row for row in rows(app, 'reappearance')}
        app.delivery.store.enter_gap('delivery_storage', {})
        app.clock.now += 100
        scan(app, monkeypatch, [IP])
        assert app.delivery.store.health_snapshot()['coverage'] == 'covered'
        assert app.delivery.store.health_snapshot()['missed_total'] == 0
        assert added(app) == original
        assert rows(app, 'reappearance') == [holds[NEW_IP]]
        app.clock.now += 100
        scan(app, monkeypatch, [], force=True)
        new_hold = next(row for row in rows(app, 'reappearance') if row['ip'] == IP)
        assert new_hold['expires'] == app.clock.now + 86400
        assert new_hold['expires'] > holds[IP]['expires']
        app.clock.now = holds[IP]['expires'] + 50
        scan(app, monkeypatch, [IP], force=True)
        assert added(app) == original
    finally:
        app.delivery.stop()
