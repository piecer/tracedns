"""Permanent regressions promoted from the qualified Stage4 backend probes."""
import json
import math

import pytest

from monitor import engine
from test_delivery_store_atomic import AUTH, BINDINGS, obs, store_at
from test_lookup_liveness import owned_scan
from test_stage3_core_runtime import app_factory, rows


@pytest.mark.parametrize('clock_name',['wall','mono'])
@pytest.mark.parametrize('late',[False,True])
def test_real_source_publication_invalid_sample(tmp_path,monkeypatch,clock_name,late):
    wall,mono=[100.0],[100.0]
    store=store_at(tmp_path,clock=lambda:wall[0]);store._monotonic=lambda:mono[0]
    try:
        store.bootstrap({}, {}, AUTH)
        store.record_domain(obs(['192.0.2.1'],observed_at=0),AUTH,BINDINGS)
        old=store._health_cache
        mono[0]=wall[0]=110
        original=store._one;fired=[]
        def delayed(sql,*args):
            result=original(sql,*args)
            if sql.startswith('SELECT id,created FROM receipt') and not fired:
                fired.append(True)
                if late:(wall if clock_name=='wall' else mono)[0]=math.nan
            return result
        result=None;error=None
        with monkeypatch.context() as patch:
            patch.setattr(store,'_one',delayed)
            try:result=store.record_domain(obs(['192.0.2.1','192.0.2.2'],observed_at=110),AUTH,BINDINGS)
            except Exception as caught:error=type(caught).__name__+': '+str(caught)
        health,count_age,*_=store.progress_health_snapshot()
        # Fresh read-only connection verifies actual committed receipt count.
        import sqlite3
        with sqlite3.connect('file:'+str(store.path)+'?mode=ro',uri=True) as db:
            durable_count=db.execute('SELECT COUNT(*) FROM receipt').fetchone()[0]
        proof={'fired':len(fired),'result':result,'error':error,'health':health,'counts_age':count_age,
               'durable_count':durable_count,'anchors_preserved':store._health_cache[1] is old[1]}
        (tmp_path/('public-clock-'+clock_name+'-'+str(late)+'.json')).write_text(json.dumps(proof,indent=2)+'\n')
        assert fired==[True] and durable_count==2
        assert error is None, 'invalid health sampling must not escape after successful source COMMIT: '+str(error)
        if late:
            assert health['counts_stale'], 'late invalid sampling clock was advertised current'
            assert store._health_cache[1] is old[1]
        else:
            assert result['ledger_committed'] and not health['counts_stale']
            assert health['pending']==2 and count_age==0
    finally:
        wall[0]=mono[0]=120;store.close(clean=False)



@pytest.mark.parametrize('clock_name', ['wall','mono'])
@pytest.mark.parametrize('late', [False,True])
def test_late_invalid_clock_retains_coherent_count_sample(tmp_path,monkeypatch,clock_name,late):
    wall,mono=[100.0],[100.0]
    store=store_at(tmp_path,clock=lambda:wall[0])
    store._monotonic=lambda:mono[0]
    try:
        store.bootstrap({}, {}, AUTH)
        store.record_domain(obs(['192.0.2.1'], observed_at=0),AUTH,BINDINGS)
        old=store._health_cache
        mono[0]=110
        wall[0]=110
        one=store._one
        fired=[]
        def delayed(sql,*args):
            result=one(sql,*args)
            if sql.startswith('SELECT id,created FROM receipt'):
                fired.append(True)
                if late:
                    (wall if clock_name=='wall' else mono)[0]=math.nan
            return result
        with monkeypatch.context() as mp:
            mp.setattr(store,'_one',delayed)
            with store._lock:
                store._safe_refresh()
        snapshot=store.progress_health_snapshot()
        save(tmp_path, 'clock-'+clock_name+'-'+str(late),{'fired':len(fired),'health':snapshot[0], 'counts_age':snapshot[1], 'anchors_preserved':store._health_cache[1] is old[1]})
        assert fired==[True]
        if late:
            assert snapshot[0]['counts_stale'], 'invalid actual sampling clock must not publish current counts'
            assert store._health_cache[1] is old[1], 'retain coherent last good anchors'
        else:
            assert not snapshot[0]['counts_stale']
            assert snapshot[0]['oldest_pending_age_seconds']==110
            assert snapshot[1]==0
    finally:
        wall[0]=mono[0]=120
        store.close(clean=False)


@pytest.mark.parametrize('overflow',[False,True])
def test_recovery_absence_view_matches_actual_readiness_gate(tmp_path,monkeypatch,overflow):
    from monitor.lookup_runtime import LookupRuntime
    from models import Snapshot,QueryResult
    from monitor.collect import Collected
    app=app_factory(tmp_path,limits={'target_ips':1} if overflow else None)
    app.lookup=LookupRuntime(app.repo)
    def collect(domain,server):
        ips=['192.0.2.1','192.0.2.2']
        return Collected(QueryResult(server=server,domain=domain.name,rtype='A',status='ok',values=ips),Snapshot(type='A',values=ips,decoded_ips=[],ts=100000))
    monkeypatch.setattr(engine,'collect_snapshot',collect)
    try:
        snap=app.cfg.snapshot();result=owned_scan(app);assert result.complete
        gates=[]
        original=app.delivery.store.rebaseline_absence
        def observe(*args,**kwargs):
            gate=original(*args,**kwargs);gates.append(gate);return gate
        monkeypatch.setattr(app.delivery.store,'rebaseline_absence',observe)
        assert app.delivery.complete(snap,result)
        assert len(gates)==1
        h=app.delivery.health_snapshot(include_progress=True)
        cursor=rows(app,'cursor')
        gate=gates[0]
        save(tmp_path, 'absence-gate-'+str(overflow),{'health':h,'cursor_tracked':[r['tracked'] for r in cursor],'gate':gate})
        if overflow:
            assert any(not r['tracked'] for r in cursor)
            assert gate['outcome']=='gap'
            assert h['recovery']['absence_state']!='ready', 'actual full-only readiness gate denied despite public ready'
        else:
            assert gate['outcome']=='consumed' and h['recovery']['absence_state']=='ready'
    finally:app.lookup.stop();app.delivery.stop()



@pytest.mark.parametrize('invalid', [False, True])
@pytest.mark.parametrize('boundary', ['diagnostic_sql', 'refresh_sql', 'after_commit', 'worker'])
def test_cache_error_paths_preserve_samples_and_durable_result(tmp_path, monkeypatch, boundary, invalid):
    import sqlite3

    wall, mono = [100.0], [100.0]
    store = store_at(tmp_path, clock=lambda: wall[0])
    store._monotonic = lambda: mono[0]
    fired = []
    try:
        store.bootstrap({}, {}, AUTH)
        store.record_domain(obs(['192.0.2.1'], observed_at=0), AUTH, BINDINGS)
        store._note_storage_error(sqlite3.OperationalError('database is locked'), 'health_refresh')
        old_error = store._storage_error
        old_diagnostics = store._diagnostics
        old_anchors = store._health_cache[1]
        wall[0] = mono[0] = 110.0

        def fault():
            fired.append(True)
            if invalid:
                wall[0] = math.nan

        with monkeypatch.context() as patch:
            if boundary == 'diagnostic_sql':
                real = store._db

                class DelayedDiagnostics:
                    def execute(self, sql, *args):
                        result = real.execute(sql, *args)
                        if 'GROUP BY error' in sql and not fired:
                            fault()
                        return result

                patch.setattr(store, '_db', DelayedDiagnostics())
                store._safe_refresh()
                assert not store.health_snapshot()['counts_stale']
                assert store._health_cache[1][3] == 110
                assert store._diagnostics['observed_at'] == 110
            elif boundary == 'refresh_sql':
                real = store._one

                def failed_sql(sql, *args):
                    result = real(sql, *args)
                    if sql.startswith('SELECT id,created FROM receipt'):
                        fault()
                        raise sqlite3.OperationalError('synthetic refresh failure')
                    return result

                patch.setattr(store, '_one', failed_sql)
                store._safe_refresh()
                assert store.health_snapshot()['counts_stale']
                assert store._health_cache[1] is old_anchors
                assert store._diagnostics is old_diagnostics
            elif boundary == 'after_commit':
                def committed_failure(point):
                    if point == 'after_commit' and not fired:
                        fault()
                        raise sqlite3.OperationalError('synthetic commit reply failure')

                patch.setattr(store, '_fault', committed_failure)
                observation = obs(['192.0.2.1', '192.0.2.2'], observed_at=110)
                result = store.record_domain(observation, AUTH, BINDINGS)
                assert result['ledger_committed']
                assert store.record_domain(observation, AUTH, BINDINGS)['ledger_committed']
                with sqlite3.connect(store.path.as_uri() + '?mode=ro', uri=True) as db:
                    assert db.execute('SELECT COUNT(*) FROM receipt').fetchone()[0] == 2
                if invalid:
                    assert store._health_cache[1] is old_anchors
                    assert store._diagnostics is old_diagnostics
                    assert store.health_snapshot()['counts_stale']
            else:
                fault()
                store.worker_failed(RuntimeError('synthetic worker failure'))
                assert not store.dispatch_available()
                assert store.health_snapshot()['counts_stale']
                assert store._health_cache[1][:5] == old_anchors[:5]
                assert store._diagnostics is old_diagnostics
        assert fired == [True]
        if invalid or boundary == 'diagnostic_sql':
            assert store._storage_error is old_error
        else:
            assert store._storage_error['at'] == 110
    finally:
        wall[0] = mono[0] = 120
        store.close(clean=False)


@pytest.mark.parametrize('capacity', [None, 'target_ips', 'cursor_targets'])
def test_actual_absence_gate_projects_bounded_counts_and_untracked_unknown(tmp_path, monkeypatch, capacity):
    import sqlite3

    from models import QueryResult, Snapshot
    from monitor.collect import Collected
    from monitor.lookup_runtime import LookupRuntime

    app = app_factory(tmp_path, limits={capacity: 1} if capacity else None, config={
        'domains': ['first.example', 'second.example'], 'servers': ['fixture'], 'alerts': {}})
    app.lookup = LookupRuntime(app.repo)

    def collect(domain, server):
        ips = ['192.0.2.1', '192.0.2.2']
        return Collected(QueryResult(server=server, domain=domain.name, rtype='A', status='ok', values=ips),
                         Snapshot(type='A', values=ips, decoded_ips=[], ts=100000))

    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    gates = []
    original = app.delivery.store.rebaseline_absence

    def observe(*args, **kwargs):
        result = original(*args, **kwargs)
        gates.append(result)
        return result

    monkeypatch.setattr(app.delivery.store, 'rebaseline_absence', observe)
    try:
        snapshot = app.cfg.snapshot()
        result = owned_scan(app)
        assert result.complete
        assert app.delivery.complete(snapshot, result)
        assert len(gates) == 1
        health = app.delivery.health_snapshot(include_progress=True)
        with sqlite3.connect(app.delivery.store.path.as_uri() + '?mode=ro', uri=True) as db:
            control = json.loads(db.execute('SELECT data FROM control WHERE id=1').fetchone()[0])
            blocked = db.execute('SELECT COUNT(*) FROM cursor WHERE addition_epoch<>? OR tracked=0',
                                 (control['addition_epoch'],)).fetchone()[0]
        assert health['recovery']['targets_rebaselining'] == blocked
        if capacity == 'cursor_targets':
            assert control['untracked_targets'] and blocked == 0
            assert health['recovery']['absence_state'] == 'unknown'
        elif capacity == 'target_ips':
            assert blocked == 2
            assert health['recovery']['absence_state'] == 'awaiting_full'
        else:
            assert blocked == 0 and health['recovery']['absence_state'] == 'ready'
        assert gates[0]['outcome'] == ('gap' if capacity else 'consumed')
        assert health['tracking_complete'] is (capacity is None)
        assert health['accounting_complete'] is (capacity is None)
    finally:
        app.lookup.stop()
        app.delivery.stop()


def save(directory, name, data):
    (directory / (name + '.json')).write_text(json.dumps(data, indent=2, allow_nan=False, default=str) + '\n')
