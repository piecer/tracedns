import json
import os
import stat

import pytest

import history_manager
from monitor import engine
from test_stage3_core_runtime import app_factory, rows, scan


@pytest.mark.parametrize('boundary', ['write', 'replace', 'directory'])
def test_history_failure_does_not_revoke_admitted_work(tmp_path, monkeypatch, boundary):
    app = app_factory(tmp_path)
    original_fsync = os.fsync
    try:
        if boundary == 'write':
            monkeypatch.setattr(history_manager.json, 'dump', lambda *a, **k: (_ for _ in ()).throw(OSError('fixture')))
        elif boundary == 'replace':
            monkeypatch.setattr(app.repo, 'commit_history', lambda *a: (_ for _ in ()).throw(OSError('fixture')))
        else:
            def fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError('fixture')
                return original_fsync(fd)
            monkeypatch.setattr(history_manager.os, 'fsync', fsync)
        accepted, result = scan(app, monkeypatch, ['1.2.3.4'])
        assert accepted and set(result) == {'1.2.3.4'}
        assert len(rows(app, 'receipt')) == 1
        assert app.current['test.example']['fake']['values'] == ['1.2.3.4']
        assert app.delivery.store.health_snapshot()['last_error'] == 'history_persistence'
        assert app.delivery.store.health_snapshot()['coverage'] == 'covered'
        assert app.delivery.history_persistence == ('uncertain' if boundary == 'directory' else 'failed')
        if boundary == 'directory':
            assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == ['1.2.3.4']
    finally:
        monkeypatch.undo()
        app.delivery.stop()


def test_reopen_older_history_does_not_replay_durable_intent(tmp_path, monkeypatch):
    app = app_factory(tmp_path)
    monkeypatch.setattr(engine, 'persist_history_entry', lambda *a, **k: False)
    scan(app, monkeypatch, ['1.2.3.4'])
    receipt = rows(app, 'receipt')[0]
    assert not (tmp_path / 'test.example.json').exists()
    app.delivery.stop()
    app = app_factory(tmp_path)
    try:
        app.clock.now += 61
        scan(app, monkeypatch, ['1.2.3.4'])
        assert len(rows(app, 'receipt')) == 1
        assert rows(app, 'receipt')[0]['operation'] == receipt['operation']
    finally:
        app.delivery.stop()
