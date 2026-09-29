"""Crash boundaries execute the real private collector and repository admission."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from test_stage3_core_runtime import app_factory, rows, scan


@pytest.mark.parametrize('boundary', ['before_commit', 'after_commit'])
def test_process_death_at_real_source_commit_has_no_history_first_gap(tmp_path, monkeypatch, boundary):
    script = '''
import os, sys
from pathlib import Path
from pytest import MonkeyPatch
from test_stage3_core_runtime import app_factory, scan
app = app_factory(Path(sys.argv[1]))
def die(at):
    if at == sys.argv[2]:
        os._exit(23)
app.delivery.store._fault = die
scan(app, MonkeyPatch(), ['1.2.3.4'])
raise AssertionError('did not reach source transaction')
'''
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(Path.cwd()), str(Path.cwd() / 'tests')]),
               PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path), boundary], env=env,
                            capture_output=True, timeout=10)
    assert result.returncode == 23, result.stderr.decode()
    assert not (tmp_path / 'test.example.json').exists()
    with sqlite3.connect(tmp_path / 'delivery.sqlite') as db:
        ips = json.loads(db.execute('SELECT ips FROM cursor').fetchone()[0])
        count = db.execute('SELECT COUNT(*) FROM receipt').fetchone()[0]
    assert ips == (['1.2.3.4'] if boundary == 'after_commit' else [])
    assert count == (1 if boundary == 'after_commit' else 0)
    app = app_factory(tmp_path)
    try:
        scan(app, monkeypatch, ['1.2.3.4'])
        assert len(rows(app, 'receipt')) == count
        assert app.current['test.example']['fake']['values'] == ['1.2.3.4']
    finally:
        app.delivery.stop()


def test_absent_domain_crash_does_not_replace_prior_completed_full_baseline(tmp_path, monkeypatch):
    script = '''
import os, sys
from pathlib import Path
from pytest import MonkeyPatch
from monitor import engine
from test_stage3_core_runtime import app_factory, scan
app = app_factory(Path(sys.argv[1]), current={'test.example': {'fake': {'values': ['1.2.3.4']}}})
def die(*args):
    os._exit(24)
engine.reconcile_scan = die
scan(app, MonkeyPatch(), [])
'''
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(Path.cwd()), str(Path.cwd() / 'tests')]),
               PYTHONDONTWRITEBYTECODE='1')
    child = subprocess.run([sys.executable, '-c', script, str(tmp_path)], env=env,
                           capture_output=True, timeout=10)
    assert child.returncode == 24, child.stderr.decode()
    assert json.loads((tmp_path / 'test.example.json').read_text())['current']['fake']['values'] == []
    app = app_factory(tmp_path)
    try:
        assert rows(app, 'baseline')[0]['ip'] == '1.2.3.4'
        assert rows(app, 'grace') == []
        scan(app, monkeypatch, [])
        assert rows(app, 'grace')[0]['missing_since'] == app.clock.now
        assert rows(app, 'receipt') == []
    finally:
        app.delivery.stop()
