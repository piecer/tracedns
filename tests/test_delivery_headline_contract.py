"""Loss-aware headlines through the shipped delivery renderer."""
import json
from pathlib import Path
import subprocess

import pytest

from test_delivery_frontend_fixture import delivery_fixture

ROOT = Path(__file__).resolve().parents[1]


def test_capacity_loss_headline_names_backend_status_and_durable_loss(tmp_path):
    store = delivery_fixture(tmp_path / 'health', 'overflow')
    assert store is not None
    try:
        health = store.health_snapshot()
    finally:
        store.close(clean=True)
    assert health['status'] == 'ok'
    assert health['missed_total'] > 0
    result = subprocess.run(['node', 'tests/test_delivery_headline_contract.js'], cwd=ROOT,
        input=json.dumps({'sequence': [health], 'contains': [
            'Backend delivery status: ok',
            f"{health['missed_total']} not admitted (durable)",
            'Worker: not running',
        ], 'excludes': ['Delivery ok.', 'sent successfully']}),
        text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('scenario', ['incomplete_recovery', 'failed', 'unsafe', 'healthy', 'stale'])
def test_headline_retains_loss_uncertainty_and_separate_backend_state(tmp_path, scenario):
    store = delivery_fixture(tmp_path / 'health', 'acked')
    assert store is not None
    try:
        health = store.health_snapshot()
    finally:
        store.close(clean=True)
    health['worker_running'] = True
    sequence = [health]
    contains = ['Backend delivery status: ok', 'Worker: running']
    excludes = ['Delivery ok.', 'sent successfully']
    if scenario == 'incomplete_recovery':
        health['missed_total'] = 3
        health['missed_unpersisted'] = 2
        health['accounting_complete'] = False
        sequence = [health, {**health, 'missed_unpersisted': 0, 'accounting_complete': True}]
        contains += ['3 not admitted (durable)', '0 volatile known misses', 'lower bound', 'total loss unknown']
        excludes += ['Accounting complete']
    elif scenario == 'failed':
        health['failed_total'] = 1
        contains += ['1 failed', '0 not admitted (durable)']
    elif scenario == 'unsafe':
        health['missed_total'] = 2**53 + 1
        contains += ['precision unavailable', 'lower bound', 'total loss unknown']
        excludes += ['9007199254740992', '9007199254740993']
    elif scenario == 'healthy':
        contains += ['0 not admitted (durable)', '0 failed', 'Accounting complete for this epoch']
        excludes += ['lower bound', 'total loss unknown']
    else:
        health['counts_stale'] = True
        contains += ['Counts stale']
    result = subprocess.run(['node', 'tests/test_delivery_headline_contract.js'], cwd=ROOT,
        input=json.dumps({'sequence': sequence, 'contains': contains, 'excludes': excludes}),
        text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
