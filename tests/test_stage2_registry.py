"""Captured decoder view crosses thread boundaries without held owner locks."""
import sys
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from types import SimpleNamespace
from unittest.mock import patch

from monitor.stores import ConfigStore
from monitor.engine import run_full_cycle
from tests.test_stage2_force import context, admit
from tests.test_monitor_state_ownership import _collected


def test_pinned_registry_captured_under_config_lock_used_in_each_query_worker(tmp_path):
    ctx = context(tmp_path, domains=[{'name': 'a.example', 'type': 'A'}], servers=['one', 'two'])
    ctx.config_lock = threading.Lock()
    current_view = ContextVar('registry', default=None)
    view = object()
    entered = []

    def snapshot_registry():
        assert ctx.config_lock.locked()
        return view

    @contextmanager
    def use_registry(captured):
        assert not ctx.config_lock.locked()
        token = current_view.set(captured)
        try:
            yield
        finally:
            current_view.reset(token)

    def collect(domain, server):
        entered.append(current_view.get())
        return _collected(domain, server)

    registry = SimpleNamespace(snapshot_registry=snapshot_registry, use_registry=use_registry)
    with patch.dict(sys.modules, decoder_registry=registry):
        store = ConfigStore(ctx.shared_config, ctx.config_lock, ctx.state_repository,
                            registry_snapshot=snapshot_registry)
        snap = store.snapshot()
        admit(ctx, {'domain': 'a.example'})
        job = store.dequeue_force()
        assert job['_registry_view'] is view
        with patch('monitor.engine.collect_snapshot', side_effect=collect):
            run_full_cycle(domains_raw=snap.domains, servers=snap.servers,
                           current_results=ctx.state_repository.current,
                           history=ctx.state_repository.history, history_dir=str(tmp_path),
                           query_fail_counts={}, state_repository=ctx.state_repository,
                           target_leases=snap.target_leases, registry_view=snap.registry_view)
    assert entered == [view, view]
