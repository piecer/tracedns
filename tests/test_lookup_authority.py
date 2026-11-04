"""Original lease and decoder authority survives neither revocation nor rebasing."""
import threading

import pytest

from monitor import engine
from test_lookup_liveness import owned_app, owned_scan, background_scan, success, wait_for
from test_lookup_force import enqueue
from test_stage3_core_runtime import rows


def test_invalid_standalone_force_fails_before_any_dispatch(tmp_path, monkeypatch):
    app = owned_app(tmp_path, servers=['healthy'])
    job = enqueue(app, ['test.example'])
    app.cfg.dequeue_force()
    app.service.commit('config', {'servers': ['new']}, expected_revision=0)
    called = []
    monkeypatch.setattr(engine, 'collect_snapshot', lambda *a: called.append(a))
    try:
        result = owned_scan(app, force_req=job)
        assert not called and not result.complete
        assert job.get('_terminal_outcome') == 'failure'
        assert wait_for(lambda: job.get('_terminal_audit_done'))
        job['_security_store'].audit.assert_called_once()
    finally:
        app.lookup.stop()
        app.delivery.stop()


@pytest.mark.parametrize('change', ['delete_readd', 'providers', 'decoder'])
def test_revoked_result_cannot_mutate_new_incarnation(tmp_path, monkeypatch, change):
    app = owned_app(tmp_path, servers=['healthy'])
    entered, release = threading.Event(), threading.Event()
    old = app.repo.capture()['test.example']
    def collect(domain, server):
        entered.set()
        assert release.wait(10)
        raise RuntimeError('synthetic old worker')
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    thread, results, errors = background_scan(app)
    try:
        assert entered.wait(2)
        if change == 'delete_readd':
            app.service.commit('config', {'domains': []}, expected_revision=0)
            app.service.commit('config', {'domains': ['test.example']}, expected_revision=1)
        elif change == 'providers':
            app.service.commit('config', {'servers': ['different']}, expected_revision=0)
        else:
            app.service.commit('config', {'domains': [{'name': 'test.example', 'type': 'TXT'}]}, expected_revision=0)
        replacement = app.repo.capture()['test.example']
        assert replacement.target is not old.target
        release.set()
        thread.join(2)
        assert not errors and not results[0].complete
        assert replacement.target.failures == {} and replacement.current == {}
        assert rows(app, 'receipt') == []
        assert not (tmp_path / 'test.example.json').exists()
    finally:
        release.set()
        thread.join(3)
        app.lookup.stop()
        app.delivery.stop()


def test_original_registry_object_is_entered_inside_provider_worker(tmp_path, monkeypatch):
    import decoder_registry
    from contextlib import contextmanager
    from contextvars import ContextVar
    app = owned_app(tmp_path)
    pinned = decoder_registry.snapshot_registry()
    app.cfg.raw['_decoder_registry_snapshot'] = lambda: pinned
    selected = ContextVar('selected', default=None)
    seen = []
    real_use = decoder_registry.use_registry
    @contextmanager
    def use(view):
        token = selected.set(view)
        try:
            with real_use(view):
                yield
        finally:
            selected.reset(token)
    def collect(domain, server):
        seen.append(selected.get())
        return success(domain, server)
    monkeypatch.setattr(decoder_registry, 'use_registry', use)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    try:
        assert owned_scan(app).complete
        assert len(seen) == 2 and all(view is pinned for view in seen)
    finally:
        app.lookup.stop()
        app.delivery.stop()
