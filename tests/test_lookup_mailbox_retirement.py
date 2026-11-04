"""Both ready mailboxes must retire after a real reduction exception."""
import json
import threading

import pytest

from monitor import engine
from test_lookup_liveness import owned_app, background_scan, owned_scan, success, wait_for


@pytest.mark.parametrize('admission_error', [False, True], ids=['on_time_control', 'publication_exception'])
def test_ready_batch_retires_after_publication_exception(tmp_path, monkeypatch, admission_error):
    app = owned_app(tmp_path, servers=['one','two'])
    paused, resume = threading.Event(), threading.Event()
    condition = app.lookup.condition
    wait = condition.wait
    suspended = []
    attempts = []
    record = app.repo.accept_observation
    actual_collect = app.lookup.collect
    consumer = None

    def active_collect(*args, **kwargs):
        nonlocal consumer
        consumer = threading.current_thread()
        try:
            yield from actual_collect(*args, **kwargs)
        finally:
            consumer = None

    def collect(domain, server):
        assert paused.wait(2)
        return success(domain, server)

    def pause_consumer(timeout=None):
        if threading.current_thread() is consumer and not suspended:
            suspended.append(True)
            condition.release()
            try:
                paused.set()
                assert resume.wait(10)
            finally:
                condition.acquire()
            return True
        return wait(timeout)

    def admit(*args, **kwargs):
        attempts.append(True)
        if admission_error and len(attempts)==1:
            raise RuntimeError('synthetic publication failure')
        return record(*args, **kwargs)

    monkeypatch.setattr(condition, 'wait', pause_consumer)
    monkeypatch.setattr(app.lookup, 'collect', active_collect)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    monkeypatch.setattr(app.repo, 'accept_observation', admit)
    thread, results, errors = background_scan(app)
    try:
        assert paused.wait(2)
        assert wait_for(lambda: len(app.lookup.active_providers)==2 and all(w.done for w in app.lookup.active_providers))
        resume.set()
        thread.join(3)
        assert not thread.is_alive() and not errors and attempts
        if not admission_error:
            assert results[0].complete
        else:
            assert not results[0].complete
        # No callback is blocked, but a leaked second ready mailbox can retain
        # physical capacity and permanently suppress future fresh attempts.
        retired = wait_for(lambda: app.lookup.status()['active']==0, seconds=.3)
        status = app.lookup.status()
        following = owned_scan(app)
        observation={'retired':retired,'status':status,'next_complete':following.complete,
                     'remaining': [{'server':w.server,'done':w.done,'consumed':w.consumed} for w in app.lookup.active_providers],
                     'first_complete':results[0].complete,'provider_threads':len(app.lookup.providers)}
        (tmp_path/'ready-batch-observation.json').write_text(json.dumps(observation,indent=2))
        assert retired, 'unconsumed ready mailbox retained after controller exception'
        assert following.complete, 'returned provider cannot run again without stopping the owner'
    finally:
        resume.set()
        thread.join(3)
        assert app.lookup.stop()['stopped']
        app.delivery.stop()


@pytest.mark.parametrize('outcome', ['success', 'collector_error', 'timeout'])
@pytest.mark.parametrize('consumer_exit', ['close', 'throw'])
def test_ready_batch_cleanup_owns_unvisited_mailboxes(tmp_path, monkeypatch, outcome, consumer_exit):
    from models import coerce_domains
    from test_lookup_liveness import MonotonicClock

    clock = MonotonicClock()
    app = owned_app(tmp_path, servers=['one', 'two'], clock=clock)
    paused, resume, release = threading.Event(), threading.Event(), threading.Event()
    condition = app.lookup.condition
    original_wait = condition.wait
    suspended, calls, yielded, errors = [], [], [], []
    healthy = False

    def pause_consumer(timeout=None):
        if threading.current_thread().name == 'mailbox-consumer' and not suspended:
            suspended.append(True)
            condition.release()
            try:
                paused.set()
                assert resume.wait(10)
            finally:
                condition.acquire()
            return True
        return original_wait(timeout)

    def collect(domain, server):
        calls.append(server)
        if not healthy:
            if outcome == 'timeout':
                assert release.wait(10)
            elif outcome == 'collector_error':
                raise RuntimeError('synthetic collector failure')
        return success(domain, server)

    monkeypatch.setattr(condition, 'wait', pause_consumer)
    monkeypatch.setattr(engine, 'collect_snapshot', collect)
    app.lookup.start(2)
    workers = tuple(app.lookup.providers)
    snap = app.cfg.snapshot()
    generator = app.lookup.collect(coerce_domains(snap.domains)[0], snap.servers,
                                   snap.registry_view, snap.target_leases['test.example'], 75)

    def take_first():
        try:
            yielded.append(next(generator))
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=take_first, name='mailbox-consumer')
    thread.start()
    try:
        assert paused.wait(2)
        assert wait_for(lambda: len(calls) == 2)
        if outcome == 'timeout':
            assert not any(work.done for work in app.lookup.active_providers)
            clock.now = 5
        else:
            assert wait_for(lambda: len(app.lookup.active_providers) == 2
                            and all(work.done for work in app.lookup.active_providers))
        tickets = tuple(app.lookup.active_providers)
        resume.set()
        thread.join(2)
        assert not thread.is_alive() and not errors and len(yielded) == 1
        error = yielded[0][2]
        if outcome == 'success':
            assert error is None
        else:
            assert isinstance(error, TimeoutError if outcome == 'timeout' else RuntimeError)
        if consumer_exit == 'close':
            generator.close()
        else:
            failure = RuntimeError('synthetic consumer failure')
            with pytest.raises(RuntimeError) as raised:
                generator.throw(failure)
            assert raised.value is failure
        assert all(work.consumed for work in tickets), 'ready remainder lost on generator exit'
        if outcome == 'timeout':
            assert app.lookup.status()['active'] == 2
            assert len(app.lookup.singleflight) == 2
            assert all(not work.done for work in tickets)
            assert tuple(app.lookup.providers) == workers and not release.is_set()
        healthy = True
        release.set()
        assert wait_for(lambda: app.lookup.status()['active'] == 0)
        assert not app.lookup.singleflight and not app.lookup.provider_queue
        assert owned_scan(app).complete
        assert tuple(app.lookup.providers) == workers and len(calls) == 4
    finally:
        resume.set()
        release.set()
        thread.join(3)
        generator.close()
        assert app.lookup.stop()['stopped']
        app.delivery.stop()
