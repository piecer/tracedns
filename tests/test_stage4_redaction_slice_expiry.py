"""Real inner traversal boundaries: cooperative expiry is not attempt expiry."""
import sys
import weakref
from types import SimpleNamespace

import pytest

import security.derived_redaction as m
from tests.test_stage4_redaction_plan import owners


class BoundaryClock:
    """Advance only at a selected real monotonic call, without retaining frames."""

    def __init__(self):
        self.now = 0
        self.predicate = None
        self.hits = 0
        self.at = 0

    def arm(self, predicate, at):
        self.predicate, self.at = predicate, at

    def __call__(self):
        frame = sys._getframe(1)
        if self.predicate is not None and self.predicate(frame):
            self.predicate = None
            self.hits += 1
            self.now = self.at
        return self.now


@pytest.fixture
def clock(monkeypatch):
    value = BoundaryClock()
    monkeypatch.setattr(m, 'time', SimpleNamespace(monotonic=value))
    return value


def make(cfg):
    lock, model = owners(cfg)
    budget = m.RedactionBudget(deadline=5)
    return m.Builder(cfg, lock, model, budget=budget), lock, model


def clean(builder, lock, model):
    assert not lock._is_owned() and not model._condition._is_owned()
    assert not builder._running and builder.budget._active is None


def retired(builder):
    assert builder.config is builder.lock is builder.model is None
    assert builder.catalog is builder.pending is builder._lease is None
    assert not builder.frames and not builder.found
    counts = builder.budget.counters()
    assert counts['worker_bytes'] == counts['metadata_bytes'] == 0
    assert counts['hold_worker_bytes'] == counts['hold_metadata_bytes'] == 0
    assert not counts['active']


def inner(site, key):
    def selected(frame):
        state = frame.f_locals
        if site == 'enumeration':
            return (frame.f_code is m.Builder.walk_locked.__code__
                    and state.get('path') == ('nested',) and state.get('j') == 0)
        return (frame.f_code is m.Builder.own_key.__code__
                and state.get('key') == key
                and state.get('i') == (1024 if site == 'key_chunk' else 0))
    return selected


def complete(builder):
    assert builder.slice() == 'captured', builder.counters()
    assert builder.seal_slice() == 'done', builder.counters()
    handle = builder.take()
    assert handle is not None
    assert {secret for secret, _ in handle.value.replacements} == {'secret'}
    assert handle.value.visits == builder.budget.visits <= m.VISITS
    assert builder.max_slice_visits <= 512 and builder.quantum == 512
    assert builder.budget.deadline == 5
    assert handle.value.metadata_charge <= m.METADATA
    handle.close()
    retired(builder)


@pytest.mark.parametrize('site', ['enumeration', 'key', 'key_chunk'])
def test_inner_expiry_after_progress_retries_only_uncommitted_edge(clock, site):
    key = 'é' * 2050 if site == 'key_chunk' else 'branch'
    cfg = {'nested': {key: {'api_key': 'secret'}}}
    builder, lock, model = make(cfg)
    baseline = builder.budget.counters()['metadata_bytes']
    clock.arm(inner(site, key), m.SLICE)
    try:
        assert builder.slice() == 'more', builder.counters()
        assert clock.hits == 1
        assert builder.frames == [((), 1, False, True), (('nested',), 0, False, True)]
        # The incomplete nested key has no persistent charge or copy. The
        # catalog's completed root key is still owned and charged exactly once.
        assert builder.budget.counters()['metadata_bytes'] == baseline + 128 + 8 * len('nested')
        assert builder.pending is None and not builder.found
        clean(builder, lock, model)
        complete(builder)
    finally:
        builder.discard()


def test_nested_path_expiry_after_completed_child_resumes(clock):
    cfg = {'nested': {'branch': {'first': None, 'api_key': 'secret'}}}
    builder, lock, model = make(cfg)
    clock.arm(lambda f: f.f_code is m.Builder.walk_locked.__code__
              and f.f_locals.get('child_path') == ('nested', 'branch', 'first'), m.SLICE)
    try:
        assert builder.slice() == 'more'
        before = builder._progress
        charge = builder.budget.counters()['metadata_bytes']
        clock.arm(lambda f: f.f_code is m.Builder.resolve.__code__
                  and f.f_locals['path'] == ('nested', 'branch')
                  and f.f_locals.get('key') == 'branch', clock.now + m.SLICE)
        assert builder.slice() == 'more', builder.counters()
        assert clock.hits == 2 and builder._progress > before
        assert builder.frames[-1] == (('nested', 'branch'), 1, False, True)
        assert builder.budget.counters()['metadata_bytes'] == charge
        clean(builder, lock, model)
        complete(builder)
    finally:
        builder.discard()


@pytest.mark.parametrize('site', ['enumeration', 'key', 'key_chunk'])
def test_repeated_inner_expiry_without_new_progress_is_terminal(clock, site):
    key = 'é' * 2050 if site == 'key_chunk' else 'branch'
    builder, lock, model = make({'nested': {key: {'api_key': 'secret'}}})
    try:
        clock.arm(inner(site, key), m.SLICE)
        assert builder.slice() == 'more'
        progress = builder._progress
        clock.arm(inner(site, key), clock.now + m.SLICE)
        assert builder.slice() == 'deadline'
        assert clock.hits == 2 and builder._progress == progress
        clean(builder, lock, model)
        retired(builder)
    finally:
        builder.discard()


@pytest.mark.parametrize('site', ['enumeration', 'key', 'key_chunk'])
def test_absolute_expiry_inside_progress_stays_terminal(clock, site):
    key = 'é' * 2050 if site == 'key_chunk' else 'branch'
    builder, lock, model = make({'nested': {key: {'api_key': 'secret'}}})
    try:
        clock.arm(inner(site, key), builder.budget.deadline)
        assert builder.slice() == 'deadline'
        assert clock.hits == 1 and builder._progress > 0
        clean(builder, lock, model)
        retired(builder)
    finally:
        builder.discard()


@pytest.mark.parametrize('site', ['root_scan', 'root_copy', 'root_chunk'])
def test_root_admission_remains_atomic(clock, site):
    key = 'é' * 2050 if site == 'root_chunk' else 'api_key'
    builder, lock, model = make({key: 'secret'})
    if site == 'root_scan':
        selected = lambda f: f.f_code is m.Builder.roots.__code__ and 'key' in f.f_locals
    else:
        selected = inner('key_chunk' if site == 'root_chunk' else 'key', key)
    try:
        clock.arm(selected, m.SLICE)
        assert builder.slice() == 'deadline'
        assert clock.hits == 1 and builder._progress == 0
        clean(builder, lock, model)
        retired(builder)
    finally:
        builder.discard()


@pytest.mark.parametrize('action', ['mutation', 'cancel', 'close', 'stop'])
def test_yielded_inner_boundary_keeps_owner_fences(clock, action):
    cfg = {'nested': {'branch': {'api_key': 'secret'}}}
    builder, lock, model = make(cfg)
    try:
        clock.arm(inner('key', 'branch'), m.SLICE)
        assert builder.slice() == 'more'
        clean(builder, lock, model)
        if action == 'mutation':
            with lock:
                cfg['_config_revision'] = 1
            expected = 'mutation'
        elif action == 'cancel':
            builder.discard()
            expected = 'stopped'
        elif action == 'close':
            builder.budget.close()
            expected = 'invalid'
        else:
            with model._condition:
                model._stopped = True
            expected = 'stopped'
        assert builder.slice() == expected
        assert builder.take() is None
        clean(builder, lock, model)
        retired(builder)
    finally:
        builder.discard()


def test_yield_drops_nested_cache_and_partial_key_before_return(clock):
    class Sentinel:
        pass

    value = Sentinel()
    ref = weakref.ref(value)
    cfg = {'nested': {'branch': value}}
    builder, lock, model = make(cfg)
    try:
        clock.arm(inner('key', 'branch'), m.SLICE)
        assert builder.slice() == 'more'
        clean(builder, lock, model)
        # Legal writer holds the lock and changes the authority. Neither the
        # abandoned exception nor a traversal cache may keep this old child.
        with lock:
            cfg['nested'] = {}
            cfg['_config_revision'] = 1
        del value
        assert ref() is None
        assert builder.slice() == 'mutation'
        retired(builder)
    finally:
        builder.discard()


def test_partial_key_rollback_allocation_fault_is_terminal(clock, monkeypatch):
    builder, lock, model = make({'nested': {'é' * 2050: {'api_key': 'secret'}}})
    release = builder._lease.release
    calls = []

    def fail_once(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise MemoryError('single partial-key release allocation')
        return release(**kwargs)

    monkeypatch.setattr(builder._lease, 'release', fail_once)
    try:
        clock.arm(inner('key_chunk', 'é' * 2050), m.SLICE)
        assert builder.slice() == 'invalid'
        assert calls == [{'metadata': 128 + 8 * 2050}]
        assert clock.hits == 1
        clean(builder, lock, model)
        retired(builder)
    finally:
        builder.discard()
