"""Production ceilings and late-deadline controls, not lifecycle proof worlds."""
import threading

import pytest

from http_api.read_capture import Capture, CaptureBudget, CaptureOwners, RootCursor
from tests.test_stage4_read_capture import source, drain
from tests.test_stage4_capture_limits import finish


@pytest.mark.parametrize('count,expected', [(16384, 'done'), (16385, 'capacity')])
def test_production_descriptor_ceiling_exact_and_plus_one(count, expected):
    owners = CaptureOwners(*source())
    owners.current.clear()
    owners.current.update((str(i), None) for i in range(count))
    budget = CaptureBudget()
    cursor = RootCursor(owners, 'current', budget=budget)
    observed = 0
    while cursor.next_key() is not None:
        observed += 1
    assert cursor.status == expected
    assert observed == budget.descriptors == 16384
    assert budget.visits <= 262144
    assert cursor._iterator is None and budget.workspace == 0


@pytest.mark.parametrize('kind,ceiling', [('prepared', 64 * 1024 * 1024), ('search', 32 * 1024 * 1024)])
def test_production_examination_ceiling_exact_and_plus_one(kind, ceiling):
    unit_bytes = 1024 * 1024 - 16384
    full, remainder = divmod(ceiling, unit_bytes)
    owners = CaptureOwners(*source())
    owners.current.clear()
    owners.current.update(big='x' * (unit_bytes - 2), tail='x' * (remainder - 2), one=0)
    budget = CaptureBudget(kind=kind)
    for _ in range(full):
        blob = drain(Capture(owners, 'current', ('big',), budget=budget, unit_bytes=unit_bytes))
        assert len(blob) == unit_bytes
        del blob
    assert len(drain(Capture(owners, 'current', ('tail',), budget=budget, unit_bytes=unit_bytes))) == remainder
    assert budget.examined_bytes == ceiling
    cap = Capture(owners, 'current', ('one',), budget=budget)
    assert finish(cap) == 'capacity'
    assert budget.examined_bytes == ceiling and budget.visits <= 262144
    assert budget.workspace == 0


def test_production_attempt_visits_shared_across_released_units():
    owners = CaptureOwners(*source())
    owners.current['a.test'] = 0
    budget = CaptureBudget()
    units = 0
    while budget.visits < 262144:
        cap = Capture(owners, 'current', ('a.test',), budget=budget)
        if finish(cap) == 'done':
            cap.seal()
            result = cap.take()
        else:
            result = None
        if result is None:
            assert cap.status == 'capacity'
            cap.discard()
            break
        units += 1
    assert units > 1 and 262136 <= budget.visits <= 262144
    assert budget.workspace == 0 and budget._unit is None


@pytest.mark.parametrize('after', ['ownership', 'encoding', 'transfer'])
def test_expiry_at_actual_final_boundary_never_returns_payload(after, monkeypatch):
    owners = CaptureOwners(*source())
    now = [0]
    budget = CaptureBudget(clock=lambda: now[0])
    cap = Capture(owners, 'current', ('a.test',), budget=budget)
    if after == 'ownership':
        # Certify the root before installing the late-fence injection.
        assert cap.slice() == 'more'
        original = cap._authority
        def expire():
            original()
            now[0] = 5
        monkeypatch.setattr(cap, '_authority', expire)
        assert cap.slice() == 'deadline'
    elif after == 'encoding':
        original = cap._emit
        def expire(blob):
            original(blob)
            now[0] = 5
        monkeypatch.setattr(cap, '_emit', expire)
        assert finish(cap) == 'deadline'
    else:
        assert finish(cap) == cap.seal() == 'done'
        original = cap._authority
        def expire():
            original()
            now[0] = 5
        monkeypatch.setattr(cap, '_authority', expire)
        assert cap.take() is None
        assert cap.status == 'deadline'
    assert cap.take() is None and budget.workspace == 0


def test_config_wait_that_crosses_deadline_fails_after_acquisition():
    owners = CaptureOwners(*source())
    now = [0]
    budget = CaptureBudget(clock=lambda: now[0])
    cap = Capture(owners, 'config', ('domains',), budget=budget)
    held, release = threading.Event(), threading.Event()
    def holder():
        with owners.lock:
            held.set()
            assert release.wait(4)
            now[0] = 5
    thread = threading.Thread(target=holder)
    thread.start()
    assert held.wait(4)
    release.set()
    try:
        assert cap.slice() == 'deadline'
    finally:
        thread.join(4)
    assert not thread.is_alive() and budget.workspace == 0


def test_source_cycle_is_depth_bounded_and_does_not_retain_frames():
    owners = CaptureOwners(*source())
    cyclic = []
    cyclic.append(cyclic)
    owners.current['a.test'] = cyclic
    cap = Capture(owners, 'current', ('a.test',), budget=CaptureBudget())
    assert finish(cap) == 'capacity'
    assert cap._frames == [] and cap.budget.workspace == 0


def test_search_disallows_skipped_projected_units():
    owners = CaptureOwners(*source())
    budget = CaptureBudget(kind='search')
    with pytest.raises(ValueError):
        Capture(owners, 'current', ('a.test',), budget=budget, skip_fields=('values',))
    assert budget.workspace == budget.visits == 0


@pytest.mark.parametrize('kind', [None, True, '', 'raw', object()])
def test_budget_kind_is_closed(kind):
    with pytest.raises((ValueError, TypeError)):
        CaptureBudget(kind=kind)


@pytest.mark.parametrize('root', ['config', '', True, object()])
def test_root_cursor_rejects_every_unstable_root(root):
    owners = CaptureOwners(*source())
    budget = CaptureBudget()
    with pytest.raises((ValueError, TypeError)):
        RootCursor(owners, root, budget=budget)
    assert budget.workspace == budget.visits == 0
