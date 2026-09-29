"""Literal per-call work, inclusive fences, and sliced owned preflight."""
from unittest.mock import patch
import inspect
import sys

import security.derived_redaction as m
from tests.test_stage4_redaction_plan import owners


def test_sliced_preflight_never_yields_without_work():
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        admission = m.OwnedPayload.admit_sliced([0], budget=budget)
    ticks = iter(i * .003 for i in range(100))
    with patch.object(m.time, 'monotonic', side_effect=lambda: next(ticks)):
        assert admission.slice() == 'deadline'
    assert admission.gen is None and admission._lease is None
    assert budget._active is None and not admission._running


def test_maximum_owned_graph_has_resumable_preflight():
    assert hasattr(m.OwnedPayload, 'admit_sliced'), 'bounded preflight producer missing'
    raw = [0] * 4095
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        admission = m.OwnedPayload.admit_sliced(raw, budget=budget)
        assert admission.status == 'more'
        deltas = []
        for _ in range(20):
            before = admission.steps
            status = admission.slice()
            deltas.append(admission.steps - before)
            assert 0 < deltas[-1] <= 512 or status != 'more'
            if status != 'more':
                break
        assert admission.status == 'done'
        assert admission.nodes == 4096
        assert len(deltas) > 1
        handle = admission.take()
        assert handle.value is raw
        assert admission.take() is None
        handle.close()
        assert budget.counters()['worker_bytes'] == 0


def test_256_roots_share_slice_budget_with_real_dfs():
    cfg = {f'ordinary-{i}': i for i in range(256)}
    lock, model = owners(cfg)
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        builder = m.Builder(cfg, lock, model, budget=budget)
        deltas = []
        for _ in range(100):
            before = budget.visits
            if builder.status == 'more':
                builder.slice()
            elif builder.status == 'captured':
                builder.seal_slice()
            else:
                break
            deltas.append(budget.visits - before)
            assert deltas[-1] <= 512, (builder.counters(), deltas)
        assert builder.status == 'done', builder.counters()
        before = budget.visits
        output = builder.take()
        assert output is not None and budget.visits - before <= 512
        assert builder.visits == budget.visits <= m.VISITS
        output.close()
        assert budget.counters()['worker_bytes'] == 0
        assert max(deltas) <= 512


def test_atomic_root_budget_cannot_cause_no_progress_retry():
    cfg = {f'root-{i}': i for i in range(512)}
    lock, model = owners(cfg)
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        builder = m.Builder(cfg, lock, model, budget=budget)
        assert builder.slice() == 'deadline'
        assert budget.visits <= 512
        assert builder.config is builder.model is builder.lock is None
        assert budget.counters()['worker_bytes'] == 0


def test_nested_validation_and_path_resolution_share_literal_work():
    cfg = {f'opaque-{i}': None for i in range(250)}
    cfg['nested'] = {'level': {f'key-{i}': i for i in range(20)}}
    lock, model = owners(cfg)
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        builder = m.Builder(cfg, lock, model, budget=budget)
        for _ in range(80):
            previous = tuple(builder.frames)
            before = budget.visits
            status = builder.slice() if builder.status == 'more' else builder.seal_slice()
            assert budget.visits - before <= 512
            if status != 'more':
                if builder.status == 'captured':
                    continue
                break
            assert tuple(builder.frames) != previous or builder.status == 'captured'
        assert builder.status == 'done', builder.counters()
        output = builder.take()
        assert output is not None
        output.close()
        assert budget.counters()['worker_bytes'] == 0


def test_digest_work_and_both_source_fences_share_one_slice():
    cfg = {f'opaque-{i}': None for i in range(249)}
    cfg['api_key'] = 's' * 65536
    lock, model = owners(cfg)
    units = [0]
    visit, prepare = m.Builder.visit, m.Builder.prepare
    seal_code = inspect.unwrap(m.Builder.seal_slice).__code__

    def charge(owner, n=1):
        # Observe source visits independently of any new digest accounting.
        if sys._getframe(1).f_code is not seal_code:
            units[0] += n
        return visit(owner, n)

    def digest(owner):
        for value in prepare(owner):
            units[0] += 1
            yield value

    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        builder = m.Builder(cfg, lock, model, budget=budget)
        for _ in range(100):
            if builder.slice() != 'more':
                break
        assert builder.status == 'captured'
        with patch.object(m.Builder, 'visit', new=charge), patch.object(m.Builder, 'prepare', new=digest):
            for _ in range(10):
                units[0] = 0
                status = builder.seal_slice()
                assert units[0] <= 512, (units[0], builder.counters())
                if status != 'more':
                    break
        assert builder.status == 'done'
        output = builder.take()
        assert output is not None
        output.close()


def test_sliced_preflight_deadline_and_cleanup_do_not_reset_attempt():
    clock = [0]
    with patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]):
        budget = m.RedactionBudget(deadline=5)
        admission = m.OwnedPayload.admit_sliced([0] * 4095, budget=budget)
        assert admission.slice() == 'more'
        assert 0 < admission.steps <= 512 and budget.deadline == 5
        clock[0] = 5
        assert admission.slice() == 'deadline'
        assert admission.gen is admission.result is admission._lease is None
        assert not budget.counters()['active'] and not admission._running
        assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0
        assert admission.take() is None
        admission.discard()


def test_sliced_preflight_exact_node_boundary_and_public_cancellation():
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        admission = m.OwnedPayload.admit_sliced([0] * 4096, budget=budget)
        assert admission.slice() == 'capacity'
        assert budget.counters()['worker_bytes'] == 0
        following = m.OwnedPayload.admit_sliced('é' * 8192, budget=budget)
        assert following.slice() == 'done'
        assert following.steps == 9  # node plus eight UTF8 validation chunks
        following.discard()
        assert following.gen is following.result is None
        assert not following._running and budget._active is None
        assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0


def test_secret_copy_iterations_share_root_validation_work_allowance():
    cfg = {f'opaque-{i}': None for i in range(249)}
    cfg['api_key'] = 's' * 65536
    lock, model = owners(cfg)
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        builder = m.Builder(cfg, lock, model, budget=budget)
        for _ in range(100):
            scans = builder.root_scans
            status = builder.slice()
            # Every DFS iteration (including an additional UTF8 copy chunk)
            # plus the actual catalog-key visits shares the one work ceiling.
            assert builder.steps + (builder.root_scans - scans) * len(cfg) <= 512
            if status != 'more':
                break
        assert builder.status == 'captured'
        builder.discard()


def test_atomic_catalog_counts_key_utf8_chunks_before_work():
    cfg = {f'k{i}': None for i in range(419)}
    cfg['k' * 100000] = None
    lock, model = owners(cfg)
    with patch.object(m.time, 'monotonic', return_value=0):
        budget = m.RedactionBudget(deadline=5)
        builder = m.Builder(cfg, lock, model, budget=budget)
        assert builder.slice() == 'deadline'
        assert budget.visits == 512
        assert builder.config is builder.catalog is builder._lease is None
        assert budget.counters()['worker_bytes'] == budget.counters()['metadata_bytes'] == 0
