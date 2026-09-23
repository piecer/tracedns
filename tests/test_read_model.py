"""Event-controlled contracts for the worker-only published read model."""
import importlib
import importlib.util
import threading
import time

import pytest


def eventually(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.001)
    assert predicate(), "condition did not become true"


@pytest.fixture
def factory():
    assert importlib.util.find_spec("http_api.read_model"), "read model is missing"
    cls = importlib.import_module("http_api.read_model").BackgroundReadModel
    models = []

    def create(capture, build, **kwargs):
        model = cls(capture, build, **kwargs)
        models.append(model)
        return model

    yield create
    for model in models:
        assert model.close(timeout=2)["remaining"] == 0


def test_cold_start_publishes_worker_result_without_request_work(factory):
    entered, release = threading.Event(), threading.Event()
    threads = []
    payload = {"rows": [1]}

    def capture(previous):
        threads.append(threading.current_thread())
        entered.set()
        assert release.wait(2)
        return "source-1", [1]

    model = factory(capture, lambda inputs: payload)
    assert threads == []
    assert model.read() == (None, {
        "ready": False, "stale": False, "source_version": None,
        "generated_at": None, "status": "building", "version": 0,
        "error_code": None,
    })
    try:
        model.start()
        model.start()
        assert entered.wait(1)
        for _ in range(100):
            assert model.read()[0] is None
        assert len(threads) == 1
        assert threads[0].daemon
        assert threads[0] is not threading.current_thread()
    finally:
        release.set()
    eventually(lambda: model.read()[1]["ready"])
    result, metadata = model.read()
    assert result is payload
    assert metadata["source_version"] == "source-1"
    assert metadata["version"] == 1
    assert metadata["status"] == "ready"
    assert metadata["generated_at"] > 0
    metadata["ready"] = False
    assert model.read()[1]["ready"]
    assert model.close() == {"remaining": 0, "running": 0, "queued": 0}
    assert model.read()[1]["status"] == "stopped"


def test_periodic_capture_skips_unchanged_and_detects_missed_notifications(factory):
    state = [1]
    captures, builds = [], []

    def capture(previous):
        captures.append(previous)
        return None if previous == state[0] else (state[0], state[0])

    def build(value):
        builds.append(value)
        return {"value": value}

    model = factory(capture, build, interval=0.01)
    model.start()
    eventually(lambda: len(captures) >= 3)
    assert builds == [1]
    assert captures[:3] == [None, 1, 1]
    state[0] = 2
    eventually(lambda: model.read()[1]["source_version"] == 2)
    assert builds == [1, 2]
    assert model.read()[1]["version"] == 2


def test_dirty_during_build_coalesces_without_starving_publication(factory):
    building, release = threading.Event(), threading.Event()
    recapture, release_capture = threading.Event(), threading.Event()
    state, builds, captures = [1], [], []

    def capture(previous):
        captures.append(previous)
        if len(captures) == 2:
            recapture.set()
            assert release_capture.wait(2)
        return None if previous == state[0] else (state[0], state[0])

    def build(value):
        builds.append(value)
        if value == 1:
            building.set()
            assert release.wait(2)
        return {"value": value}

    model = factory(capture, build, interval=10)
    model.start()
    try:
        assert building.wait(1)
        state[0] = 2
        for _ in range(5000):
            model.invalidate()
        release.set()
        assert recapture.wait(1)
        payload, metadata = model.read()
        assert payload == {"value": 1}
        assert metadata["version"] == 1
        assert metadata["stale"]
        assert metadata["status"] == "stale"
    finally:
        release.set()
        release_capture.set()
    eventually(lambda: model.read()[1]["source_version"] == 2)
    assert not model.read()[1]["stale"]
    assert builds == [1, 2]
    assert captures == [None, 1]


def test_invalidation_during_unchanged_capture_is_not_lost(factory):
    entered, release = threading.Event(), threading.Event()
    state, captures = [1], []

    def capture(previous):
        captures.append(previous)
        value = state[0]
        if len(captures) == 2:
            entered.set()
            assert release.wait(2)
        return None if previous == value else (value, value)

    model = factory(capture, lambda value: {"value": value}, interval=10)
    model.start()
    eventually(lambda: model.read()[1]["ready"])
    try:
        model.invalidate()
        assert entered.wait(1)
        state[0] = 2
        model.invalidate()
        release.set()
        eventually(lambda: model.read()[1]["source_version"] == 2)
        model.invalidate()  # Unchanged successful check clears stale.
        eventually(lambda: len(captures) == 4 and not model.read()[1]["stale"])
        assert model.read()[1]["version"] == 2
    finally:
        release.set()


@pytest.mark.parametrize("phase", ["capture", "build", "unchanged"])
def test_hard_invalidation_fences_old_work_and_forces_capture(factory, phase):
    entered, release = threading.Event(), threading.Event()
    fresh, release_fresh = threading.Event(), threading.Event()
    state, captures = [1], []

    def capture(previous):
        captures.append(previous)
        value = state[0]
        if len(captures) == 2 and phase != "build":
            entered.set()
            assert release.wait(2)
        if len(captures) == 3:
            fresh.set()
            assert release_fresh.wait(2)
        return None if previous == value else (value, value)

    def build(value):
        if value == 2 and phase == "build" and len(captures) == 2:
            entered.set()
            assert release.wait(2)
        return {"value": value}

    model = factory(capture, build, interval=10)
    model.start()
    eventually(lambda: model.read()[1]["ready"])
    try:
        state[0] = 1 if phase == "unchanged" else 2
        model.invalidate()
        assert entered.wait(1)
        model.invalidate(hard=True)
        payload, metadata = model.read()
        assert payload is None
        assert not metadata["ready"]
        assert metadata["generated_at"] is None
        assert metadata["source_version"] is None
        release.set()
        assert fresh.wait(1)
        assert model.read()[0] is None
        assert model.read()[1]["version"] == 1
        assert captures == [None, 1, None]
    finally:
        release.set()
        release_fresh.set()
    eventually(lambda: model.read()[1]["version"] == 2)
    assert model.read()[0] == {"value": state[0]}


@pytest.mark.parametrize("phase", ["capture", "build"])
def test_failure_preserves_last_good_and_retries_same_source_with_backoff(factory, phase):
    state, attempts = [1], []
    retry_entered, release_retry = threading.Event(), threading.Event()

    def operation():
        if state[0] == 2:
            attempts.append(time.monotonic())
            if len(attempts) == 1:
                raise RuntimeError("private input and traceback must not escape")
            retry_entered.set()
            assert release_retry.wait(2)

    def capture(previous):
        if phase == "capture":
            operation()
        return None if previous == state[0] else (state[0], state[0])

    def build(value):
        if phase == "build":
            operation()
        return {"value": value}

    model = factory(capture, build, interval=0.08)
    model.start()
    eventually(lambda: model.read()[1]["ready"])
    state[0] = 2
    model.invalidate()
    try:
        eventually(lambda: model.read()[1]["status"] == "error")
        payload, metadata = model.read()
        assert payload == {"value": 1}
        assert metadata["stale"] and metadata["ready"]
        assert metadata["source_version"] == 1
        assert metadata["error_code"] == "build_failed"
        assert "private" not in str(metadata)
        for _ in range(5000):
            model.invalidate()
        assert retry_entered.wait(1)
        assert attempts[1] - attempts[0] >= 0.07
    finally:
        release_retry.set()
    eventually(lambda: model.read()[1]["source_version"] == 2)
    assert model.read()[1]["error_code"] is None
    assert model.read()[1]["status"] == "ready"


@pytest.mark.parametrize("phase", ["capture", "build"])
def test_stop_admission_and_close_report_running_without_late_publication(factory, phase):
    entered, release = threading.Event(), threading.Event()
    builds = []

    def capture(previous):
        if phase == "capture":
            entered.set()
            assert release.wait(2)
        return 1, 1

    def build(value):
        builds.append(value)
        if phase == "build":
            entered.set()
            assert release.wait(2)
        return {"value": value}

    model = factory(capture, build)
    model.start()
    try:
        assert entered.wait(1)
        model.invalidate()
        model.stop_admission()
        before = model.read()
        model.invalidate(hard=True)
        model.start()
        assert model.read() == before
        started = time.monotonic()
        assert model.close(timeout=0.01) == {"remaining": 1, "running": 1, "queued": 0}
        assert time.monotonic() - started < 0.3
        assert model.close(timeout=0) == {"remaining": 1, "running": 1, "queued": 0}
        assert model.read()[1]["status"] == "stopped"
    finally:
        release.set()
    assert model.close() == {"remaining": 0, "running": 0, "queued": 0}
    assert model.read()[0] is None
    assert model.read()[1]["version"] == 0
    assert builds == ([] if phase == "capture" else [1])


def test_stop_before_start_is_terminal(factory):
    calls = []
    model = factory(lambda previous: calls.append(previous), lambda inputs: {})
    model.stop_admission()
    model.start()
    model.invalidate()
    assert model.close() == {"remaining": 0, "running": 0, "queued": 0}
    assert calls == []


@pytest.mark.parametrize("bad_payload", [{"value": "x" * 100}, {"value": object()}, [], {"value": float("nan")}])
def test_invalid_or_oversized_payload_never_replaces_last_good(factory, bad_payload):
    state = [1]

    def capture(previous):
        return None if previous == state[0] else (state[0], state[0])

    model = factory(capture, lambda value: {} if value == 1 else bad_payload,
                    max_bytes=32, interval=0.05)
    model.start()
    eventually(lambda: model.read()[1]["ready"])
    state[0] = 2
    model.invalidate()
    eventually(lambda: model.read()[1]["error_code"] is not None)
    payload, metadata = model.read()
    assert payload == {}
    assert metadata["version"] == 1
    assert metadata["source_version"] == 1
    assert metadata["stale"]
    assert metadata["error_code"] == "build_failed"


def test_json_byte_limit_and_one_worker_only_encoding(factory, monkeypatch):
    module = importlib.import_module("http_api.read_model")
    import json
    real_dumps = json.dumps
    calls = []

    def dumps(*args, **kwargs):
        calls.append(threading.current_thread())
        return real_dumps(*args, **kwargs)

    monkeypatch.setattr(module.json, "dumps", dumps)
    model = factory(lambda previous: None if previous == 1 else (1, {}),
                    lambda inputs: inputs, max_bytes=2, interval=0.01)
    model.start()
    eventually(lambda: model.read()[1]["ready"])
    for _ in range(100):
        assert model.read()[0] == {}
    assert len(calls) == 1
    assert calls[0] is not threading.current_thread()
    assert calls[0].daemon


@pytest.mark.parametrize("kwargs", [
    {"interval": 0}, {"interval": -1}, {"interval": 0.0001},
    {"interval": float("nan")}, {"interval": float("inf")},
    {"interval": 1e100}, {"interval": 10 ** 1000},
    {"interval": True}, {"interval": "1"},
    {"max_bytes": 0}, {"max_bytes": -1}, {"max_bytes": 32 * 1024 * 1024 + 1},
    {"max_bytes": 1.5}, {"max_bytes": True}, {"max_bytes": "32"},
])
def test_constructor_rejects_invalid_resource_bounds(factory, kwargs):
    with pytest.raises(ValueError):
        factory(lambda previous: None, lambda inputs: {}, **kwargs)


def test_failed_candidate_and_inputs_are_released_before_retry(factory):
    import weakref
    refs = []

    class Payload(dict):
        pass

    def capture(previous):
        inputs = Payload(value="x" * 100)
        refs.append(weakref.ref(inputs))
        return 1, inputs

    def build(inputs):
        payload = Payload(inputs)
        refs.append(weakref.ref(payload))
        return payload

    model = factory(capture, build, max_bytes=2, interval=10)
    model.start()
    eventually(lambda: model.read()[1]["status"] == "error")
    eventually(lambda: len(refs) == 2 and all(ref() is None for ref in refs), timeout=0.2)
    assert model.read()[0] is None


def test_periodically_detected_change_marks_last_good_stale_while_building(factory):
    state = [1]
    entered, release = threading.Event(), threading.Event()

    def capture(previous):
        return None if previous == state[0] else (state[0], state[0])

    def build(value):
        if value == 2:
            entered.set()
            assert release.wait(2)
        return {"value": value}

    model = factory(capture, build, interval=0.01)
    model.start()
    eventually(lambda: model.read()[1]["ready"])
    try:
        state[0] = 2  # No notification: periodic source check discovers this.
        assert entered.wait(1)
        payload, metadata = model.read()
        assert payload == {"value": 1}
        assert metadata["stale"]
        assert metadata["status"] == "stale"
    finally:
        release.set()
    eventually(lambda: model.read()[1]["source_version"] == 2)


@pytest.mark.parametrize("hard", [False, True])
def test_retiring_payload_does_not_hold_the_read_lock(factory, hard):
    retiring, release = threading.Event(), threading.Event()
    read_done = threading.Event()
    state = [1]

    class Payload(dict):
        def __del__(self):
            retiring.set()
            release.wait(2)

    def capture(previous):
        return None if previous == state[0] else (state[0], state[0])

    model = factory(capture, lambda value: Payload(value=1) if value == 1 else {}, interval=10)
    model.start()
    eventually(lambda: model.read()[1]["ready"])
    state[0] = 2
    mutator = threading.Thread(target=lambda: model.invalidate(hard=hard), daemon=True)
    reader = threading.Thread(target=lambda: (model.read(), read_done.set()), daemon=True)
    try:
        mutator.start()
        assert retiring.wait(1)
        reader.start()
        assert read_done.wait(0.2), "payload destruction blocked request-side reads"
    finally:
        release.set()
        mutator.join(1)
        if reader.ident is not None:
            reader.join(1)
