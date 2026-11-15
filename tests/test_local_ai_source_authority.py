"""AI source authority distinguishes hard revocation from ordinary refresh."""
import threading

import pytest

from http_api.read_model import BackgroundReadModel


def test_read_model_exposes_instance_and_hard_epoch_without_capture():
    def forbidden(*args):
        raise AssertionError('authority read must not capture or rebuild')

    model = BackgroundReadModel(forbidden, forbidden)
    other = BackgroundReadModel(forbidden, forbidden)
    getter = getattr(model, 'publication_authority', None)
    assert callable(getter), 'publication authority accessor missing'
    initial = getter()
    assert initial == getter()
    assert initial != other.publication_authority()
    model.invalidate(hard=False)
    assert getter() == initial
    model.invalidate(hard=True)
    current = getter()
    assert current[0] == initial[0]
    assert current[1] == initial[1] + 1


def test_stopped_publisher_cannot_authorize_an_ai_source():
    model = BackgroundReadModel(lambda _: None, lambda _: {})
    model.stop_admission()
    with pytest.raises(RuntimeError, match='stopped'):
        model.publication_authority()


def test_authority_lock_wait_has_a_finite_policy_bound():
    model = BackgroundReadModel(lambda _: None, lambda _: {})
    acquired, release = threading.Event(), threading.Event()

    def hold():
        with model._condition:
            acquired.set()
            assert release.wait(2)

    holder = threading.Thread(target=hold)
    holder.start()
    try:
        assert acquired.wait(1)
        with pytest.raises(TimeoutError):
            model.publication_authority(timeout=0.01)
    finally:
        release.set()
        holder.join(2)
    assert not holder.is_alive()


@pytest.mark.parametrize('timeout', [-1, 1, True, float('nan'), float('inf')])
def test_authority_rejects_invalid_wait_overrides(timeout):
    model = BackgroundReadModel(lambda _: None, lambda _: {})
    with pytest.raises(ValueError):
        model.publication_authority(timeout=timeout)
