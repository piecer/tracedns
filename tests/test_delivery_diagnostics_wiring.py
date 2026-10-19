"""Main binds the exact store's cached diagnostic callback, not an I/O wrapper."""
import pytest

import dns_monitor
from monitor.delivery_store import DeliveryStore
from test_delivery_lifecycle_diagnostics_start import main_owners  # noqa: F401


def test_main_wires_store_diagnostics_snapshot(request, monkeypatch):
    owners = request.getfixturevalue('main_owners')
    # Allows this API worktree to exercise composition before store integration.
    def snapshot(self):
        return {'fixture': True}
    monkeypatch.setattr(DeliveryStore, 'diagnostics_snapshot', snapshot, raising=False)
    captured = {}
    stop = RuntimeError('stop before starting HTTP or delivery workers')

    def make_handler(*args, **kwargs):
        captured.update(kwargs)
        raise stop

    monkeypatch.setattr(dns_monitor, 'make_handler', make_handler)
    with pytest.raises(RuntimeError) as error:
        dns_monitor.main()
    assert error.value is stop
    assert 'delivery_diagnostics' in captured
    assert captured['delivery_diagnostics'].__self__ is owners['runtime'].store
    assert captured['delivery_diagnostics'].__func__ is snapshot
