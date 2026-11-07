"""Kernel namespace boundary controls; no external service is contacted."""
from pathlib import Path
import runpy
import socket
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts/ci/network_probe.py"


def test_ci_network_probe_rejects_nonloopback_before_any_io(monkeypatch):
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    def forbidden(*args, **kwargs):
        pytest.fail("external socket attempted before topology rejection")
    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(SystemExit, match="only loopback"):
        runpy.run_path(str(PROBE), run_name="__main__")


def test_ci_network_wrapper_rejects_missing_command():
    result = subprocess.run(["bash", str(ROOT / "scripts/ci/loopback_only.sh")],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "usage" in result.stderr
