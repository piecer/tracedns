"""Execute the shipped JavaScript against deterministic stalled transports."""
import pathlib
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_frontend_request_recovery():
    result = subprocess.run(
        ["node", "tests/frontend_request_recovery.js"],
        cwd=ROOT, text=True, capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
