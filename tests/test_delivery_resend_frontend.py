"""Execute the shipped widget through the real auth wrapper; no provider I/O."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_delivery_resend_frontend():
    result = subprocess.run(['node', 'tests/test_delivery_resend_frontend.js'], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
