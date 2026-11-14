"""Execute the shipped presentation owner contract in Node."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_view_feedback():
    result = subprocess.run(['node', 'tests/test_view_feedback.js'], cwd=ROOT,
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
