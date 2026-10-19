"""Execute shipped UI/auth/settings-loader code with synthetic transport only."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_teams_test_frontend():
    result = subprocess.run(['node', 'tests/test_teams_test_frontend.js'], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
