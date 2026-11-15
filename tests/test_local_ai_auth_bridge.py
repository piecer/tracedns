"""Run the shipped auth wrapper against controlled HTTP outcomes in Node."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_local_ai_auth_bridge():
    result = subprocess.run(['node', 'tests/local_ai_auth_bridge.js'], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS 98 real auth-wrapper AI protocol controls' in result.stdout
