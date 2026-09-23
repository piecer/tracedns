"""Chromium fixture gate for shipped prepared-view JS (not live backend E2E)."""
import pathlib
import subprocess

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_frontend_prepared_views():
    probe = subprocess.run(
        ["node", "-e", "require.resolve('@playwright/test')"],
        cwd=ROOT, text=True, capture_output=True, timeout=15,
    )
    if probe.returncode:
        pytest.skip("Chromium fixture gate requires npm ci and Playwright Chromium")
    result = subprocess.run(
        ["node", "tests/frontend_prepared_views.js"],
        cwd=ROOT, text=True, capture_output=True, timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
