"""Real-browser component coverage, not authenticated AI API acceptance."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from local_ai_app_fixture import application

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("scenario", ["inert-load", "remote-save", "binding-clear", "write-later", "error-409", "error-400", "error-503", "error-audit", "error-network", "closed-receipts", "read-later", "read-order", "retire-hide", "retire-role", "provider-switch", "runtime-reflow", "unrelated-drafts", "conflict-key-aba", "auth-viewer", "auth-operator", "initial-gate", "logout", "native-loaded", "loopback-anonymous"])
def test_ai_settings_component(tmp_path, monkeypatch, scenario):
    if scenario in ("auth-viewer", "auth-operator"):
        from security.store import SecurityStore
        bootstrap = SecurityStore.bootstrap

        def bootstrap_with_role(store, username, password):
            result = bootstrap(store, username, password)
            user = store.create_user("fixture-role", "fixture-initial-password", scenario.removeprefix("auth-"),
                                     actor=store.list_users()[0])
            store.change_password(user["id"], "fixture-initial-password", "fixture-only-password", actor=user)
            return result

        monkeypatch.setattr(SecurityStore, "bootstrap", bootstrap_with_role)
    with application(tmp_path, monkeypatch, enabled=False) as app:
        env = {**os.environ, "AI_SETTINGS_ORIGIN": app.origin,
               "AI_SETTINGS_SCENARIO": scenario, "AI_SETTINGS_PYTHON": sys.executable,
               "AI_SETTINGS_OUTPUT": str(tmp_path)}
        result = subprocess.run(["node", "tests/ai_settings_panel_browser.js"],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=100)
        assert result.returncode == 0, result.stdout + result.stderr
        assert app.snapshot()["native"] == []
        assert app.snapshot()["forbidden"] == []
    assert app.cleanup["remaining_owned_threads"] == []
