"""Focused Chromium acceptance through real authenticated local-AI app routes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from local_ai_app_fixture import application

ROOT = Path(__file__).resolve().parents[1]
CASES = ["delivery", "decoder", "pair", "refusal", "manual-check", "result-order",
         "unavailable", "stopped", "unsettled", "disabled", "audit-pending", "audit-failed",
         "cancel", "auth-retirement", "decoder-fences", "decoder-A", "decoder-ko", "delayed-create",
         "provider-failed", "source-exclusions", "source-retirement-after-success",
         "failed-rerun-retains-history", "same-source-eviction-create-404", "decoder-max-excerpt",
         "review-manual-preview-save", "review-delivery-missing", "review-delivery-wrong-citation",
         "review-decoder-coverage", "review-decoder-null-model"]


def source_manifest():
    paths = [ROOT / name for name in ("dns_frontend.html", "dns_frontend.js", "dns_frontend.css",
             "auth_frontend.js", "local_ai_frontend.js", "local_ai_frontend.css", "http_server.py",
             "http_api_handlers.py", "tests/local_ai_app_fixture.py", "tests/local_ai_app_browser.js",
             "tests/test_local_ai_app_browser.py", "tests/test_local_ai_sources.py",
             "tests/test_local_ai_provider.py", "tests/test_stage3_core_runtime.py")]
    for directory in ("local_ai", "http_api", "security", "monitor"):
        paths.extend((ROOT / directory).glob("*.py"))
    return {str(p.relative_to(ROOT)): {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "size": p.stat().st_size, "mode": oct(p.stat().st_mode & 0o777)} for p in sorted(set(paths))}


@pytest.mark.parametrize("case", CASES)
def test_application_browser(tmp_path, monkeypatch, case):
    if case == "same-source-eviction-create-404":
        from http_api import relationship_handlers as rh
        assert rh._IP_REL_JOB_MAX_TERMINAL == 32
        assert rh._IP_REL_JOB_MAX_RESULT_BYTES == 64 * 1024 * 1024
        assert rh._IP_REL_JOB_TTL_SECONDS == 3600
    output = Path(os.environ.get("UI_APP_EVIDENCE", str(tmp_path / "evidence"))) / case
    output.mkdir(parents=True, exist_ok=False)
    before = source_manifest()
    (output / "sources.json").write_text(json.dumps(before, indent=2))
    with application(tmp_path / "app", monkeypatch, enabled=case != 'disabled') as app:
        command = ["node", str(ROOT / "tests/local_ai_app_browser.js"),
                   app.origin, app.control, str(output), case]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=100)
        (output / "stdout.txt").write_text(result.stdout)
        (output / "stderr.txt").write_text(result.stderr)
        (output / "execution.json").write_text(json.dumps({"command": command, "returncode": result.returncode,
            "scope": "Real authenticated HTTP/service/engine/producers; controlled native peer, no model"}, indent=2))
        (output / "server.json").write_text(json.dumps(app.snapshot(), indent=2))
    (output / "cleanup.json").write_text(json.dumps(app.cleanup, indent=2))
    assert source_manifest() == before, "executed source must remain frozen"
    assert result.returncode == 0, result.stdout + result.stderr
