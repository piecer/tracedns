"""Real Chromium component tests; controlled job/model/auth adapter, not app acceptance."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OWNED = ("local_ai_frontend.js", "local_ai_frontend.css",
         "tests/local_ai_panel_browser.js", "tests/test_local_ai_panel.py")


def evidence_fixtures(output, monkeypatch):
    from local_ai import evidence
    from test_local_ai_evidence import real_pair
    from test_stage3_core_runtime import app_factory

    result = real_pair(monkeypatch, count=100, candidate_limit=1000, top_pairs=5000)
    pair = evidence.project_pair(result["pairs"][0], result["quality"], result["analysis_window"],
                                 source_job_id="a" * 32, has_misp_context=False)
    app = app_factory(output / "ledger")
    try:
        progress = app.delivery.health_snapshot(include_progress=True)
        delivery = evidence.project_delivery(
            app.delivery.store.diagnostics_snapshot(), progress,
            diagnostics_captured_at=100001, progress_captured_at=100002,
        )
    finally:
        app.delivery.stop()
    from http_api import relationship_handlers as rh
    maximal_pair = dict(result["pairs"][0])
    maximal_pair["evidence"] = [{"type": key, "weight": 1} for key in sorted(evidence.PAIR_TYPES)]
    maximal_pair["assessment"] = rh._build_pair_assessment(maximal_pair["evidence"])
    maximal_pair["assessment"]["confidence"] = result["pairs"][0]["assessment"]["confidence"]
    maximum_pair = evidence.project_pair(maximal_pair, result["quality"], result["analysis_window"],
                                        source_job_id="a" * 32, has_misp_context=False)
    # Real store preserves old failure separately from later success. No adapters run.
    from test_delivery_store_atomic import AUTH, BINDINGS, obs, store_at
    from test_delivery_store_claims import result as step_result
    store = store_at(output / "diagnostics-ledger", clock=lambda: 100)
    try:
        store.bootstrap({}, {}, AUTH)
        store.record_domain(obs([f"192.0.2.{i}" for i in range(1, 14)]), AUTH, BINDINGS)
        for now in range(100, 112):
            store.finish_step(store.claim_next(BINDINGS[0], now), step_result("failed", reason="provider_tls"), now)
        store.finish_step(store.claim_next(BINDINGS[0], 112), step_result("acked"), 112)
        diagnostics = store.diagnostics_snapshot()
        assert len(diagnostics["recent_failures"]) == 10
        assert diagnostics["channels"]["misp"]["latest_result"]["state"] == "acked"
        # These cache reads deliberately have separate freshness and producers.
        delivery_history = evidence.project_delivery(diagnostics, progress,
            diagnostics_captured_at=113, progress_captured_at=100002)
    finally:
        store.close(clean=True)
    snapshots = {"relationship_pair": pair, "delivery": delivery, "maximum_pair": maximum_pair,
                 "delivery_history": delivery_history}
    digests = {key: hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
               separators=(",", ":")).encode()).hexdigest() for key, value in snapshots.items()}
    dependencies = ("local_ai/evidence.py", "local_ai/decoder.py", "local_ai/decoder_worker.py",
        "http_api/relationship_handlers.py", "http_api/delivery_diagnostics.py", "http_api/delivery_health.py",
        "monitor/delivery_store.py", "monitor/delivery_runtime.py", "tests/test_local_ai_evidence.py",
        "tests/test_stage3_core_runtime.py", "tests/test_delivery_store_atomic.py", "tests/test_delivery_store_claims.py")
    provenance = {"files": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in dependencies},
        "ordinary_pair": "real _analyze then evidence.project_pair; external lookups denied",
        "maximum_pair": "controlled complete signal inventory through real _build_pair_assessment and evidence.project_pair",
        "delivery": "real cache producers and real store failed/acked transitions; no adapters run",
        "decoder": "fresh real verifier subprocesses, not hand-authored reports",
        "model_and_jobs": "controlled component transport fixtures, not native inference or backend acceptance"}
    (output / "producer-provenance.json").write_text(json.dumps(provenance, indent=2))
    return {"snapshots": snapshots, "digests": digests}


def decoder_fixtures():
    import base64
    import time

    from local_ai import decoder

    samples = [{"data": base64.b64encode(f"192.0.2.{i + 10}:443".encode()).decode(),
                "expected_ips": [f"192.0.2.{i + 10}"], "usage": "example" if i == 0 else "validation",
                "complete_expected": True} for i in range(6)]
    steps = [{"op": "base64"}, {"op": "extract_ip_prefix"}]
    definitions = [{"name": f"custom_{i:02}", "steps": steps} for i in range(32 - len(decoder.capture_catalog({}, "TXT")["builtins"]))]
    catalog = decoder.capture_catalog({"custom_decoders": definitions}, "TXT")
    candidates = [{"steps": steps}, {"steps": [{"op": "base64"}]},
                  {"steps": [{"op": "urlsafe_b64"}, {"op": "extract_ip_prefix"}]}]
    result = {"samples": samples, "proposal": candidates,
              "catalog": decoder.evaluate_catalog("TXT", catalog, samples[:2], time.monotonic() + 30),
              "generated": decoder.evaluate_generated("TXT", candidates, samples[:2], time.monotonic() + 30),
              "maximum": decoder.evaluate_catalog("TXT", catalog, samples, time.monotonic() + 30)}
    # Real unverified extras: tokenizer yields two output addresses for one partially labelled row.
    extras = [{"data": "192.0.2.10;192.0.2.11", "expected_ips": ["192.0.2.10"],
               "usage": "example", "complete_expected": False}]
    result["extras_samples"] = extras
    result["extras"] = decoder.evaluate_generated("TXT", [{"steps": [{"op": "ascii"}]}], extras, time.monotonic() + 30)
    result["extras_catalog"] = decoder.evaluate_catalog("TXT", decoder.capture_catalog({}, "TXT"), extras, time.monotonic() + 30)
    result["six_catalog"] = decoder.evaluate_catalog("TXT", decoder.capture_catalog({"custom_decoders": definitions[:12]}, "TXT"), samples, time.monotonic() + 30)
    result["long_name_catalog"] = decoder.evaluate_catalog("TXT", decoder.capture_catalog({
        "custom_decoders": [{"name": "n" * 4096, "steps": steps}]}, "TXT"), samples[:2], time.monotonic() + 30)
    a_samples = [{"data": f"192.0.2.{i}", "expected_ips": [f"192.0.2.{i}"],
                  "usage": "example" if i == 1 else "validation", "complete_expected": True} for i in (1, 2)]
    a_proposal = [{"steps": [{"op": "xor32_ipv4", "key": "0x00000000"}]}]
    result["a"] = {"samples": a_samples, "proposal": a_proposal,
                   "catalog": decoder.evaluate_catalog("A", decoder.capture_catalog({}, "A"), a_samples, time.monotonic() + 30),
                   "generated": decoder.evaluate_generated("A", a_proposal, a_samples, time.monotonic() + 30)}
    assert result["a"]["generated"]["candidates"][0]["validation"]["passed"] == 1
    assert result["extras"]["candidates"][0]["examples"]["unverified_extra_outputs"] == 1
    assert decoder._active_child is None
    # Feed exact source-producer bytes to the browser, not a hand-written
    # abbreviated snapshot that accidentally hides a consumer shape bug.
    from local_ai.sources import capture_decoder
    from test_local_ai_sources import context
    result['snapshots'] = {}
    for name, kind, rows in [('normal', 'TXT', samples), ('extras', 'TXT', extras), ('a', 'A', a_samples)]:
        lease, encoded, _ = capture_decoder(context(), {'decoder_type': kind, 'samples': rows, 'generate': True},
                                             time.monotonic() + 10)
        try:
            result['snapshots'][name] = json.loads(encoded)
        finally:
            lease.dispose()
    return result


def test_browser_dependency_default_is_checkout_local():
    script = """
const Module=require('node:module');
const load=Module._load;let observed;
const stop=new Error('resolution observed');
Module._load=function(name,...args){
  if(name.includes('playwright')){observed=name;throw stop;}
  return load.call(this,name,...args);
};
try{require(process.argv[1]);}catch(error){if(error!==stop)throw error;}
require('node:assert/strict').equal(observed,'@playwright/test');
"""
    env = {key: value for key, value in os.environ.items() if key != 'UI_PLAYWRIGHT_MODULE'}
    result = subprocess.run(['node', '-e', script, str(ROOT / 'tests/local_ai_panel_browser.js')],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_local_ai_panel(tmp_path, monkeypatch):
    monkeypatch.setenv('MISP_SIGHTING_BATCH_FILE', str(tmp_path / 'sightings.json'))
    output = Path(os.environ.get("UI_PANEL_EVIDENCE", str(tmp_path / "browser")))
    output.mkdir(parents=True, exist_ok=True)
    sources = output / "sources"
    sources.mkdir()
    manifest = {}
    for name in OWNED:
        source = ROOT / name
        if source.exists():
            raw = source.read_bytes()
            target = sources / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            manifest[name] = {"sha256": hashlib.sha256(raw).hexdigest(),
                              "size": len(raw), "mode": oct(source.stat().st_mode & 0o777)}
        else:
            manifest[name] = {"absent": True}
    (output / "source-manifest.json").write_text(json.dumps(manifest, indent=2))
    fixtures = evidence_fixtures(output, monkeypatch)
    auth_path = Path(os.environ.get("UI_PANEL_REAL_AUTH", str(ROOT / "auth_frontend.js")))
    auth_bytes = auth_path.read_bytes()
    (output / "auth-wrapper.js").write_bytes(auth_bytes)
    (output / "auth-wrapper-provenance.json").write_text(json.dumps({
        "path": str(auth_path), "sha256": hashlib.sha256(auth_bytes).hexdigest(),
        "scope": "real script with controlled auth/me; not real server authentication acceptance",
    }, indent=2))
    fixtures["decoder"] = decoder_fixtures()
    fixture_path = output / "fixtures.json"
    fixture_path.write_text(json.dumps(fixtures))
    command = ["node", "tests/local_ai_panel_browser.js", str(fixture_path), str(output),
               os.environ.get("UI_PANEL_CASE", "all")]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=150,
                            env={**os.environ, "UI_PANEL_REAL_AUTH": str(output / "auth-wrapper.js")})
    (output / "browser.stdout").write_text(result.stdout)
    (output / "browser.stderr").write_text(result.stderr)
    (output / "execution.json").write_text(json.dumps({
        "command": command, "returncode": result.returncode,
        "scope": "component; controlled job lifecycle and auth adapter, not real authentication",
    }, indent=2))
    assert result.returncode == 0, result.stdout + result.stderr
