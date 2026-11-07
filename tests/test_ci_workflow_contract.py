"""CI wiring regression checks (no GitHub service or credentials needed)."""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SECURITY_FILES = (
    "test_ens_decoder.py", "test_ens_static_mapping.py", "test_ens_sha256_hmac_xor.py",
    "test_ens_authenticated_integration.py", "test_dht_protocol_regressions.py",
    "test_dht_monitor.py", "test_dht_state_regressions.py", "test_ip_removal_grace.py",
    "test_reappearance_suppression.py", "test_regex_safety.py", "test_ip_list_external_lookup_policy.py",
)


def test_ci_security_regression_uses_existing_corpus_verbose():
    result = subprocess.run(["make", "-n", "security-regression", "PYTHON=python3"], cwd=ROOT,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "-m pytest -v -ra" in result.stdout
    assert set(re.findall(r"tests/(test_\w+\.py)", result.stdout)) == set(SECURITY_FILES)


def test_ci_workflow_has_fail_closed_jobs_and_exact_action_pins():
    import yaml
    data = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    triggers = data.get("on", data.get(True))  # YAML 1.1 treats 'on' as true.
    assert set(triggers) == {"pull_request", "push", "schedule", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["master"]
    assert data["permissions"] == {"contents": "read"}
    jobs = data["jobs"]
    assert set(jobs) == {"unit", "lint", "browser", "dependency-audit"}
    for job in jobs.values():
        assert not job.get("continue-on-error")
        assert job["timeout-minutes"] > 0
        for step in job["steps"]:
            assert not step.get("continue-on-error")
            if "uses" in step:
                assert re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"])
    assert jobs["unit"]["strategy"]["matrix"]["python"] == ["3.11", "3.12"]
    assert any(step.get("uses", "").startswith("actions/setup-node@") for step in jobs["unit"]["steps"])
    for name, command in (("unit", "make test"), ("lint", "make lint"), ("browser", "npm run test:e2e")):
        commands = "\n".join(step.get("run", "") for step in jobs[name]["steps"])
        assert f"loopback_only.sh {command}" in commands
    assert "loopback_only.sh make security-regression" in str(jobs["unit"])
    assert "--with-deps chromium" in str(jobs["browser"])
    assert "audit_environment.sh" in str(jobs["dependency-audit"])
    assert "if" not in jobs["dependency-audit"]
    assert "secrets." not in str(data)
    # A root .ci-tools venv is not Ruff's excluded .venv and pollutes make lint.
    assert 'venv .ci-tools' not in str(data)
    assert 'RUNNER_TEMP' in str(jobs["lint"])


def test_ci_retains_relationship_coverage_gate():
    import yaml
    data = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
    steps = data['jobs']['unit']['steps']
    coverage = [s for s in steps if 'make botnet-coverage' in s.get('run', '')]
    assert len(coverage) == 1
    assert 'loopback_only.sh make botnet-coverage' in coverage[0]['run']
    assert coverage[0]['if'] == "matrix.python == '3.12' && matrix.profile == 'ens'"
