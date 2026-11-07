"""Fail-closed audit report acceptance; fixtures are synthetic, not audit results."""
from importlib.metadata import version
import json
import shlex
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_validator(tmp_path, report, freeze="example-package==1.0\n", status=0):
    report_path = tmp_path / "audit.json"
    if report is not None:
        report_path.write_text(report if isinstance(report, str) else json.dumps(report))
    freeze_path = tmp_path / "freeze.txt"
    freeze_path.write_text(freeze)
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/ci/validate_audit.py"), str(report_path),
         str(freeze_path), str(status)], capture_output=True, text=True, check=False,
    )


def clean_report():
    return {"dependencies": [{"name": "example-package", "version": "1.0", "vulns": []}], "fixes": []}


def test_ci_audit_accepts_complete_clean_report(tmp_path):
    result = run_validator(tmp_path, clean_report())
    assert result.returncode == 0, result.stderr
    assert "audited 1 pinned packages" in result.stdout


@pytest.mark.parametrize("report", [
    None, "", "{", {}, [], {"dependencies": [], "fixes": []},
    {"dependencies": [{"name": "example-package", "skip_reason": "unavailable"}], "fixes": []},
    {"dependencies": [{"name": "example-package", "version": "1.0", "vulns": [], "skip_reason": "skip"}], "fixes": []},
    {"dependencies": [{"name": "example-package", "version": "1.0", "vulns": [{"id": "CVE-test"}]}], "fixes": []},
    {**clean_report(), "errors": ["service failure"]},
    {**clean_report(), "fixes": [{"error": "failed"}]},
    {"dependencies": [clean_report()["dependencies"][0]] * 2, "fixes": []},
    {"dependencies": [{"name": "other", "version": "1.0", "vulns": []}], "fixes": []},
    {"dependencies": [{"name": "example-package", "version": "2.0", "vulns": []}], "fixes": []},
    {"dependencies": [None], "fixes": []},
])
def test_ci_audit_rejects_incomplete_or_dirty_report(tmp_path, report):
    assert run_validator(tmp_path, report).returncode != 0


@pytest.mark.parametrize("freeze", ["", "example-package>=1.0\n", "-e .\n", "example-package==1.0\nother==2.0\n"])
def test_ci_audit_requires_complete_pinned_inventory(tmp_path, freeze):
    assert run_validator(tmp_path, clean_report(), freeze=freeze).returncode != 0


@pytest.mark.parametrize("status", [1, 2, 127])
def test_ci_audit_rejects_tool_error_even_with_clean_json(tmp_path, status):
    assert run_validator(tmp_path, clean_report(), status=status).returncode != 0


@pytest.mark.parametrize("mode", ["clean", "missing", "empty", "skip", "error", "stale"])
def test_ci_audit_runner_rejects_missing_output_and_tool_errors(tmp_path, mode):
    app = tmp_path / "app-python"
    app.write_text(f'#!/bin/sh\nif [ "$2" = pip ]; then\n'
                   '  if [ "$3" = freeze ]; then printf "example-package==1.0\\n"; fi\n'
                   f'  exit 0\nfi\nexec "{sys.executable}" "$@"\n')
    app.chmod(0o700)
    scanner = tmp_path / "pip-audit"
    payload = clean_report()
    if mode == "skip":
        payload["dependencies"][0]["skip_reason"] = "unavailable"
    scanner.write_text(f'#!{sys.executable}\nimport pathlib, sys\n'
                       'if "--version" in sys.argv:\n    print("synthetic test scanner")\n    sys.exit(0)\n'
                       'out = pathlib.Path(sys.argv[sys.argv.index("-o") + 1])\n'
                       + (f'out.write_text({json.dumps(payload)!r})\n' if mode in {"clean", "skip", "error"} else '')
                       + ('out.write_text("")\n' if mode == "empty" else '')
                       + f'sys.exit({2 if mode == "error" else 0})\n')
    scanner.chmod(0o700)
    output = tmp_path / "result"
    if mode == "stale":
        output.mkdir()
        (output / "audit.json").write_text(json.dumps(clean_report()))
    result = subprocess.run(["bash", str(ROOT / "scripts/ci/audit_environment.sh"),
                             str(app), str(scanner), str(output)], capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == (mode == "clean"), result.stdout + result.stderr
    if mode != "stale":
        assert (output / "audit-exit.txt").read_text().strip() == ("2" if mode == "error" else "0")


@pytest.mark.parametrize("inventory", ["python311-default-omission", "installed"])
def test_ci_audit_runner_includes_runtime_setuptools_and_installer(tmp_path, inventory):
    """Exercise the runner, not a separately constructed freeze command.

    The fake models Python 3.11's default bootstrap-package omission. The real
    mode reads this interpreter's installed inventory without changing it.
    The scanner is deliberately synthetic: this is not an advisory audit.
    """
    argv_path = tmp_path / "freeze-argv.json"
    app = tmp_path / "app-python"
    app.write_text(
        f'#!{sys.executable}\nimport json, os, pathlib, sys\n'
        'if sys.argv[1:4] == ["-m", "pip", "freeze"]:\n'
        f'    pathlib.Path({str(argv_path)!r}).write_text(json.dumps(sys.argv[1:]))\n'
        f'    if {inventory!r} == "python311-default-omission":\n'
        '        print("example-package==1.0")\n'
        '        if "--all" in sys.argv:\n'
        f'            print("setuptools=={version("setuptools")}")\n'
        f'            print("pip=={version("pip")}")\n'
        '        sys.exit(0)\n'
        f'if {inventory!r} != "installed" and sys.argv[1:4] == ["-m", "pip", "check"]:\n'
        '    sys.exit(0)\n'
        f'os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n'
    )
    app.chmod(0o700)
    scanner = tmp_path / "synthetic-scanner"
    scanner.write_text(
        f'#!{sys.executable}\nimport json, pathlib, sys\n'
        'if "--version" in sys.argv:\n'
        '    print("synthetic inventory-only scanner")\n    sys.exit(0)\n'
        'freeze = pathlib.Path(sys.argv[sys.argv.index("-r") + 1]).read_text()\n'
        'dependencies = []\n'
        'for line in freeze.splitlines():\n'
        '    name, version = line.split("==")\n'
        '    dependencies.append({"name": name, "version": version, "vulns": []})\n'
        'pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text(\n'
        '    json.dumps({"dependencies": dependencies, "fixes": []}))\n'
    )
    scanner.chmod(0o700)
    output = tmp_path / "result"
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/ci/audit_environment.sh"), str(app), str(scanner), str(output)],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    frozen = (output / "freeze.txt").read_text().splitlines()
    assert f"setuptools=={version('setuptools')}" in frozen
    assert f"pip=={version('pip')}" in frozen
    assert json.loads(argv_path.read_text()) == ["-m", "pip", "freeze", "--all"]
    audited = json.loads((output / "audit.json").read_text())["dependencies"]
    assert {f"{item['name']}=={item['version']}" for item in audited} == set(frozen)


def test_ci_retained_inventories_include_runtime_and_installer():
    lines = (ROOT / ".github/workflows/ci.yml").read_text().splitlines()
    commands = [shlex.split(line.strip()) for line in lines if "-m pip freeze" in line]
    assert len(commands) == 2  # unit matrix and browser installation evidence
    for command in commands:
        args = command[1:command.index(">")]
        result = subprocess.run([sys.executable, *args], capture_output=True, text=True,
                                check=False, timeout=30)
        assert result.returncode == 0, result.stderr
        assert f"setuptools=={version('setuptools')}" in result.stdout.splitlines()
        assert f"pip=={version('pip')}" in result.stdout.splitlines()
        assert args == ["-m", "pip", "freeze", "--all"]


def test_ci_bootstraps_every_new_application_and_tool_environment():
    lines = (ROOT / ".github/workflows/ci.yml").read_text().splitlines()
    environments = []
    for index, line in enumerate(lines):
        if not line.strip().startswith("python -m venv "):
            continue
        command = shlex.split(line.strip())
        environment = command[3]
        environments.append(environment)
        assert shlex.split(lines[index + 1].strip()) == [
            environment + "/bin/python", "-m", "pip", "install", "-r", "requirements-bootstrap.txt",
        ]
    assert len(environments) == 6
