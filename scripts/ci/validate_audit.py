"""Validate pip-audit JSON against the exact installed-package freeze."""
import json
from pathlib import Path
import sys
import re


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def validate(report_path, freeze_path, status):
    if status != 0:
        raise ValueError(f"pip-audit failed with exit {status}")
    report = json.loads(Path(report_path).read_text())
    if not isinstance(report, dict) or set(report) != {"dependencies", "fixes"} or report["fixes"] != []:
        raise ValueError("unexpected report schema, errors or fixes")
    expected = {}
    for line in Path(freeze_path).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;]+)", line)
        if not match:
            raise ValueError(f"not an exact package pin: {line}")
        name, version = match.groups()
        name = normalize(name)
        if name in expected:
            raise ValueError("duplicate installed package")
        expected[name] = version
    if not expected:
        raise ValueError("empty installed inventory")
    dependencies = report["dependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("missing or empty dependencies")
    actual = {}
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {"name", "version", "vulns"}:
            raise ValueError("skipped package or malformed dependency")
        if dependency["vulns"] != []:
            raise ValueError("vulnerabilities or missing vulnerability result")
        name = normalize(dependency["name"])
        if name in actual:
            raise ValueError("duplicate audited package")
        actual[name] = dependency["version"]
    if actual != expected:
        raise ValueError("audit does not match complete installed inventory")
    print(f"audited {len(dependencies)} pinned packages")


if __name__ == "__main__":
    try:
        validate(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        print(f"audit rejected: {exc}", file=sys.stderr)
        sys.exit(1)
