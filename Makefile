PYTHON ?= $(if $(VIRTUAL_ENV),$(VIRTUAL_ENV)/bin/python3,$(if $(wildcard .venv/bin/python),.venv/bin/python,python3))
PIP := $(PYTHON) -m pip
RUFF ?= $(shell command -v ruff 2>/dev/null || true)

.PHONY: install test security-regression botnet-coverage run lint e2e

install:
	$(PIP) install -r requirements.txt

test:
	$(PYTHON) -m pytest -q tests

# Replay version-controlled evidence only: no live DNS/RPC/MISP/Teams required.
# CI executes this inside scripts/ci/loopback_only.sh to enforce that boundary.
security-regression:
	$(PYTHON) -m pytest -v -ra \
		tests/test_ens_decoder.py tests/test_ens_static_mapping.py \
		tests/test_ens_sha256_hmac_xor.py tests/test_ens_authenticated_integration.py \
		tests/test_dht_protocol_regressions.py tests/test_dht_monitor.py \
		tests/test_dht_state_regressions.py tests/test_ip_removal_grace.py \
		tests/test_reappearance_suppression.py tests/test_regex_safety.py \
		tests/test_ip_list_external_lookup_policy.py

botnet-coverage:
	@set -eu; \
	COVERAGE_FILE=.coverage.botnet; \
	export COVERAGE_FILE; \
	trap '$(PYTHON) -c '"'"'import os; p = os.environ.get("COVERAGE_FILE"); p and os.path.exists(p) and os.unlink(p)'"'"'' EXIT; \
	$(PYTHON) -m coverage run --branch --source=http_api.relationship_handlers -m pytest -q tests; \
	$(PYTHON) -m coverage report --fail-under=80 http_api/relationship_handlers.py

run:
	$(PYTHON) dns_monitor.py

e2e:
	npm ci
	npx playwright install chromium
	npm run test:e2e

lint:
	@if [ -x "$(RUFF)" ]; then \
		exec "$(RUFF)" check .; \
	else \
		echo "ruff not found; install with: pip3 install ruff" >&2; \
		exit 127; \
	fi
