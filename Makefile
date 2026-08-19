PYTHON := python3
PIP := pip3
RUFF := $(shell command -v ruff 2>/dev/null || echo /tmp/ruff_venv/bin/ruff)

.PHONY: install test run lint

install:
	$(PIP) install -r requirements.txt

test:
	$(PYTHON) -m pytest -q tests

run:
	$(PYTHON) dns_monitor.py

lint:
	"$(RUFF)" check .
