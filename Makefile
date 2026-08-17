PYTHON := python3
PIP := pip3
RUFF := $(shell command -v ruff 2>/dev/null || echo /tmp/ruff_venv/bin/ruff)

.PHONY: install test run lint

install:
	$(PIP) install -r requirements.txt

test:
	PYTHONPATH=$(abspath ..) $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

run:
	$(PYTHON) dns_monitor.py

lint:
	"$(RUFF)" check .
