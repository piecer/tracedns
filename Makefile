PYTHON := python3
PIP := pip3

.PHONY: install test run lint

install:
	$(PIP) install -r requirements.txt

run:
	$(PYTHON) dns_monitor.py

lint:
	@echo "No linter configured. Install and run your preferred linter."
