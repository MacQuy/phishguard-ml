.PHONY: install test adversarial lint security train gate drift sbom api

install:
	python -m pip install -r requirements-dev.txt
	python -m pip install -e .

test:
	pytest -q

adversarial:
	pytest tests/test_adversarial.py -v

lint:
	ruff check src tests

security:
	bandit -r src -ll
	pip-audit -r requirements.txt

train:
	python -m phishguard.training

gate:
	python -m phishguard.security_gate

drift:
	python -m phishguard.drift_monitor --urls $(URLS) --output reports/drift_report.json

sbom:
	cyclonedx-py environment --output-format JSON -o reports/sbom.json

api:
	uvicorn phishguard.api:app --reload
