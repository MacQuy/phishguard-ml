# PhishGuard ML

A portfolio-grade MLSecOps project for phishing URL classification. The repository combines a real ML training pipeline, model artifact integrity metadata, MLflow experiment tracking, an authenticated FastAPI inference service, CI security checks, and a metric-based release gate.

## What it demonstrates

- **Data pipeline:** reads the included PhiUSIIL dataset, validates labels/URLs, removes duplicate URLs, and uses a stratified holdout split.
- **Inference-consistent features:** trains only on features that can be extracted from the submitted URL. Website-content-only features are intentionally excluded.
- **Model training:** Random Forest classifier, fixed random seed, accuracy, phishing precision/recall/F1, ROC-AUC, confusion matrix, and feature importance.
- **Supply-chain metadata:** SHA-256 hashes for the raw dataset and model artifact, Python/scikit-learn versions, and MLflow run ID.
- **Release gate:** fails if accuracy, phishing recall, phishing precision, or integrity metadata do not meet configured thresholds.
- **API controls:** API key, constant-time key comparison, URL validation, simple per-IP in-memory rate limiting, health/readiness endpoints.
- **Structured audit log:** every prediction, auth failure, and rate-limit hit is emitted as a JSON line to stdout — ready for SIEM ingestion. IP addresses are hashed; URLs are hash-referenced, not stored raw.
- **Adversarial robustness tests:** 30+ test cases covering IP-literal hosts, IDN homograph/punycode attacks, @-sign credential embedding, percent-encoding obfuscation, deep subdomain chains, scheme injection (javascript:, data:, ftp:), HTTP header injection via control characters, and URL padding evasion.
- **Feature drift monitor:** PSI-based (Population Stability Index) drift detection compares any new batch of URLs against the training feature distribution. Flags minor drift (PSI 0.10–0.25) and major drift (PSI > 0.25) per feature. Integrated into CI as a post-training health check.
- **SBOM generation:** CycloneDX Software Bill of Materials is generated and uploaded as a CI artifact on every run, enabling supply-chain audits and licence compliance checks.
- **CI security:** tests, adversarial tests, Ruff, Bandit, pip-audit, Gitleaks, SBOM, training, ML release gate, and drift check.
- **Container hardening:** non-root user, read-only filesystem, dropped Linux capabilities, no-new-privileges, localhost-only port binding by default.

## Dataset and label meaning

Dataset: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (235,795 rows in the supplied archive). The dataset's `label` is interpreted as `0 = phishing` and `1 = legitimate`, consistent with the included sample rows. The training script uses the `URL` and `label` columns and calculates its own URL-only features to ensure the deployed API can use the same feature schema.

The project is a research/portfolio demonstration, not a production-grade threat-intelligence service. The model cannot inspect live page content, DNS, TLS certificates, redirects, or reputation feeds. A prediction must not be treated as a guarantee that a URL is safe.

## Requirements

- Python 3.11 or 3.12 recommended
- Ubuntu/Linux, 4 GB+ RAM recommended
- Docker optional

## Quick start (Ubuntu)

```bash
cd phishguard-ml
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
```

If the supplied CSV is not present, put it at `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`.

## Run the full pipeline

```bash
python -m phishguard.training
python -m phishguard.security_gate
pytest -q
pytest tests/test_adversarial.py -v   # adversarial evasion tests
ruff check src tests
bandit -r src -ll
pip-audit -r requirements.txt
```

## Feature drift monitor

After training, run the drift monitor against any batch of URLs to detect
distribution shift between training data and production traffic:

```bash
# One URL per line in a plain-text file
python -m phishguard.drift_monitor --urls /path/to/recent_urls.txt

# Custom PSI threshold and save report
python -m phishguard.drift_monitor \
  --urls /path/to/recent_urls.txt \
  --threshold 0.20 \
  --output reports/drift_report.json
```

Exit code 0 = stable, 1 = major drift detected (PSI above threshold).

## Audit log format

The API emits one JSON line per event to stdout. Example:

```json
{"ts": 1700000000.123, "event": "prediction", "request_id": "a1b2c3d4e5f6a7b8",
 "client_hash": "3f2a1b9c0e4d", "url_hash": "f1e2d3c4b5a6",
 "url_length": 42, "prediction": "phishing", "phishing_probability": 0.94,
 "model_version": "1.0.0", "inference_ms": 3.21}
```

Events: `prediction`, `predict_rejected`, `auth_failure`, `rate_limit_exceeded`.
IP addresses and URLs are hashed — raw values are never written to the audit log.

## SBOM

A CycloneDX SBOM is generated on every CI run:

```bash
cyclonedx-py environment --output-format JSON -o reports/sbom.json
```

The SBOM is uploaded as a GitHub Actions artifact (`phishguard-ml-reports`)
and can be consumed by Dependency-Track or any CycloneDX-compatible tool.

Training creates `artifacts/model.joblib`, `reports/training_report.json`, and local MLflow metadata under `.mlflow/`. Training takes longer than unit tests because the dataset has more than 200k rows. `joblib` model files are trusted local artifacts only; do not load artifacts from untrusted sources.

## Run API locally

Set a non-default API key before starting the API.

```bash
export PHISHGUARD_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn phishguard.api:app --reload
```

In another terminal:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/ready
curl -X POST http://127.0.0.1:8000/predict \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $PHISHGUARD_API_KEY" \
  -d '{"url":"http://secure-login-example.test/account"}'
```

Swagger UI: `http://127.0.0.1:8000/docs`. Never expose this demo publicly without TLS termination, a proper secrets manager, distributed rate limiting, structured audit logs, monitoring, and production deployment review.

## Docker

After training and setting `PHISHGUARD_API_KEY` in your shell or `.env` file:

```bash
docker compose up --build
```

The compose configuration binds to `127.0.0.1` by default.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PHISHGUARD_API_KEY` | insecure development placeholder (API refuses it unless explicitly allowed) | API authentication |
| `PHISHGUARD_MODEL_PATH` | `artifacts/model.joblib` | Model artifact path |
| `PHISHGUARD_RATE_LIMIT_PER_MINUTE` | `60` | In-memory per-IP request limit |
| `PHISHGUARD_MIN_ACCURACY` | `0.90` | Minimum release accuracy |
| `PHISHGUARD_MIN_PHISHING_RECALL` | `0.90` | Minimum phishing recall |
| `PHISHGUARD_MIN_PHISHING_PRECISION` | `0.85` | Minimum phishing precision |

## CI behavior

GitHub Actions runs lint, tests, Bandit, dependency audit, secret scanning, model training, and the ML release gate. The pipeline intentionally fails closed if a metric gate fails or a dependency vulnerability is reported. Review tool output and pin/upgrade dependencies as part of maintenance; a green workflow is evidence for this commit, not proof of zero risk.

## Project layout

```text
phishguard-ml/
├── .github/workflows/ci.yml
├── data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
├── src/phishguard/
│   ├── api.py              ← FastAPI service + structured audit log
│   ├── drift_monitor.py    ← PSI-based feature drift detection
│   ├── features.py
│   ├── security_gate.py
│   └── training.py         ← embeds feature_baseline_stats for drift monitor
├── tests/
│   ├── test_adversarial.py ← 30+ evasion technique tests
│   ├── test_api.py
│   ├── test_drift_monitor.py
│   └── test_features.py
├── artifacts/
├── reports/                ← training_report.json, drift_report.json, sbom.json
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── requirements.txt
└── README.md
```

## Portfolio metrics to report

After training, use the generated report to publish: phishing precision/recall/F1, ROC-AUC, confusion matrix, number of URLs used, training duration, artifact SHA-256, CI pass/fail, and API latency measured locally. Never claim metrics before running the pipeline on the committed dataset.
