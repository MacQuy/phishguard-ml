# PhishGuard ML

A portfolio-grade MLSecOps project for phishing URL classification. The repository combines a real ML training pipeline, model artifact integrity metadata, MLflow experiment tracking, an authenticated FastAPI inference service, CI security checks, and a metric-based release gate.

## CI status

Latest pipeline: **all checks passed** (2026-10-26, Python 3.12.15, scikit-learn 1.9.1)

| Step | Result |
|---|---|
| Lint (Ruff) | ✅ pass |
| Unit + API tests | ✅ 57 passed |
| Adversarial robustness tests | ✅ 31 passed |
| Bandit SAST | ✅ no issues |
| Dependency audit (pip-audit) | ✅ no vulnerabilities |
| SBOM generation (CycloneDX 1.5) | ✅ 139 components |
| Secret scan (Gitleaks 8.24.3) | ✅ 0 findings |
| Model training | ✅ 235,366 URLs, 14.5 s |
| ML release gate | ✅ all thresholds met |
| Feature drift check | ✅ minor\_drift, 0 features above threshold |

## Model performance (CI-verified, commit `f327cd6`)

| Metric | Value |
|---|---|
| Accuracy | 99.56% |
| Phishing precision | 99.86% |
| Phishing recall | 99.10% |
| Phishing F1 | 99.48% |
| ROC-AUC | 99.77% |
| Train rows | 188,292 |
| Test rows | 47,074 |
| Invalid URLs skipped | 4 |
| Training time | 14.51 s |
| Model SHA-256 | `b65f854…` |
| Dataset SHA-256 | `cb4e29f…` |

Confusion matrix (phishing = positive class):

```
               Predicted phishing   Predicted legitimate
Actual phishing        19,924                  180
Actual legitimate          27               26,943
```

Top 5 features by importance:

| Feature | Importance |
|---|---|
| is\_https | 41.50% |
| slash\_count | 17.94% |
| path\_length | 14.14% |
| digit\_ratio | 5.57% |
| url\_length | 5.13% |

## Supply-chain artifacts (uploaded on every CI run)

- `reports/training_report.json` — full metrics, feature importance, SHA-256 hashes, MLflow run ID, sklearn version
- `reports/drift_report.json` — PSI per feature, overall drift status
- `reports/sbom.json` — CycloneDX 1.5 SBOM, 139 components, serial `urn:uuid:f3224663-…`
- `gitleaks-results.sarif` — 0 secret findings

## What it demonstrates

- **Data pipeline:** reads the included PhiUSIIL dataset, validates labels/URLs, removes duplicate URLs, and uses a stratified holdout split.
- **Inference-consistent features:** trains only on features that can be extracted from the submitted URL. Website-content-only features are intentionally excluded.
- **Model training:** Random Forest classifier, fixed random seed, accuracy, phishing precision/recall/F1, ROC-AUC, confusion matrix, and feature importance.
- **Supply-chain metadata:** SHA-256 hashes for the raw dataset and model artifact, Python/scikit-learn versions, and MLflow run ID.
- **Release gate:** fails if accuracy, phishing recall, phishing precision, or integrity metadata do not meet configured thresholds.
- **API controls:** API key with constant-time comparison, URL validation, per-IP in-memory rate limiting, health/readiness endpoints.
- **Structured audit log:** every prediction, auth failure, and rate-limit hit is emitted as a JSON line to stdout — ready for SIEM ingestion. IP addresses are hashed; URLs are hash-referenced, not stored raw.
- **Adversarial robustness tests:** 31 test cases covering IP-literal hosts, IDN homograph/punycode attacks, @-sign credential embedding, percent-encoding obfuscation, deep subdomain chains, scheme injection (`javascript:`, `data:`, `ftp:`), HTTP header injection via control characters, and URL padding evasion.
- **Feature drift monitor:** PSI-based drift detection compares any new batch of URLs against the training feature distribution. Flags minor drift (PSI 0.10–0.25) and major drift (PSI > 0.25) per feature. CI-verified: 2000-URL random sample from training data returns `minor_drift`, 0 features above threshold.
- **SBOM generation:** CycloneDX 1.5 Software Bill of Materials, 139 components, generated and uploaded as a CI artifact on every run.
- **Secret scanning:** Gitleaks 8.24.3, 0 findings on latest commit.
- **CI security:** Ruff lint, 57 unit/API tests, 31 adversarial tests, Bandit SAST, pip-audit, Gitleaks, SBOM, training, ML release gate, drift check.
- **Container hardening:** non-root user, read-only filesystem, dropped Linux capabilities, no-new-privileges, localhost-only port binding by default.

## Dataset and label meaning

Dataset: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (235,795 rows). Label `0 = phishing`, `1 = legitimate`. The training script uses only the `URL` and `label` columns and calculates URL-only features to ensure the deployed API can use the same feature schema.

This project is a research/portfolio demonstration, not a production threat-intelligence service. The model cannot inspect live page content, DNS, TLS certificates, redirects, or reputation feeds. A prediction must not be treated as a guarantee that a URL is safe.

## Requirements

- Python 3.12 recommended (3.11 also supported)
- Ubuntu/Linux, 4 GB+ RAM
- Docker optional

## Quick start (Ubuntu)

```bash
cd phishguard-ml
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
export MLFLOW_ALLOW_FILE_STORE=true
```

## Run the full pipeline

```bash
python -m phishguard.training
python -m phishguard.security_gate
pytest -q
pytest tests/test_adversarial.py -v
ruff check src tests
bandit -r src -ll
pip-audit -r requirements.txt
```

## Feature drift monitor

```bash
# One URL per line
python -m phishguard.drift_monitor --urls /path/to/recent_urls.txt

# Custom threshold + save report
python -m phishguard.drift_monitor \
  --urls /path/to/recent_urls.txt \
  --threshold 0.25 \
  --output reports/drift_report.json
```

Exit code 0 = stable or minor drift, 1 = major drift (PSI above threshold).

## Audit log format

One JSON line per event to stdout:

```json
{"ts": 1761566862.1, "event": "prediction", "request_id": "a1b2c3d4e5f6a7b8",
 "client_hash": "3f2a1b9c0e4d", "url_hash": "f1e2d3c4b5a6",
 "url_length": 42, "prediction": "phishing", "phishing_probability": 0.94,
 "model_version": "1.0.0", "inference_ms": 3.21}
```

Events: `prediction`, `predict_rejected`, `auth_failure`, `rate_limit_exceeded`.
IP addresses and URLs are hashed — raw values are never written to the audit log.

## SBOM

```bash
cyclonedx-py environment --output-format JSON -o reports/sbom.json
```

CycloneDX 1.5 format, 139 components. Uploaded as `phishguard-ml-reports` artifact on every CI run. Consumable by Dependency-Track or any CycloneDX-compatible tool.

## Run API locally

```bash
export PHISHGUARD_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn phishguard.api:app --reload
```

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/ready
curl -s -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PHISHGUARD_API_KEY" \
  -d '{"url":"http://paypal-secure-login-verify.com/account"}' | python3 -m json.tool
```

Swagger UI: `http://127.0.0.1:8000/docs`

## Docker

```bash
cp .env.example .env
echo "PHISHGUARD_API_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" > .env
docker compose up --build
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PHISHGUARD_API_KEY` | — (required) | API authentication |
| `PHISHGUARD_MODEL_PATH` | `artifacts/model.joblib` | Model artifact path |
| `PHISHGUARD_RATE_LIMIT_PER_MINUTE` | `60` | Per-IP request limit |
| `PHISHGUARD_MIN_ACCURACY` | `0.90` | Release gate threshold |
| `PHISHGUARD_MIN_PHISHING_RECALL` | `0.90` | Release gate threshold |
| `PHISHGUARD_MIN_PHISHING_PRECISION` | `0.85` | Release gate threshold |
| `MLFLOW_ALLOW_FILE_STORE` | — | Set `true` for local file-based MLflow tracking |

## Project layout

```text
phishguard-ml/
├── .github/workflows/ci.yml
├── .gitleaks.toml
├── data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
├── src/phishguard/
│   ├── api.py              ← FastAPI service + structured audit log
│   ├── drift_monitor.py    ← PSI-based feature drift detection
│   ├── features.py
│   ├── security_gate.py
│   └── training.py         ← embeds feature_baseline_stats for drift monitor
├── tests/
│   ├── test_adversarial.py ← 31 evasion technique tests
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

## CI behavior

GitHub Actions runs on every push and pull request. The pipeline fails closed if any check fails — lint error, test failure, SAST finding, dependency vulnerability, ML metric below threshold, or secret detected. Training uses `MLFLOW_ALLOW_FILE_STORE=true` for file-based experiment tracking in CI. All reports are uploaded as the `phishguard-ml-reports` artifact and retained for 90 days.
