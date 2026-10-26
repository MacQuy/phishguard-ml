from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from phishguard.features import features_frame

# Structured audit logger — writes one JSON line per prediction to stdout.
# In production, pipe stdout to your SIEM / log aggregator.
_audit = logging.getLogger("phishguard.audit")
if not _audit.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _audit.addHandler(_handler)
    _audit.setLevel(logging.INFO)
    _audit.propagate = False


def _emit_audit(event: str, **fields) -> None:
    """Write a structured JSON audit record to the audit logger."""
    record = {"ts": time.time(), "event": event, **fields}
    _audit.info(json.dumps(record, default=str))


MODEL_PATH = Path(os.getenv("PHISHGUARD_MODEL_PATH", "artifacts/model.joblib"))
API_KEY = os.getenv("PHISHGUARD_API_KEY", "")
MAX_REQUESTS_PER_MINUTE = int(os.getenv("PHISHGUARD_RATE_LIMIT_PER_MINUTE", "60"))
app = FastAPI(title="PhishGuard ML API", version="1.0.0", docs_url="/docs", redoc_url=None)
_model_bundle = None
_request_buckets: dict[str, list[float]] = {}

class PredictionRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096, examples=["http://secure-login-example.test/account"])

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL must not be empty")
        return value

class PredictionResponse(BaseModel):
    url: str
    prediction: Literal["phishing", "legitimate"]
    phishing_probability: float = Field(ge=0, le=1)
    model_version: str
    request_id: str
    disclaimer: str = "Prediction is a risk signal, not a guarantee of URL safety."

def get_bundle():
    global _model_bundle
    if _model_bundle is None:
        if not MODEL_PATH.is_file():
            raise HTTPException(status_code=503, detail="Model artifact missing. Run the training command first.")
        try:
            _model_bundle = joblib.load(MODEL_PATH)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Model artifact could not be loaded.") from exc
    return _model_bundle

def authenticate(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if len(API_KEY) < 24 and os.getenv("PHISHGUARD_ALLOW_INSECURE_DEV_KEY", "0") != "1":
        raise HTTPException(status_code=503, detail="Configure a PHISHGUARD_API_KEY with at least 24 characters.")
    if not x_api_key or not hmac.compare_digest(x_api_key, API_KEY):
        _emit_audit("auth_failure", reason="invalid_or_missing_api_key")
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

def rate_limit(request: Request) -> None:
    now = time.time()
    client = request.client.host if request.client else "unknown"
    # Hash the IP so we log an identifier without storing raw addresses
    client_hash = hashlib.sha256(client.encode()).hexdigest()[:12]
    recent = [t for t in _request_buckets.get(client, []) if now - t < 60]
    if len(recent) >= MAX_REQUESTS_PER_MINUTE:
        _emit_audit("rate_limit_exceeded", client_hash=client_hash, requests_in_window=len(recent))
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    recent.append(now)
    _request_buckets[client] = recent

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_loaded": _model_bundle is not None or MODEL_PATH.is_file()}

@app.get("/ready")
def readiness() -> dict:
    bundle = get_bundle()
    return {"status": "ready", "model_version": bundle.get("model_version", "unknown"),
            "artifact_sha256": hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()}

@app.post("/predict", response_model=PredictionResponse, dependencies=[Depends(authenticate), Depends(rate_limit)])
def predict(payload: PredictionRequest, request: Request) -> PredictionResponse:
    client = request.client.host if request.client else "unknown"
    client_hash = hashlib.sha256(client.encode()).hexdigest()[:12]
    request_id = hashlib.sha256(f"{time.time_ns()}:{payload.url}".encode()).hexdigest()[:16]

    try:
        features = features_frame([payload.url])
    except ValueError as exc:
        _emit_audit(
            "predict_rejected",
            request_id=request_id,
            client_hash=client_hash,
            reason="invalid_url",
            detail=str(exc),
        )
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    bundle = get_bundle()
    model = bundle["model"]
    t0 = time.perf_counter()
    predicted = int(model.predict(features)[0])
    probabilities = model.predict_proba(features)[0]
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    classes = list(model.classes_)
    phishing_probability = float(probabilities[classes.index(0)])
    label = "phishing" if predicted == 0 else "legitimate"

    # Audit log: hash the URL to avoid storing raw user data in logs.
    # The full URL is available in the application request log if needed.
    url_hash = hashlib.sha256(payload.url.encode()).hexdigest()[:16]
    _emit_audit(
        "prediction",
        request_id=request_id,
        client_hash=client_hash,
        url_hash=url_hash,
        url_length=len(payload.url),
        prediction=label,
        phishing_probability=round(float(np.clip(phishing_probability, 0, 1)), 6),
        model_version=bundle.get("model_version", "unknown"),
        inference_ms=latency_ms,
    )

    return PredictionResponse(
        url=payload.url,
        prediction=label,
        phishing_probability=round(float(np.clip(phishing_probability, 0, 1)), 6),
        model_version=bundle.get("model_version", "unknown"),
        request_id=request_id,
    )
