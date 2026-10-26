from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import mlflow
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             precision_score, recall_score, f1_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from phishguard.features import FEATURE_NAMES, extract_url_features, features_frame
from phishguard.drift_monitor import compute_baseline_stats

ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = ROOT / "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
ARTIFACT_DIR = ROOT / "artifacts"
REPORT_DIR = ROOT / "reports"

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def train(data_path: Path = DATA_PATH, model_path: Path | None = None) -> dict:
    started = time.time()
    if not data_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {data_path}")
    frame = pd.read_csv(data_path, usecols=["URL", "label"], low_memory=False)
    frame = frame.dropna(subset=["URL", "label"]).copy()
    frame["URL"] = frame["URL"].astype(str)
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    frame = frame.dropna(subset=["label"])
    frame = frame[frame["label"].isin([0, 1])]
    frame = frame.drop_duplicates(subset=["URL"]).reset_index(drop=True)
    if len(frame) < 100 or frame["label"].nunique() != 2:
        raise ValueError("Dataset must contain at least 100 unique URLs and both labels 0 and 1")
    feature_rows = []
    labels = []
    invalid_rows = 0
    for url, label in zip(frame["URL"], frame["label"].astype(int)):
        try:
            feature_rows.append(extract_url_features(url))
        except ValueError:
            invalid_rows += 1
            continue
        labels.append(label)
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = pd.Series(labels, dtype="int64")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=250, max_depth=24, min_samples_leaf=2,
        class_weight="balanced_subsample", random_state=42, n_jobs=-1
    )
    mlflow.set_tracking_uri((ROOT / ".mlflow").as_uri())
    mlflow.set_experiment("phishguard-ml")
    with mlflow.start_run() as run:
        model.fit(X_train, y_train)
        predicted = model.predict(X_test)
        probabilities = model.predict_proba(X_test)
        classes = list(model.classes_)
        phishing_index = classes.index(0)
        phishing_truth = (y_test == 0).astype(int)
        phishing_pred = (predicted == 0).astype(int)
        metrics = {
            "accuracy": float(accuracy_score(y_test, predicted)),
            "phishing_precision": float(precision_score(phishing_truth, phishing_pred, zero_division=0)),
            "phishing_recall": float(recall_score(phishing_truth, phishing_pred, zero_division=0)),
            "phishing_f1": float(f1_score(phishing_truth, phishing_pred, zero_division=0)),
            "roc_auc_phishing": float(roc_auc_score(phishing_truth, probabilities[:, phishing_index])),
            "test_rows": int(len(y_test)),
            "train_rows": int(len(y_train)),
            "dataset_rows_after_cleaning": int(len(y)),
            "invalid_urls_skipped": int(invalid_rows),
            "features_count": len(FEATURE_NAMES),
            "confusion_matrix_labels_phishing_then_legitimate": confusion_matrix(
                (y_test == 0).astype(int), (predicted == 0).astype(int), labels=[1, 0]
            ).tolist(),
        }
        mlflow.log_params({"model": "RandomForestClassifier", "n_estimators": 250, "max_depth": 24,
                           "random_state": 42, "feature_count": len(FEATURE_NAMES)})
        mlflow.log_metrics({k: v for k, v in metrics.items() if isinstance(v, (int, float))})
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        model_path = model_path or ARTIFACT_DIR / "model.joblib"
        joblib.dump({"model": model, "feature_names": FEATURE_NAMES, "model_version": "1.0.0",
                     "label_mapping": {"0": "phishing", "1": "legitimate"}}, model_path)
        report = {
            "project": "PhishGuard ML", "created_at": datetime.now(timezone.utc).isoformat(),
            "model_version": "1.0.0", "dataset_file": data_path.name,
            "dataset_sha256": sha256_file(data_path), "model_sha256": sha256_file(model_path),
            "python_version": platform.python_version(), "sklearn_version": __import__("sklearn").__version__,
            "mlflow_run_id": run.info.run_id, "feature_names": FEATURE_NAMES, "metrics": metrics,
            "classification_report": classification_report(y_test, predicted, output_dict=True, zero_division=0),
            "feature_importance": sorted(
                [{"feature": name, "importance": float(value)} for name, value in zip(FEATURE_NAMES, model.feature_importances_)],
                key=lambda item: item["importance"], reverse=True
            ),
            "training_seconds": round(time.time() - started, 2),
            "feature_baseline_stats": compute_baseline_stats(X_train),
        }
        (REPORT_DIR / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"model_path": str(model_path), "report_path": str(REPORT_DIR / 'training_report.json'),
                          "metrics": metrics, "model_sha256": report["model_sha256"]}, indent=2))
        return report

def main() -> None:
    parser = argparse.ArgumentParser(description="Train PhishGuard URL classifier")
    parser.add_argument("--data", type=Path, default=DATA_PATH)
    parser.add_argument("--model", type=Path, default=None)
    args = parser.parse_args()
    train(args.data, args.model)

if __name__ == "__main__":
    main()
