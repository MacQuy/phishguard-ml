from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "reports/training_report.json"

def main() -> int:
    if not REPORT.is_file():
        print("FAIL: reports/training_report.json is missing; train the model first")
        return 1
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    metrics = report.get("metrics", {})
    thresholds = {
        "accuracy": float(os.getenv("PHISHGUARD_MIN_ACCURACY", "0.90")),
        "phishing_recall": float(os.getenv("PHISHGUARD_MIN_PHISHING_RECALL", "0.90")),
        "phishing_precision": float(os.getenv("PHISHGUARD_MIN_PHISHING_PRECISION", "0.85")),
    }
    failed = []
    for name, threshold in thresholds.items():
        actual = metrics.get(name)
        status = actual is not None and actual >= threshold
        print(f"{'PASS' if status else 'FAIL'} {name}: actual={actual} threshold={threshold}")
        if not status:
            failed.append(name)
    if not report.get("model_sha256") or not report.get("dataset_sha256"):
        failed.append("artifact/dataset integrity metadata")
        print("FAIL artifact/dataset integrity metadata")
    if failed:
        print("RELEASE BLOCKED:", ", ".join(failed))
        return 1
    print("RELEASE GATE PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
