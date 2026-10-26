"""
Feature drift monitor for PhishGuard ML.

Compares the feature distribution of a new batch of URLs against the
training baseline stored in reports/training_report.json.

Uses Population Stability Index (PSI) — the standard metric in
model risk management for detecting input drift. PSI interpretation:
  < 0.10  → No significant drift (stable)
  0.10–0.25 → Minor drift (monitor closely)
  > 0.25  → Major drift (retrain recommended)

Usage (CLI):
    python -m phishguard.drift_monitor --urls urls.txt
    python -m phishguard.drift_monitor --urls urls.txt --threshold 0.20

Each argument to --urls is a plain-text file with one URL per line.
Exit code 0 = stable, 1 = drift detected above threshold.

Usage (library):
    from phishguard.drift_monitor import run_drift_check
    report = run_drift_check(urls, baseline_stats)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NamedTuple

import numpy as np
import pandas as pd

from phishguard.features import FEATURE_NAMES, extract_url_features

ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "reports" / "training_report.json"

# Number of equal-width bins for PSI calculation
_N_BINS = 10
# Small epsilon to avoid log(0)
_EPS = 1e-6


# ---------------------------------------------------------------------------
# PSI calculation
# ---------------------------------------------------------------------------

def _psi_for_feature(
    baseline: np.ndarray,
    current: np.ndarray,
    n_bins: int = _N_BINS,
) -> float:
    """Compute Population Stability Index between two 1-D arrays."""
    combined = np.concatenate([baseline, current])
    bin_edges = np.linspace(combined.min(), combined.max() + _EPS, n_bins + 1)

    base_counts, _ = np.histogram(baseline, bins=bin_edges)
    curr_counts, _ = np.histogram(current, bins=bin_edges)

    base_pct = base_counts / (len(baseline) + _EPS)
    curr_pct = curr_counts / (len(current) + _EPS)

    # Avoid log(0) by clipping
    base_pct = np.clip(base_pct, _EPS, None)
    curr_pct = np.clip(curr_pct, _EPS, None)

    psi = float(np.sum((curr_pct - base_pct) * np.log(curr_pct / base_pct)))
    return round(psi, 6)


# ---------------------------------------------------------------------------
# Baseline stats extraction from training report
# ---------------------------------------------------------------------------

class BaselineStats(NamedTuple):
    means: dict[str, float]
    stds: dict[str, float]
    # Raw percentile data stored per feature for bin alignment
    percentiles: dict[str, list[float]]  # 0,10,20,...,100


def load_baseline(report_path: Path = REPORT_PATH) -> BaselineStats:
    """Load feature statistics from the training report JSON."""
    if not report_path.is_file():
        raise FileNotFoundError(
            f"Training report not found at {report_path}. "
            "Run `python -m phishguard.training` first."
        )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    baseline = report.get("feature_baseline_stats")
    if not baseline:
        raise KeyError(
            "Training report does not contain 'feature_baseline_stats'. "
            "Re-run training to generate an updated report."
        )
    return BaselineStats(
        means=baseline["means"],
        stds=baseline["stds"],
        percentiles=baseline["percentiles"],
    )


# ---------------------------------------------------------------------------
# Drift check
# ---------------------------------------------------------------------------

class DriftResult(NamedTuple):
    feature: str
    psi: float
    status: str  # "stable" | "minor_drift" | "major_drift"
    baseline_mean: float
    current_mean: float


def _classify_psi(psi: float) -> str:
    if psi < 0.10:
        return "stable"
    if psi < 0.25:
        return "minor_drift"
    return "major_drift"


def run_drift_check(
    urls: list[str],
    baseline: BaselineStats,
    psi_threshold: float = 0.25,
) -> dict:
    """
    Compute per-feature PSI between baseline and a new batch of URLs.

    Returns a report dict with overall status and per-feature breakdown.
    """
    if len(urls) < 30:
        raise ValueError(
            f"Need at least 30 URLs for meaningful drift detection; got {len(urls)}."
        )

    # Extract features for the new batch
    rows = []
    skipped = 0
    for url in urls:
        try:
            rows.append(extract_url_features(url))
        except ValueError:
            skipped += 1
    if len(rows) < 30:
        raise ValueError(
            f"After filtering invalid URLs, only {len(rows)} usable rows remain "
            f"(need ≥30). Skipped {skipped} invalid URLs."
        )

    current_df = pd.DataFrame(rows, columns=FEATURE_NAMES)

    results: list[DriftResult] = []
    for feature in FEATURE_NAMES:
        if feature not in baseline.percentiles:
            continue  # Skip if baseline doesn't have this feature

        base_values = np.array(baseline.percentiles[feature], dtype=float)
        curr_values = current_df[feature].to_numpy(dtype=float)

        psi = _psi_for_feature(base_values, curr_values)
        results.append(
            DriftResult(
                feature=feature,
                psi=psi,
                status=_classify_psi(psi),
                baseline_mean=round(baseline.means.get(feature, 0.0), 6),
                current_mean=round(float(curr_values.mean()), 6),
            )
        )

    drifted = [r for r in results if r.psi >= psi_threshold]
    overall_status = "major_drift" if drifted else (
        "minor_drift" if any(r.psi >= 0.10 for r in results) else "stable"
    )

    report = {
        "overall_status": overall_status,
        "psi_threshold": psi_threshold,
        "urls_evaluated": len(rows),
        "urls_skipped": skipped,
        "features_drifted": len(drifted),
        "recommendation": (
            "Retrain recommended — feature distribution has shifted significantly."
            if overall_status == "major_drift"
            else "Monitor closely — minor drift detected."
            if overall_status == "minor_drift"
            else "Model input distribution is stable."
        ),
        "features": [
            {
                "feature": r.feature,
                "psi": r.psi,
                "status": r.status,
                "baseline_mean": r.baseline_mean,
                "current_mean": r.current_mean,
            }
            for r in sorted(results, key=lambda x: x.psi, reverse=True)
        ],
    }
    return report


# ---------------------------------------------------------------------------
# Training report patch: add baseline stats
# ---------------------------------------------------------------------------

def compute_baseline_stats(X: pd.DataFrame) -> dict:
    """
    Compute per-feature statistics to embed in the training report.
    Stores mean, std, and raw sample percentiles (0–100 in steps of 1)
    for PSI bin alignment at inference time.
    """
    percentile_points = list(range(0, 101))
    means = {}
    stds = {}
    percentiles = {}
    for col in X.columns:
        arr = X[col].to_numpy(dtype=float)
        means[col] = round(float(arr.mean()), 6)
        stds[col] = round(float(arr.std()), 6)
        percentiles[col] = [round(float(np.percentile(arr, p)), 6) for p in percentile_points]
    return {"means": means, "stds": stds, "percentiles": percentiles}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect feature drift in a new batch of URLs vs training baseline."
    )
    parser.add_argument(
        "--urls", required=True, type=Path,
        help="Plain-text file with one URL per line.",
    )
    parser.add_argument(
        "--threshold", type=float, default=0.25,
        help="PSI threshold above which drift is flagged (default: 0.25).",
    )
    parser.add_argument(
        "--report", type=Path, default=REPORT_PATH,
        help="Path to training_report.json (default: reports/training_report.json).",
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Optional path to write the drift report JSON.",
    )
    args = parser.parse_args()

    urls_text = args.urls.read_text(encoding="utf-8").splitlines()
    urls = [u.strip() for u in urls_text if u.strip()]

    try:
        baseline = load_baseline(args.report)
    except (FileNotFoundError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        result = run_drift_check(urls, baseline, psi_threshold=args.threshold)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    output_json = json.dumps(result, indent=2)
    print(output_json)

    if args.output:
        args.output.write_text(output_json, encoding="utf-8")
        print(f"\nDrift report saved to {args.output}", file=sys.stderr)

    status = result["overall_status"]
    print(f"\nDrift status: {status.upper()}", file=sys.stderr)
    if status == "major_drift":
        sys.exit(1)


if __name__ == "__main__":
    main()
