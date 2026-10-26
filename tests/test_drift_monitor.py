"""
Unit tests for the feature drift monitor.

Tests PSI calculation logic and run_drift_check() behaviour without
requiring a trained model or training report on disk.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from phishguard.drift_monitor import (
    BaselineStats,
    _classify_psi,
    _psi_for_feature,
    compute_baseline_stats,
    run_drift_check,
)
from phishguard.features import FEATURE_NAMES

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_baseline(n: int = 500, seed: int = 0) -> BaselineStats:
    """Build a baseline from actual URL feature extraction so distributions match."""
    from phishguard.features import extract_url_features
    urls = [f"https://example{i}.com/page?q={i}" for i in range(n)]
    rows = []
    for url in urls:
        try:
            rows.append(extract_url_features(url))
        except ValueError:
            pass
    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    stats = compute_baseline_stats(df)
    return BaselineStats(
        means=stats["means"],
        stds=stats["stds"],
        percentiles=stats["percentiles"],
    )


def _make_baseline_from_urls(urls: list[str]) -> BaselineStats:
    """Build baseline stats from a given list of URLs (for stable distribution tests)."""
    from phishguard.features import extract_url_features
    rows = []
    for url in urls:
        try:
            rows.append(extract_url_features(url))
        except ValueError:
            pass
    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    stats = compute_baseline_stats(df)
    return BaselineStats(
        means=stats["means"],
        stds=stats["stds"],
        percentiles=stats["percentiles"],
    )


def _legit_urls(n: int = 60) -> list[str]:
    return [f"https://example{i}.com/page?q={i}" for i in range(n)]


def _phishing_urls(n: int = 60) -> list[str]:
    return [
        f"http://192.0.2.{i % 255}/login%{i:02X}?user=admin&pass=x{'a' * 50}"
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# PSI unit tests
# ---------------------------------------------------------------------------

class TestPSI:
    def test_identical_distributions_near_zero(self):
        rng = np.random.default_rng(42)
        arr = rng.uniform(0, 1, 1000)
        psi = _psi_for_feature(arr, arr)
        assert psi < 0.01, f"Identical distributions should have PSI ≈ 0, got {psi}"

    def test_very_different_distributions_high_psi(self):
        rng = np.random.default_rng(42)
        base = rng.uniform(0, 0.1, 500)
        curr = rng.uniform(0.9, 1.0, 500)
        psi = _psi_for_feature(base, curr)
        assert psi > 0.25, f"Very different distributions should have PSI > 0.25, got {psi}"

    def test_psi_is_non_negative(self):
        rng = np.random.default_rng(0)
        a = rng.normal(0, 1, 200)
        b = rng.normal(0.5, 1, 200)
        psi = _psi_for_feature(a, b)
        assert psi >= 0.0


class TestClassifyPSI:
    def test_stable(self):
        assert _classify_psi(0.05) == "stable"

    def test_minor_drift(self):
        assert _classify_psi(0.15) == "minor_drift"

    def test_major_drift(self):
        assert _classify_psi(0.30) == "major_drift"

    def test_boundary_stable_to_minor(self):
        assert _classify_psi(0.10) == "minor_drift"

    def test_boundary_minor_to_major(self):
        assert _classify_psi(0.25) == "major_drift"


# ---------------------------------------------------------------------------
# run_drift_check tests
# ---------------------------------------------------------------------------

class TestRunDriftCheck:
    def test_stable_urls_return_stable_status(self):
        urls = _legit_urls(200)
        baseline = _make_baseline_from_urls(urls)
        result = run_drift_check(urls, baseline)
        assert result["overall_status"] in {"stable", "minor_drift"}
        assert result["urls_evaluated"] >= 30

    def test_result_has_required_keys(self):
        baseline = _make_baseline()
        result = run_drift_check(_legit_urls(60), baseline)
        for key in ("overall_status", "psi_threshold", "urls_evaluated", "features"):
            assert key in result, f"Missing key: {key}"

    def test_feature_list_contains_all_features(self):
        baseline = _make_baseline()
        result = run_drift_check(_legit_urls(60), baseline)
        returned = {r["feature"] for r in result["features"]}
        expected = set(FEATURE_NAMES)
        assert expected == returned

    def test_too_few_urls_raises(self):
        baseline = _make_baseline()
        with pytest.raises(ValueError, match="30"):
            run_drift_check(_legit_urls(10), baseline)

    def test_invalid_urls_counted_as_skipped(self):
        baseline = _make_baseline()
        urls = _legit_urls(60) + ["javascript:alert(1)", "not-a-url", ""]
        result = run_drift_check(urls, baseline)
        assert result["urls_skipped"] >= 2

    def test_all_invalid_urls_raises(self):
        baseline = _make_baseline()
        bad_urls = ["javascript:alert(1)"] * 50
        with pytest.raises(ValueError):
            run_drift_check(bad_urls, baseline)


# ---------------------------------------------------------------------------
# compute_baseline_stats
# ---------------------------------------------------------------------------

class TestComputeBaselineStats:
    def test_returns_all_features(self):
        rng = np.random.default_rng(1)
        df = pd.DataFrame({f: rng.uniform(0, 1, 100) for f in FEATURE_NAMES})
        stats = compute_baseline_stats(df)
        assert set(stats["means"]) == set(FEATURE_NAMES)
        assert set(stats["stds"]) == set(FEATURE_NAMES)
        assert set(stats["percentiles"]) == set(FEATURE_NAMES)

    def test_percentiles_has_101_points(self):
        rng = np.random.default_rng(2)
        df = pd.DataFrame({f: rng.uniform(0, 1, 100) for f in FEATURE_NAMES})
        stats = compute_baseline_stats(df)
        for feat, pts in stats["percentiles"].items():
            assert len(pts) == 101, (
                f"Expected 101 percentile points for {feat}, got {len(pts)}"
            )
