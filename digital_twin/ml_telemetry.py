"""Multivariate temporal anomaly detection for synthetic data-center telemetry."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache

import numpy as np
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from .attacks import scenario_names
from .telemetry import BASELINES, TelemetryEvent, generate_normal_telemetry, inject_attack_telemetry

MODEL_NAME = "PCAReconstructionAnomalyModel"
MODEL_VERSION = "ai-dc-pca-telemetry-v1"
REFERENCE_SEEDS = tuple(range(20, 36))
METRICS = tuple(BASELINES)
FEATURE_NAMES = tuple([f"z_{name}" for name in METRICS] + [f"delta_{name}" for name in METRICS])


@dataclass(frozen=True)
class MinuteAnomaly:
    minute: int
    anomaly_percentile: float
    reconstruction_error: float
    top_contributors: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _normalized_value(event: TelemetryEvent) -> float:
    center, spread = BASELINES[event.metric]
    return (event.value - center) / spread if spread > 0 else 0.0


def minute_matrix(events: list[TelemetryEvent], minutes: int | None = None) -> np.ndarray:
    max_minute = max((event.minute for event in events), default=0)
    total = minutes if minutes is not None else max_minute + 1
    base = np.zeros((total, len(METRICS)), dtype=float)
    index = {metric: i for i, metric in enumerate(METRICS)}

    # For each minute/metric keep the observation furthest from its normal center.
    # This avoids averaging away a sharp event when multiple sources report the same metric.
    for event in events:
        if event.metric not in index or event.minute >= total:
            continue
        column = index[event.metric]
        value = _normalized_value(event)
        if abs(value) > abs(base[event.minute, column]):
            base[event.minute, column] = value

    delta = np.vstack([np.zeros((1, len(METRICS))), np.diff(base, axis=0)])
    return np.hstack([base, delta])


def _reconstruction_error(scaler: StandardScaler, pca: PCA, matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    scaled = scaler.transform(matrix)
    reconstructed = pca.inverse_transform(pca.transform(scaled))
    residual = scaled - reconstructed
    error = np.mean(residual * residual, axis=1)
    return error, residual


@lru_cache(maxsize=1)
def trained_model():
    reference = np.vstack(
        [minute_matrix(generate_normal_telemetry(seed=seed, minutes=60), minutes=60) for seed in REFERENCE_SEEDS]
    )
    scaler = StandardScaler()
    scaled = scaler.fit_transform(reference)
    pca = PCA(n_components=0.95, svd_solver="full")
    pca.fit(scaled)
    reference_error, _ = _reconstruction_error(scaler, pca, reference)
    return scaler, pca, reference_error


def score_minutes(events: list[TelemetryEvent], limit: int = 10) -> list[MinuteAnomaly]:
    scaler, pca, reference_error = trained_model()
    matrix = minute_matrix(events)
    error, residual = _reconstruction_error(scaler, pca, matrix)
    rows: list[MinuteAnomaly] = []
    for minute, value in enumerate(error):
        percentile = 100.0 * float(np.mean(reference_error <= value))
        top = np.argsort(np.abs(residual[minute]))[::-1][:4]
        contributors = tuple(FEATURE_NAMES[int(i)] for i in top if abs(residual[minute, int(i)]) >= 0.25)
        rows.append(
            MinuteAnomaly(
                minute=minute,
                anomaly_percentile=round(percentile, 1),
                reconstruction_error=round(float(value), 5),
                top_contributors=contributors,
            )
        )
    rows.sort(key=lambda row: (row.anomaly_percentile, row.reconstruction_error, row.minute), reverse=True)
    return rows[:limit]


def scenario_evaluation() -> dict[str, object]:
    results = []
    for scenario in scenario_names():
        normal = generate_normal_telemetry(seed=11, minutes=60)
        events = inject_attack_telemetry(normal, scenario)
        injected_minutes = {event.minute for event in events if event.detail}
        top = score_minutes(events, limit=8)
        ranked_minutes = {row.minute for row in top}
        overlap = sorted(injected_minutes & ranked_minutes)
        results.append(
            {
                "scenario": scenario,
                "injected_signal_minutes": sorted(injected_minutes),
                "top_ranked_overlap": overlap,
                "surfaced": bool(overlap),
                "highest_anomaly_percentile": top[0].anomaly_percentile if top else 0.0,
            }
        )
    surfaced = sum(row["surfaced"] for row in results)
    return {
        "scenarios": results,
        "surfaced": surfaced,
        "total": len(results),
        "synthetic_scenario_surface_rate": round(surfaced / len(results), 3) if results else 0.0,
        "boundary": "Synthetic scenario coverage validates the temporal ranking pipeline; it is not production attack-detection recall.",
    }


def model_report(events: list[TelemetryEvent] | None = None, limit: int = 10) -> dict[str, object]:
    scaler, pca, reference_error = trained_model()
    current = events or generate_normal_telemetry(seed=11, minutes=60)
    return {
        "model": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "reference_runs": len(REFERENCE_SEEDS),
        "features": list(FEATURE_NAMES),
        "pca_components": int(pca.n_components_),
        "explained_variance": round(float(np.sum(pca.explained_variance_ratio_)), 4),
        "reference_error_p95": round(float(np.quantile(reference_error, 0.95)), 5),
        "top_anomaly_minutes": [row.to_dict() for row in score_minutes(current, limit=limit)],
        "evaluation": scenario_evaluation(),
        "decision_boundary": "ML ranks multivariate telemetry anomalies; graph, policy, and resilience controls remain separate evidence layers.",
    }
