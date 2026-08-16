"""Risk scoring over topology, telemetry, and attack-path evidence."""

from dataclasses import dataclass

from digital_twin.attacks import get_scenario
from digital_twin.telemetry import TelemetryEvent, top_anomalies
from digital_twin.topology import DigitalTwin


@dataclass(frozen=True)
class AssetRisk:
    asset_id: str
    risk: float
    criticality: float
    anomaly: float
    connectivity: float
    scenario_exposure: float
    reasons: tuple[str, ...]


def score_assets(twin: DigitalTwin, events: list[TelemetryEvent], scenario: str) -> list[AssetRisk]:
    scenario_assets = {step.asset_id for step in get_scenario(scenario)}
    anomaly_by_asset: dict[str, float] = {}
    for event, score in top_anomalies(events, limit=len(events)):
        anomaly_by_asset[event.source] = max(anomaly_by_asset.get(event.source, 0.0), score)

    max_degree = max((len(neighbors) for neighbors in twin.edges.values()), default=1)
    results: list[AssetRisk] = []

    for asset_id, asset in twin.assets.items():
        anomaly = anomaly_by_asset.get(asset_id, 0.0)
        connectivity = len(twin.neighbors(asset_id)) / max_degree
        scenario_exposure = 1.0 if asset_id in scenario_assets else 0.0
        surface = 0.12 if asset.internet_exposed else 0.0
        privilege = 0.10 if asset.privileged else 0.0
        risk = (
            0.34 * asset.criticality
            + 0.28 * anomaly
            + 0.12 * connectivity
            + 0.16 * scenario_exposure
            + surface
            + privilege
        )
        risk = min(1.0, risk)
        reasons: list[str] = []
        if asset.criticality >= 0.9:
            reasons.append("high_criticality")
        if anomaly >= 0.6:
            reasons.append("telemetry_anomaly")
        if scenario_exposure:
            reasons.append("on_simulated_attack_path")
        if asset.privileged:
            reasons.append("privileged_surface")
        if asset.internet_exposed:
            reasons.append("internet_exposed")
        if connectivity >= 0.5:
            reasons.append("high_connectivity")
        results.append(
            AssetRisk(
                asset_id=asset_id,
                risk=round(risk, 4),
                criticality=asset.criticality,
                anomaly=round(anomaly, 4),
                connectivity=round(connectivity, 4),
                scenario_exposure=scenario_exposure,
                reasons=tuple(reasons or ["baseline_exposure"]),
            )
        )

    return sorted(results, key=lambda item: item.risk, reverse=True)


def overall_risk(asset_risks: list[AssetRisk], top_k: int = 8) -> float:
    if not asset_risks:
        return 0.0
    selected = asset_risks[:top_k]
    weights = [1.0 / (index + 1) for index in range(len(selected))]
    numerator = sum(item.risk * weight for item, weight in zip(selected, weights))
    return round(numerator / sum(weights), 4)
