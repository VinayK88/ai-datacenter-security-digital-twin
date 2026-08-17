"""FastAPI boundary for digital-twin security simulations."""

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from digital_twin.attack_surface import trust_chokepoints
from digital_twin.attacks import scenario_names
from digital_twin.counterfactual import simulate_compromise
from digital_twin.ml_telemetry import model_report
from digital_twin.resilience import evaluate_resilience
from digital_twin.scoring import overall_risk, score_assets
from digital_twin.telemetry import generate_normal_telemetry, inject_attack_telemetry, top_anomalies
from digital_twin.topology import build_default_twin


app = FastAPI(title="AI Data Center Security Digital Twin", version="0.4.0")


class SimulationRequest(BaseModel):
    scenario: str = "bmc_compromise"
    start_asset: str = "bmc-01-02"
    max_hops: int = Field(default=3, ge=1, le=6)


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "service": "ai-datacenter-security-digital-twin"}


@app.get("/twin")
def twin_summary() -> dict[str, object]:
    twin = build_default_twin()
    return {
        "asset_count": len(twin.assets),
        "asset_types": twin.summary(),
        "scenarios": scenario_names(),
    }


@app.get("/chokepoints")
def chokepoints(limit: int = Query(default=10, ge=1, le=30)) -> dict[str, object]:
    twin = build_default_twin()
    rows = trust_chokepoints(twin, limit=limit)
    return {
        "count": len(rows),
        "chokepoints": [
            {
                "asset_id": row.asset_id,
                "kind": row.kind,
                "degree": row.degree,
                "criticality": row.criticality,
                "articulation_point": row.articulation_point,
                "chokepoint_score": row.chokepoint_score,
            }
            for row in rows
        ],
    }


@app.get("/ml/telemetry")
def telemetry_ml(scenario: str = "normal", limit: int = Query(default=10, ge=1, le=30)) -> dict[str, object]:
    normal = generate_normal_telemetry(seed=11, minutes=60)
    if scenario == "normal":
        events = normal
    elif scenario in scenario_names():
        events = inject_attack_telemetry(normal, scenario)
    else:
        raise HTTPException(
            status_code=400,
            detail={"error": "unknown scenario", "available_scenarios": ["normal", *scenario_names()]},
        )
    report = model_report(events, limit=limit)
    report["scenario"] = scenario
    return report


@app.post("/simulate")
def simulate(request: SimulationRequest) -> dict[str, object]:
    available = scenario_names()
    if request.scenario not in available:
        raise HTTPException(
            status_code=400,
            detail={"error": "unknown scenario", "available_scenarios": available},
        )

    twin = build_default_twin()
    if request.start_asset not in twin.assets:
        raise HTTPException(status_code=404, detail={"error": "unknown start asset"})

    events = inject_attack_telemetry(generate_normal_telemetry(), request.scenario)
    risks = score_assets(twin, events, request.scenario)
    blast = simulate_compromise(twin, request.start_asset, request.max_hops)
    resilience = evaluate_resilience(twin, request.scenario, request.start_asset, request.max_hops)
    anomalies = top_anomalies(events, limit=5)

    return {
        "scenario": request.scenario,
        "overall_risk": overall_risk(risks),
        "top_risky_assets": [
            {"asset_id": item.asset_id, "risk": item.risk, "reasons": list(item.reasons)}
            for item in risks[:8]
        ],
        "blast_radius": {
            "start_asset": blast.start_asset,
            "max_hops": blast.max_hops,
            "reachable_assets": blast.reachable_assets,
            "critical_assets": blast.critical_assets,
            "gpu_nodes": blast.gpu_nodes,
            "gpus": blast.gpus,
            "workloads": blast.workloads,
            "models": blast.models,
            "blast_score": blast.blast_score,
            "recommendations": list(blast.recommendations),
        },
        "resilience": {
            "raw_blast_score": resilience.raw_blast_score,
            "control_reduction": resilience.control_reduction,
            "residual_blast_score": resilience.residual_blast_score,
            "resilience_score": resilience.resilience_score,
            "active_controls": list(resilience.active_controls),
        },
        "top_anomalies": [
            {
                "minute": event.minute,
                "source": event.source,
                "metric": event.metric,
                "value": event.value,
                "anomaly_score": round(score, 4),
                "detail": event.detail,
            }
            for event, score in anomalies
        ],
        "multivariate_ml": {
            "model": "PCAReconstructionAnomalyModel",
            "top_minutes": model_report(events, limit=5)["top_anomaly_minutes"],
        },
    }
