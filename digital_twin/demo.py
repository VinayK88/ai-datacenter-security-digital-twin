"""CLI demonstration for the AI Data Center Security Digital Twin."""

from digital_twin.attacks import get_scenario
from digital_twin.counterfactual import simulate_compromise
from digital_twin.scoring import overall_risk, score_assets
from digital_twin.telemetry import generate_normal_telemetry, inject_attack_telemetry, top_anomalies
from digital_twin.topology import build_default_twin


def main() -> None:
    twin = build_default_twin()
    scenario = "bmc_compromise"
    events = inject_attack_telemetry(generate_normal_telemetry(), scenario)
    risks = score_assets(twin, events, scenario)
    blast = simulate_compromise(twin, "bmc-01-02", max_hops=3)

    print("AI Data Center Security Digital Twin")
    print(f"assets={len(twin.assets)} topology={twin.summary()}")
    print(f"scenario={scenario} overall_risk={overall_risk(risks):.3f}")

    print("\nSimulated attack path")
    for step in get_scenario(scenario):
        print(f"{step.order}. {step.asset_id:<22} {step.objective:<18} {step.action}")

    print("\nTop risky assets")
    for item in risks[:8]:
        print(f"{item.asset_id:<24} risk={item.risk:.3f} reasons={','.join(item.reasons)}")

    print("\nTop telemetry anomalies")
    for event, score in top_anomalies(events, limit=5):
        print(f"t+{event.minute:02d} {event.source:<22} {event.metric:<18} anomaly={score:.2f}")

    print("\nCounterfactual: compromise bmc-01-02")
    print(
        f"reachable={blast.reachable_assets} critical={blast.critical_assets} "
        f"gpu_nodes={blast.gpu_nodes} gpus={blast.gpus} blast_score={blast.blast_score:.3f}"
    )
    for recommendation in blast.recommendations:
        print(f"- {recommendation}")


if __name__ == "__main__":
    main()
