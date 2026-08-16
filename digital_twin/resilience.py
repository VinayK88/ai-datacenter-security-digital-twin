"""Defensive control what-if analysis for the AI data center digital twin."""

from dataclasses import dataclass
from math import prod

from digital_twin.counterfactual import BlastRadius, simulate_compromise
from digital_twin.topology import DigitalTwin


@dataclass(frozen=True)
class SecurityControl:
    control_id: str
    description: str
    scenarios: tuple[str, ...]
    effectiveness: float


@dataclass(frozen=True)
class ResilienceResult:
    scenario: str
    start_asset: str
    raw_blast_score: float
    control_reduction: float
    residual_blast_score: float
    resilience_score: float
    active_controls: tuple[str, ...]


CONTROL_CATALOG: tuple[SecurityControl, ...] = (
    SecurityControl(
        "bmc_network_segmentation",
        "isolate management controllers from workload and east-west data-plane traffic",
        ("bmc_compromise",),
        0.48,
    ),
    SecurityControl(
        "unique_bmc_credentials",
        "enforce unique short-lived management credentials with MFA-backed administration",
        ("bmc_compromise",),
        0.26,
    ),
    SecurityControl(
        "signed_privileged_workloads",
        "admit only signed privileged workloads and require policy approval for host access",
        ("bmc_compromise", "rogue_workload"),
        0.34,
    ),
    SecurityControl(
        "model_registry_egress_guard",
        "restrict model-registry reads and large artifact transfers to approved identities and destinations",
        ("bmc_compromise", "model_exfiltration", "rogue_workload"),
        0.31,
    ),
    SecurityControl(
        "cluster_admin_mfa",
        "protect cluster-admin and workload-creation paths with phishing-resistant MFA and JIT access",
        ("model_exfiltration", "rogue_workload"),
        0.30,
    ),
    SecurityControl(
        "gpu_runtime_egress_policy",
        "block unexpected outbound destinations from GPU workloads and training namespaces",
        ("cryptomining", "model_exfiltration"),
        0.28,
    ),
    SecurityControl(
        "pdu_command_guard",
        "require privileged approval and anomaly checks for remote PDU power-control operations",
        ("power_control_abuse",),
        0.42,
    ),
)


def controls_for_scenario(scenario: str) -> list[SecurityControl]:
    return [control for control in CONTROL_CATALOG if scenario in control.scenarios]


def _combined_reduction(controls: list[SecurityControl]) -> float:
    if not controls:
        return 0.0
    residual = prod(1.0 - min(max(control.effectiveness, 0.0), 0.95) for control in controls)
    return min(0.85, 1.0 - residual)


def evaluate_resilience(
    twin: DigitalTwin,
    scenario: str,
    start_asset: str,
    max_hops: int = 3,
    enabled_controls: set[str] | None = None,
) -> ResilienceResult:
    """Estimate residual systemic risk under an explicit set of defensive controls.

    Effectiveness values are illustrative assumptions, not empirical probabilities.
    They make control tradeoffs inspectable and suitable for counterfactual demos.
    """
    blast: BlastRadius = simulate_compromise(twin, start_asset, max_hops=max_hops)
    relevant = controls_for_scenario(scenario)
    if enabled_controls is not None:
        relevant = [control for control in relevant if control.control_id in enabled_controls]

    reduction = _combined_reduction(relevant)
    residual = blast.blast_score * (1.0 - reduction)
    resilience = 1.0 - residual

    return ResilienceResult(
        scenario=scenario,
        start_asset=start_asset,
        raw_blast_score=blast.blast_score,
        control_reduction=round(reduction, 4),
        residual_blast_score=round(residual, 4),
        resilience_score=round(resilience, 4),
        active_controls=tuple(control.control_id for control in relevant),
    )
