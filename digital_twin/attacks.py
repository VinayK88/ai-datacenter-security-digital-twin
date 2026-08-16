"""Defensive attack scenarios used to exercise the AI data center twin."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackStep:
    order: int
    asset_id: str
    action: str
    technique: str
    objective: str


SCENARIOS: dict[str, list[AttackStep]] = {
    "bmc_compromise": [
        AttackStep(1, "bmc-01-02", "remote management login", "Valid Accounts / Remote Services", "initial access"),
        AttackStep(2, "gpu-node-01-02", "remote console pivot", "Remote Services", "lateral movement"),
        AttackStep(3, "training-pod-01-02", "deploy privileged workload", "Container Administration Command", "execution"),
        AttackStep(4, "model-registry-01", "access model artifacts", "Data from Information Repositories", "collection"),
    ],
    "model_exfiltration": [
        AttackStep(1, "ml-engineer", "reuse stolen credentials", "Valid Accounts", "initial access"),
        AttackStep(2, "identity-01", "obtain service access", "Account Manipulation", "privilege access"),
        AttackStep(3, "model-registry-01", "bulk model read", "Data from Information Repositories", "collection"),
        AttackStep(4, "object-store-01", "stage artifacts", "Data Staged", "staging"),
        AttackStep(5, "gpu-node-02-01", "large outbound transfer", "Exfiltration Over Web Service", "exfiltration"),
    ],
    "rogue_workload": [
        AttackStep(1, "k8s-control-01", "create unsigned privileged pod", "Deploy Container", "execution"),
        AttackStep(2, "training-pod-02-03", "mount model and storage paths", "Container Administration Command", "collection"),
        AttackStep(3, "gpu-node-02-03", "access host resources", "Escape to Host", "privilege escalation"),
        AttackStep(4, "model-registry-01", "query model artifacts", "Data from Information Repositories", "collection"),
    ],
    "cryptomining": [
        AttackStep(1, "training-pod-01-03", "replace scheduled workload", "Deploy Container", "execution"),
        AttackStep(2, "gpu-node-01-03", "consume GPU capacity", "Resource Hijacking", "impact"),
        AttackStep(3, "tor-01", "connect to external pool", "Application Layer Protocol", "command and control"),
    ],
    "power_control_abuse": [
        AttackStep(1, "ops-admin", "reuse privileged operations session", "Valid Accounts", "initial access"),
        AttackStep(2, "pdu-02", "issue unusual remote power-control commands", "Remote Services", "impact preparation"),
        AttackStep(3, "gpu-node-02-02", "force repeated power-cycle condition", "Service Stop / Inhibit System Recovery", "impact"),
        AttackStep(4, "training-pod-02-02", "interrupt active training workload", "Endpoint Denial of Service", "impact"),
    ],
}


def scenario_names() -> list[str]:
    return sorted(SCENARIOS)


def get_scenario(name: str) -> list[AttackStep]:
    try:
        return list(SCENARIOS[name])
    except KeyError as exc:
        raise ValueError(f"Unknown scenario: {name}") from exc


def scenario_assets(name: str) -> list[str]:
    return [step.asset_id for step in get_scenario(name)]
