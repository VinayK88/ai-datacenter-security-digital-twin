"""Synthetic security and infrastructure telemetry for the digital twin."""

from dataclasses import dataclass
from random import Random


@dataclass(frozen=True)
class TelemetryEvent:
    minute: int
    source: str
    metric: str
    value: float
    category: str
    detail: str = ""


BASELINES: dict[str, tuple[float, float]] = {
    "gpu_utilization": (62.0, 12.0),
    "gpu_power_watts": (510.0, 55.0),
    "egress_mbps": (42.0, 18.0),
    "auth_failures": (0.4, 0.8),
    "bmc_commands": (1.5, 1.2),
    "pod_creations": (0.8, 0.9),
    "model_reads": (2.0, 1.5),
    "temperature_c": (63.0, 6.0),
}


def generate_normal_telemetry(seed: int = 11, minutes: int = 60) -> list[TelemetryEvent]:
    rng = Random(seed)
    events: list[TelemetryEvent] = []
    nodes = [f"gpu-node-{rack:02d}-{node:02d}" for rack in range(1, 3) for node in range(1, 4)]
    for minute in range(minutes):
        node = nodes[minute % len(nodes)]
        for metric in ("gpu_utilization", "egress_mbps", "temperature_c"):
            center, spread = BASELINES[metric]
            value = max(0.0, rng.gauss(center, spread * 0.55))
            events.append(TelemetryEvent(minute, node, metric, round(value, 2), "infrastructure"))
        if minute % 5 == 0:
            value = max(0.0, rng.gauss(*BASELINES["auth_failures"]))
            events.append(TelemetryEvent(minute, "identity-01", "auth_failures", round(value, 2), "identity"))
        if minute % 8 == 0:
            value = max(0.0, rng.gauss(*BASELINES["model_reads"]))
            events.append(TelemetryEvent(minute, "model-registry-01", "model_reads", round(value, 2), "model"))
    return events


def inject_attack_telemetry(events: list[TelemetryEvent], scenario: str) -> list[TelemetryEvent]:
    injected = list(events)
    if scenario == "bmc_compromise":
        injected += [
            TelemetryEvent(36, "bmc-01-02", "auth_failures", 18.0, "identity", "repeated remote BMC login failures"),
            TelemetryEvent(38, "bmc-01-02", "bmc_commands", 16.0, "management", "unusual remote console and power commands"),
            TelemetryEvent(41, "gpu-node-01-02", "pod_creations", 8.0, "kubernetes", "unexpected privileged workload creation"),
        ]
    elif scenario == "model_exfiltration":
        injected += [
            TelemetryEvent(32, "identity-01", "auth_failures", 14.0, "identity", "credential stuffing against ML identity"),
            TelemetryEvent(38, "model-registry-01", "model_reads", 21.0, "model", "burst of model artifact reads"),
            TelemetryEvent(42, "gpu-node-02-01", "egress_mbps", 410.0, "network", "sustained unusual outbound transfer"),
        ]
    elif scenario == "rogue_workload":
        injected += [
            TelemetryEvent(29, "k8s-control-01", "pod_creations", 11.0, "kubernetes", "unsigned privileged container deployed"),
            TelemetryEvent(34, "gpu-node-02-03", "gpu_utilization", 99.0, "infrastructure", "unexpected GPU saturation"),
            TelemetryEvent(36, "gpu-node-02-03", "egress_mbps", 230.0, "network", "new external destination"),
        ]
    elif scenario == "cryptomining":
        injected += [
            TelemetryEvent(31, "gpu-node-01-03", "gpu_utilization", 100.0, "infrastructure", "persistent off-schedule GPU use"),
            TelemetryEvent(31, "gpu-node-01-03", "gpu_power_watts", 735.0, "infrastructure", "power draw above training baseline"),
            TelemetryEvent(44, "gpu-node-01-03", "egress_mbps", 120.0, "network", "mining-pool-like egress pattern"),
        ]
    else:
        raise ValueError(f"Unknown scenario: {scenario}")
    return sorted(injected, key=lambda event: (event.minute, event.source, event.metric))


def anomaly_score(event: TelemetryEvent) -> float:
    baseline = BASELINES.get(event.metric)
    if baseline is None:
        return 0.0
    center, spread = baseline
    if spread <= 0:
        return 0.0
    z = abs(event.value - center) / spread
    return min(1.0, z / 5.0)


def top_anomalies(events: list[TelemetryEvent], limit: int = 10) -> list[tuple[TelemetryEvent, float]]:
    scored = [(event, anomaly_score(event)) for event in events]
    scored.sort(key=lambda item: item[1], reverse=True)
    return scored[:limit]
