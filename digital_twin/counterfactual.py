"""Counterfactual compromise and directed blast-radius simulation."""

from dataclasses import dataclass

from digital_twin.topology import DigitalTwin


@dataclass(frozen=True)
class BlastRadius:
    start_asset: str
    max_hops: int
    reachable_assets: int
    critical_assets: int
    gpu_nodes: int
    gpus: int
    workloads: int
    models: int
    blast_score: float
    impacted: tuple[str, ...]
    recommendations: tuple[str, ...]


def simulate_compromise(twin: DigitalTwin, start_asset: str, max_hops: int = 3) -> BlastRadius:
    if start_asset not in twin.assets:
        raise KeyError(f"Unknown asset: {start_asset}")

    # Blast radius follows directed compromise/trust relationships rather than
    # assuming that every physical/dependency connection is reversible.
    distances = twin.attack_reachable(start_asset, max_hops=max_hops)
    impacted = sorted(distances)
    assets = [twin.assets[asset_id] for asset_id in impacted]
    critical = sum(asset.criticality >= 0.9 for asset in assets)
    gpu_nodes = sum(asset.kind == "gpu_node" for asset in assets)
    gpus = sum(asset.kind == "gpu" for asset in assets)
    workloads = sum(asset.kind == "workload" for asset in assets)
    models = sum(asset.kind == "model" for asset in assets)

    normalized_reach = min(1.0, len(impacted) / max(1, len(twin.assets)))
    critical_fraction = critical / max(1, len(impacted))
    blast_score = min(
        1.0,
        0.35 * normalized_reach
        + 0.35 * critical_fraction
        + 0.12 * min(gpu_nodes / 6, 1.0)
        + 0.10 * min(gpus / 24, 1.0)
        + 0.08 * min(models, 1),
    )

    start = twin.assets[start_asset]
    recommendations: list[str] = []
    if start.kind == "bmc":
        recommendations += [
            "isolate BMC management network from workload fabric",
            "rotate BMC credentials and disable shared administrator accounts",
            "validate firmware integrity before restoring remote management",
        ]
    if start.kind in {"control_plane", "identity_service", "identity"}:
        recommendations += [
            "revoke active privileged sessions and rotate service credentials",
            "apply emergency least-privilege policy to cluster administration",
            "review recent token issuance and workload creation events",
        ]
    if start.kind == "power_controller":
        recommendations += [
            "disable nonessential remote PDU control paths pending review",
            "validate power-controller audit logs and administrator sessions",
        ]
    if gpu_nodes or gpus:
        recommendations.append("cordon affected GPU nodes and preserve runtime evidence")
    if models:
        recommendations.append("freeze model-registry writes and audit artifact reads/checksums")
    if not recommendations:
        recommendations.append("segment the affected asset and validate adjacent trust relationships")

    return BlastRadius(
        start_asset=start_asset,
        max_hops=max_hops,
        reachable_assets=len(impacted),
        critical_assets=critical,
        gpu_nodes=gpu_nodes,
        gpus=gpus,
        workloads=workloads,
        models=models,
        blast_score=round(blast_score, 4),
        impacted=tuple(impacted),
        recommendations=tuple(dict.fromkeys(recommendations)),
    )
