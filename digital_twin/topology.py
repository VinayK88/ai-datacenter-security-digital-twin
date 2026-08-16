"""Dependency-free topology and directed attack-reachability graph."""

from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Asset:
    asset_id: str
    kind: str
    zone: str
    criticality: float
    internet_exposed: bool = False
    privileged: bool = False
    metadata: tuple[tuple[str, str], ...] = ()


class DigitalTwin:
    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        # Structural / dependency topology is undirected and is used for posture analysis.
        self.edges: dict[str, set[str]] = {}
        # Attack reachability is directional so trust is not assumed reversible.
        self.attack_edges: dict[str, set[str]] = {}

    def add_asset(self, asset: Asset) -> None:
        self.assets[asset.asset_id] = asset
        self.edges.setdefault(asset.asset_id, set())
        self.attack_edges.setdefault(asset.asset_id, set())

    def connect(self, left: str, right: str) -> None:
        """Add an undirected structural/dependency relationship."""
        if left not in self.assets or right not in self.assets:
            raise KeyError("Both assets must exist before creating a relationship")
        self.edges[left].add(right)
        self.edges[right].add(left)

    def allow_attack(self, source: str, target: str) -> None:
        """Add a directed plausible compromise/pivot relationship."""
        if source not in self.assets or target not in self.assets:
            raise KeyError("Both assets must exist before creating an attack relationship")
        self.attack_edges[source].add(target)

    def neighbors(self, asset_id: str) -> set[str]:
        return set(self.edges.get(asset_id, set()))

    def attack_neighbors(self, asset_id: str) -> set[str]:
        return set(self.attack_edges.get(asset_id, set()))

    def shortest_path(self, start: str, target: str) -> list[str]:
        """Shortest structural path in the undirected dependency graph."""
        if start == target:
            return [start]
        queue = deque([(start, [start])])
        seen = {start}
        while queue:
            node, path = queue.popleft()
            for nxt in sorted(self.edges.get(node, set())):
                if nxt in seen:
                    continue
                if nxt == target:
                    return path + [nxt]
                seen.add(nxt)
                queue.append((nxt, path + [nxt]))
        return []

    def reachable(self, start: str, max_hops: int = 4) -> dict[str, int]:
        """Structural reachability in the undirected dependency graph."""
        return self._bounded_reachable(self.edges, start, max_hops)

    def attack_reachable(self, start: str, max_hops: int = 4) -> dict[str, int]:
        """Directional compromise reachability in the attack graph."""
        return self._bounded_reachable(self.attack_edges, start, max_hops)

    @staticmethod
    def _bounded_reachable(graph: dict[str, set[str]], start: str, max_hops: int) -> dict[str, int]:
        if max_hops < 0:
            raise ValueError("max_hops must be non-negative")
        if start not in graph:
            raise KeyError(f"Unknown asset: {start}")
        queue = deque([(start, 0)])
        distances = {start: 0}
        while queue:
            node, distance = queue.popleft()
            if distance >= max_hops:
                continue
            for nxt in sorted(graph.get(node, set())):
                if nxt not in distances:
                    distances[nxt] = distance + 1
                    queue.append((nxt, distance + 1))
        return distances

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for asset in self.assets.values():
            counts[asset.kind] = counts.get(asset.kind, 0) + 1
        return dict(sorted(counts.items()))


def build_default_twin() -> DigitalTwin:
    twin = DigitalTwin()

    shared = [
        Asset("edge-fw-01", "firewall", "perimeter", 0.95, internet_exposed=True),
        Asset("spine-sw-01", "network_switch", "fabric", 0.90, privileged=True),
        Asset("k8s-control-01", "control_plane", "management", 1.00, privileged=True),
        Asset("model-registry-01", "model_registry", "services", 1.00, privileged=True),
        Asset("object-store-01", "storage", "services", 0.95),
        Asset("identity-01", "identity_service", "management", 1.00, privileged=True),
        Asset("ops-admin", "identity", "management", 0.95, privileged=True),
        Asset("ml-engineer", "identity", "users", 0.80),
        Asset("foundation-model-v3", "model", "services", 1.00),
    ]
    for asset in shared:
        twin.add_asset(asset)

    # Structural relationships.
    twin.connect("edge-fw-01", "spine-sw-01")
    twin.connect("spine-sw-01", "k8s-control-01")
    twin.connect("k8s-control-01", "identity-01")
    twin.connect("k8s-control-01", "model-registry-01")
    twin.connect("model-registry-01", "object-store-01")
    twin.connect("model-registry-01", "foundation-model-v3")
    twin.connect("identity-01", "ops-admin")
    twin.connect("identity-01", "ml-engineer")

    # Directional trust / compromise relationships for the shared control plane.
    twin.allow_attack("edge-fw-01", "spine-sw-01")
    twin.allow_attack("spine-sw-01", "k8s-control-01")
    twin.allow_attack("identity-01", "k8s-control-01")
    twin.allow_attack("ops-admin", "identity-01")
    twin.allow_attack("ml-engineer", "identity-01")
    twin.allow_attack("k8s-control-01", "model-registry-01")
    twin.allow_attack("model-registry-01", "object-store-01")
    twin.allow_attack("model-registry-01", "foundation-model-v3")

    for rack in range(1, 3):
        rack_id = f"rack-{rack:02d}"
        tor_id = f"tor-{rack:02d}"
        pdu_id = f"pdu-{rack:02d}"
        twin.add_asset(Asset(rack_id, "rack", rack_id, 0.75))
        twin.add_asset(Asset(tor_id, "network_switch", rack_id, 0.85, privileged=True))
        twin.add_asset(Asset(pdu_id, "power_controller", rack_id, 0.80, privileged=True))
        twin.connect("spine-sw-01", tor_id)
        twin.connect(rack_id, tor_id)
        twin.connect(rack_id, pdu_id)
        twin.allow_attack("spine-sw-01", tor_id)

        for node in range(1, 4):
            node_id = f"gpu-node-{rack:02d}-{node:02d}"
            bmc_id = f"bmc-{rack:02d}-{node:02d}"
            pod_id = f"training-pod-{rack:02d}-{node:02d}"
            twin.add_asset(Asset(node_id, "gpu_node", rack_id, 0.90, privileged=True))
            twin.add_asset(Asset(bmc_id, "bmc", rack_id, 0.90, privileged=True))
            twin.add_asset(Asset(pod_id, "workload", rack_id, 0.82))
            twin.connect(tor_id, node_id)
            twin.connect(pdu_id, node_id)
            twin.connect(bmc_id, node_id)
            twin.connect("k8s-control-01", node_id)
            twin.connect(node_id, pod_id)
            twin.connect(pod_id, "object-store-01")
            twin.connect(pod_id, "model-registry-01")

            twin.allow_attack(tor_id, node_id)
            twin.allow_attack(pdu_id, node_id)
            twin.allow_attack(bmc_id, node_id)
            twin.allow_attack("k8s-control-01", node_id)
            twin.allow_attack(node_id, pod_id)
            twin.allow_attack(pod_id, "object-store-01")
            twin.allow_attack(pod_id, "model-registry-01")

            for gpu in range(1, 5):
                gpu_id = f"gpu-{rack:02d}-{node:02d}-{gpu:02d}"
                twin.add_asset(Asset(gpu_id, "gpu", rack_id, 0.88))
                twin.connect(node_id, gpu_id)
                twin.allow_attack(node_id, gpu_id)

    return twin
