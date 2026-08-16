"""Graph-based trust chokepoint analysis for the AI data center twin."""

from dataclasses import dataclass

from digital_twin.topology import DigitalTwin


@dataclass(frozen=True)
class Chokepoint:
    asset_id: str
    kind: str
    degree: int
    criticality: float
    articulation_point: bool
    chokepoint_score: float


def articulation_points(twin: DigitalTwin) -> set[str]:
    """Return graph articulation points using Tarjan's DFS algorithm."""
    discovery: dict[str, int] = {}
    low: dict[str, int] = {}
    parent: dict[str, str | None] = {}
    points: set[str] = set()
    time = 0

    def dfs(node: str) -> None:
        nonlocal time
        time += 1
        discovery[node] = low[node] = time
        child_count = 0

        for neighbor in sorted(twin.neighbors(node)):
            if neighbor not in discovery:
                parent[neighbor] = node
                child_count += 1
                dfs(neighbor)
                low[node] = min(low[node], low[neighbor])

                if parent.get(node) is None and child_count > 1:
                    points.add(node)
                if parent.get(node) is not None and low[neighbor] >= discovery[node]:
                    points.add(node)
            elif neighbor != parent.get(node):
                low[node] = min(low[node], discovery[neighbor])

    for asset_id in sorted(twin.assets):
        if asset_id not in discovery:
            parent[asset_id] = None
            dfs(asset_id)

    return points


def trust_chokepoints(twin: DigitalTwin, limit: int = 10) -> list[Chokepoint]:
    """Rank assets whose compromise or outage can create systemic consequences.

    The score intentionally remains inspectable: graph degree, asset criticality,
    privileged surface, and articulation-point status are combined into a bounded
    0-1 posture score.
    """
    points = articulation_points(twin)
    max_degree = max((len(twin.neighbors(asset_id)) for asset_id in twin.assets), default=1)
    rows: list[Chokepoint] = []

    for asset_id, asset in twin.assets.items():
        degree = len(twin.neighbors(asset_id))
        degree_score = degree / max_degree
        bridge_bonus = 1.0 if asset_id in points else 0.0
        privilege_bonus = 1.0 if asset.privileged else 0.0
        score = min(
            1.0,
            0.42 * degree_score
            + 0.33 * asset.criticality
            + 0.17 * bridge_bonus
            + 0.08 * privilege_bonus,
        )
        rows.append(
            Chokepoint(
                asset_id=asset_id,
                kind=asset.kind,
                degree=degree,
                criticality=asset.criticality,
                articulation_point=asset_id in points,
                chokepoint_score=round(score, 4),
            )
        )

    rows.sort(key=lambda row: (row.chokepoint_score, row.degree), reverse=True)
    return rows[:limit]
