import json
import unittest
from pathlib import Path

from digital_twin.attack_surface import articulation_points, trust_chokepoints
from digital_twin.counterfactual import simulate_compromise
from digital_twin.resilience import evaluate_resilience
from digital_twin.scoring import overall_risk, score_assets
from digital_twin.telemetry import generate_normal_telemetry, inject_attack_telemetry
from digital_twin.topology import build_default_twin


ROOT = Path(__file__).resolve().parents[1]


class ReportConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.twin = build_default_twin()

    def test_baseline_report_matches_executable_fixture(self):
        report = json.loads((ROOT / "reports" / "baseline-evaluation.json").read_text())
        events = inject_attack_telemetry(generate_normal_telemetry(), "bmc_compromise")
        risks = score_assets(self.twin, events, "bmc_compromise")
        bmc = simulate_compromise(self.twin, "bmc-01-02", max_hops=3)
        control = simulate_compromise(self.twin, "k8s-control-01", max_hops=3)

        self.assertEqual(report["fixture"]["assets"], len(self.twin.assets))
        self.assertAlmostEqual(report["risk"]["overall_risk"], overall_risk(risks), places=4)
        self.assertEqual(report["risk"]["highest_risk_asset"], risks[0].asset_id)
        self.assertAlmostEqual(report["risk"]["highest_risk_score"], risks[0].risk, places=4)

        for expected, actual in (
            (report["counterfactual"], bmc),
            (report["control_plane_counterfactual"], control),
        ):
            self.assertEqual(expected["reachable_assets"], actual.reachable_assets)
            self.assertEqual(expected["critical_assets"], actual.critical_assets)
            self.assertEqual(expected["gpu_nodes"], actual.gpu_nodes)
            self.assertEqual(expected["gpus"], actual.gpus)
            self.assertEqual(expected["workloads"], actual.workloads)
            self.assertEqual(expected["models"], actual.models)
            self.assertAlmostEqual(expected["blast_score"], actual.blast_score, places=4)

    def test_security_posture_report_matches_current_algorithms(self):
        report = json.loads((ROOT / "reports" / "security-posture.json").read_text())
        points = articulation_points(self.twin)
        ranked = trust_chokepoints(self.twin, limit=5)
        resilience = evaluate_resilience(self.twin, "bmc_compromise", "bmc-01-02", max_hops=3)

        self.assertEqual(report["articulation_point_count"], len(points))
        self.assertEqual(
            [row["asset_id"] for row in report["top_trust_chokepoints"]],
            [row.asset_id for row in ranked],
        )
        self.assertEqual(
            [row["chokepoint_score"] for row in report["top_trust_chokepoints"]],
            [row.chokepoint_score for row in ranked],
        )

        expected = report["bmc_control_what_if"]
        self.assertAlmostEqual(expected["raw_blast_score"], resilience.raw_blast_score, places=4)
        self.assertAlmostEqual(expected["combined_control_reduction"], resilience.control_reduction, places=4)
        self.assertAlmostEqual(expected["residual_blast_score"], resilience.residual_blast_score, places=4)
        self.assertAlmostEqual(expected["resilience_score"], resilience.resilience_score, places=4)


if __name__ == "__main__":
    unittest.main()
