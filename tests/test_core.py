import unittest

from digital_twin.attacks import get_scenario, scenario_names
from digital_twin.counterfactual import simulate_compromise
from digital_twin.scoring import overall_risk, score_assets
from digital_twin.telemetry import generate_normal_telemetry, inject_attack_telemetry, top_anomalies
from digital_twin.topology import build_default_twin


class DigitalTwinTests(unittest.TestCase):
    def setUp(self):
        self.twin = build_default_twin()

    def test_topology_shape(self):
        self.assertEqual(len(self.twin.assets), 57)
        self.assertEqual(self.twin.summary()["gpu_node"], 6)
        self.assertEqual(self.twin.summary()["gpu"], 24)
        self.assertEqual(self.twin.summary()["bmc"], 6)
        self.assertEqual(self.twin.summary()["workload"], 6)

    def test_attack_scenarios_reference_real_assets(self):
        for name in scenario_names():
            for step in get_scenario(name):
                self.assertIn(step.asset_id, self.twin.assets)

    def test_bmc_blast_radius_is_bounded_and_reproducible(self):
        blast = simulate_compromise(self.twin, "bmc-01-02", max_hops=3)
        self.assertEqual(blast.reachable_assets, 20)
        self.assertEqual(blast.gpu_nodes, 6)
        self.assertEqual(blast.gpus, 4)
        self.assertAlmostEqual(blast.blast_score, 0.4695, places=4)

    def test_control_plane_has_larger_blast_radius(self):
        bmc = simulate_compromise(self.twin, "bmc-01-02", max_hops=3)
        control = simulate_compromise(self.twin, "k8s-control-01", max_hops=3)
        self.assertGreater(control.reachable_assets, bmc.reachable_assets)
        self.assertGreater(control.blast_score, bmc.blast_score)

    def test_attack_telemetry_surfaces_scenario_anomalies(self):
        events = inject_attack_telemetry(generate_normal_telemetry(), "bmc_compromise")
        anomalies = top_anomalies(events, limit=3)
        sources = {event.source for event, _ in anomalies}
        self.assertIn("bmc-01-02", sources)
        self.assertIn("gpu-node-01-02", sources)

    def test_risk_pipeline(self):
        events = inject_attack_telemetry(generate_normal_telemetry(), "bmc_compromise")
        risks = score_assets(self.twin, events, "bmc_compromise")
        self.assertEqual(risks[0].asset_id, "gpu-node-01-02")
        self.assertAlmostEqual(overall_risk(risks), 0.8284, places=4)
        self.assertIn("on_simulated_attack_path", risks[0].reasons)


if __name__ == "__main__":
    unittest.main()
