import unittest

from digital_twin.attack_surface import articulation_points, trust_chokepoints
from digital_twin.resilience import controls_for_scenario, evaluate_resilience
from digital_twin.telemetry import generate_normal_telemetry, inject_attack_telemetry, top_anomalies
from digital_twin.topology import build_default_twin


class AdvancedTwinTests(unittest.TestCase):
    def setUp(self):
        self.twin = build_default_twin()

    def test_trust_chokepoints_are_ranked(self):
        rows = trust_chokepoints(self.twin, limit=8)
        self.assertEqual(len(rows), 8)
        self.assertGreaterEqual(rows[0].chokepoint_score, rows[-1].chokepoint_score)
        self.assertTrue(all(row.asset_id in self.twin.assets for row in rows))

    def test_articulation_analysis_finds_systemic_bridges(self):
        points = articulation_points(self.twin)
        self.assertTrue(points)
        self.assertTrue(points.issubset(self.twin.assets.keys()))

    def test_bmc_controls_reduce_residual_blast_score(self):
        result = evaluate_resilience(
            self.twin,
            scenario="bmc_compromise",
            start_asset="bmc-01-02",
            max_hops=3,
        )
        self.assertGreater(result.control_reduction, 0.0)
        self.assertLess(result.residual_blast_score, result.raw_blast_score)
        self.assertGreater(result.resilience_score, 0.5)
        self.assertIn("bmc_network_segmentation", result.active_controls)

    def test_control_catalog_is_scenario_specific(self):
        bmc_controls = {control.control_id for control in controls_for_scenario("bmc_compromise")}
        mining_controls = {control.control_id for control in controls_for_scenario("cryptomining")}
        self.assertIn("bmc_network_segmentation", bmc_controls)
        self.assertNotIn("bmc_network_segmentation", mining_controls)
        self.assertIn("gpu_runtime_egress_policy", mining_controls)

    def test_power_control_scenario_emits_power_anomalies(self):
        events = inject_attack_telemetry(generate_normal_telemetry(), "power_control_abuse")
        anomalies = top_anomalies(events, limit=12)
        metrics = {event.metric for event, _ in anomalies}
        sources = {event.source for event, _ in anomalies}
        self.assertIn("pdu_commands", metrics)
        self.assertIn("pdu-02", sources)


if __name__ == "__main__":
    unittest.main()
