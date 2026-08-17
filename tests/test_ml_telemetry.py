import unittest

from digital_twin.ml_telemetry import FEATURE_NAMES, model_report, scenario_evaluation, score_minutes
from digital_twin.telemetry import generate_normal_telemetry, inject_attack_telemetry


class TelemetryMLTests(unittest.TestCase):
    def test_feature_space_contains_temporal_deltas(self):
        self.assertTrue(any(name.startswith("delta_") for name in FEATURE_NAMES))
        self.assertIn("z_gpu_utilization", FEATURE_NAMES)
        self.assertIn("z_egress_mbps", FEATURE_NAMES)

    def test_normal_scoring_is_bounded(self):
        rows = score_minutes(generate_normal_telemetry(seed=11, minutes=60), limit=10)
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(0.0 <= row.anomaly_percentile <= 100.0 for row in rows))

    def test_injected_scenario_surfaces_attack_minute(self):
        normal = generate_normal_telemetry(seed=11, minutes=60)
        events = inject_attack_telemetry(normal, "model_exfiltration")
        injected_minutes = {event.minute for event in events if event.detail}
        ranked = {row.minute for row in score_minutes(events, limit=8)}
        self.assertTrue(injected_minutes & ranked)

    def test_model_report_is_reproducible_and_scoped(self):
        report = model_report(generate_normal_telemetry(seed=11, minutes=60), limit=5)
        self.assertEqual(report["model"], "PCAReconstructionAnomalyModel")
        self.assertGreater(report["explained_variance"], 0.90)
        self.assertIn("separate evidence layers", report["decision_boundary"])

    def test_scenario_evaluation_covers_all_synthetic_scenarios(self):
        report = scenario_evaluation()
        self.assertEqual(report["total"], 5)
        self.assertGreaterEqual(report["surfaced"], 1)


if __name__ == "__main__":
    unittest.main()
