import unittest

from fastapi.testclient import TestClient

from api.app import app


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_twin_summary(self):
        response = self.client.get("/twin")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["asset_count"], 57)
        self.assertIn("bmc_compromise", body["scenarios"])

    def test_chokepoint_bounds(self):
        response = self.client.get("/chokepoints?limit=5")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 5)
        self.assertEqual(self.client.get("/chokepoints?limit=0").status_code, 422)
        self.assertEqual(self.client.get("/chokepoints?limit=31").status_code, 422)

    def test_simulate_success(self):
        response = self.client.post(
            "/simulate",
            json={"scenario": "bmc_compromise", "start_asset": "bmc-01-02", "max_hops": 3},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["blast_radius"]["reachable_assets"], 9)
        self.assertAlmostEqual(body["blast_radius"]["blast_score"], 0.2475, places=4)
        self.assertLess(body["resilience"]["residual_blast_score"], body["resilience"]["raw_blast_score"])

    def test_unknown_scenario_returns_400(self):
        response = self.client.post(
            "/simulate",
            json={"scenario": "not-a-scenario", "start_asset": "bmc-01-02", "max_hops": 3},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["error"], "unknown scenario")

    def test_unknown_asset_returns_404(self):
        response = self.client.post(
            "/simulate",
            json={"scenario": "bmc_compromise", "start_asset": "missing-asset", "max_hops": 3},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"]["error"], "unknown start asset")


if __name__ == "__main__":
    unittest.main()
