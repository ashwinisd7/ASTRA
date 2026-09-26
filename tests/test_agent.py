import unittest
from astra_recon.agent.llm_client import HeuristicLLMClient
from astra_recon.models import DiscoveredUser, BruteforceResult, VulnerabilityFinding


class TestAgent(unittest.TestCase):

    def setUp(self):
        self.agent = HeuristicLLMClient()

    def test_plan_next_technique_initial(self):
        action, thought = self.agent.plan_next_technique(
            target_url="http://localhost:8080",
            available_techniques=["rest_api", "author_archive", "login_leak"],
            executed_techniques=[],
            discovered_users=[],
            last_observation="Scan initialized",
        )
        self.assertEqual(action, "rest_api")
        self.assertIn("REST API", thought)

    def test_plan_next_technique_fallback(self):
        action, thought = self.agent.plan_next_technique(
            target_url="http://localhost:8080",
            available_techniques=["author_archive", "login_leak"],
            executed_techniques=["rest_api"],
            discovered_users=[],
            last_observation="No users found",
        )
        self.assertEqual(action, "author_archive")

    def test_analyze_login_response(self):
        valid_resp = self.agent.analyze_login_response(
            "admin",
            "The password you entered for the username admin is incorrect.",
        )
        self.assertTrue(valid_resp["user_exists"])

        invalid_resp = self.agent.analyze_login_response(
            "nonexistent",
            "Unknown username. Check again or try your email address.",
        )
        self.assertFalse(invalid_resp["user_exists"])

    def test_generate_summary_format(self):
        users = [
            DiscoveredUser(username="admin", evidence="/wp-json/wp/v2/users"),
            DiscoveredUser(username="editor", evidence="/wp-json/wp/v2/users"),
        ]
        bf_results = [
            BruteforceResult(
                target_user="admin",
                success=True,
                cracked_password="admin",
                attempt_count=1,
            )
        ]
        vulns = [
            VulnerabilityFinding(
                id="WP-VULN-001",
                title="WordPress Version Disclosure",
                severity="LOW",
                description="Version exposed",
                evidence="readme.html",
                remediation="Remove readme",
            )
        ]

        summary = self.agent.generate_summary(
            target_url="http://localhost:8080",
            techniques_used=["rest_api"],
            discovered_users=users,
            bruteforce_results=bf_results,
            vulnerabilities=vulns,
        )

        self.assertIn("discovered 2 WordPress usernames", summary)
        self.assertIn("/wp-json/wp/v2/users", summary)
        self.assertIn("CRITICAL", summary)
        self.assertIn("admin", summary)

    def test_heuristic_is_offline(self):
        self.assertTrue(self.agent.is_offline)

    def test_gemini_fallback_notifies_offline(self):
        from unittest.mock import MagicMock
        from astra_recon.agent.llm_client import GeminiLLMClient

        mock_console = MagicMock()
        client = GeminiLLMClient(api_key="invalid_test_key", console=mock_console)
        self.assertFalse(client.is_offline)

        # Trigger fallback by simulating a failed plan_next_technique call
        action, thought = client.plan_next_technique(
            target_url="http://localhost:8080",
            available_techniques=["rest_api"],
            executed_techniques=[],
            discovered_users=[],
            last_observation="",
        )

        self.assertEqual(action, "rest_api")
        self.assertTrue(client.is_offline)
        mock_console.offline_fallback.assert_called_once()


if __name__ == "__main__":
    unittest.main()
