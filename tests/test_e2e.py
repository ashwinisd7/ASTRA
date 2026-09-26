import time
import socket
import threading
import unittest
from werkzeug.serving import make_server

from astra_recon.mock_server import create_mock_app
from astra_recon.agent.orchestrator import ReconAgentOrchestrator
from astra_recon.models import ScanConfig
from astra_recon.utils.console import ReconConsole


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ServerThread(threading.Thread):
    def __init__(self, app, port):
        super().__init__()
        self.port = port
        self.server = make_server("127.0.0.1", port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


class TestEndToEndRecon(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.port = find_free_port()
        app = create_mock_app()
        cls.server_thread = ServerThread(app, cls.port)
        cls.server_thread.start()
        time.sleep(0.5)  # Allow server to bind

    @classmethod
    def tearDownClass(cls):
        cls.server_thread.shutdown()
        cls.server_thread.join()

    def test_full_recon_cycle(self):
        target_url = f"http://127.0.0.1:{self.port}"
        config = ScanConfig(
            target_url=target_url,
            techniques=["rest_api", "author_archive", "login_leak"],
            timeout=5,
            bruteforce_enabled=True,
            max_bruteforce_attempts=5,
            bruteforce_delay=0.0,
            run_exploit_checks=True,
            verbose=False,
        )

        console = ReconConsole(quiet=True)
        orchestrator = ReconAgentOrchestrator(config=config, console=console)
        result = orchestrator.run()

        # 1. Target check
        self.assertEqual(result.target, target_url)

        # 2. Users discovery check
        found_usernames = [u["username"] for u in result.users]
        self.assertIn("admin", found_usernames)
        self.assertIn("editor", found_usernames)
        self.assertIn("testuser", found_usernames)

        # 3. Techniques check
        self.assertIn("rest_api", result.techniques_used)

        # 4. Brute force check: admin123 should be cracked!
        self.assertTrue(result.bruteforce_results is not None)
        admin_cracked = next((b for b in result.bruteforce_results if b.target_user == "admin" and b.success), None)
        self.assertIsNotNone(admin_cracked)
        self.assertEqual(admin_cracked.cracked_password, "admin123")

        # 5. Exploit detector check: version 6.2, debug.log, etc.
        vuln_titles = [v.title for v in result.vulnerabilities]
        self.assertTrue(any("Version" in t for t in vuln_titles))
        self.assertTrue(any("Debug Log" in t for t in vuln_titles))

        # 6. JSON output format check (matching Section 6.2)
        json_data = result.to_assignment_json()
        self.assertIn("target", json_data)
        self.assertIn("techniques_used", json_data)
        self.assertIn("users", json_data)
        self.assertIn("ai_summary", json_data)
        self.assertIn("bruteforce_results", json_data)

        for u in json_data["users"]:
            self.assertIn("username", u)
            self.assertIn("evidence", u)


if __name__ == "__main__":
    unittest.main()
