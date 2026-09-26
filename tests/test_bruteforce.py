import unittest
from unittest.mock import MagicMock

from astra_recon.models import DiscoveredUser
from astra_recon.attacks.bruteforce import WordPressBruteforcer
from astra_recon.attacks.wordlists import load_wordlist
from astra_recon.utils.http_client import HttpResponse


class TestBruteforce(unittest.TestCase):

    def test_identify_admin_targets(self):
        users = [
            DiscoveredUser(username="alice", evidence="/author/alice/", is_admin_candidate=False, user_id=2),
            DiscoveredUser(username="admin", evidence="/author/admin/", is_admin_candidate=True, user_id=1),
            DiscoveredUser(username="editor", evidence="/author/editor/", is_admin_candidate=False, user_id=3),
        ]
        bf = WordPressBruteforcer("http://test.local", MagicMock(), delay=0)
        targets = bf.select_admin_targets(users)
        self.assertIn("admin", targets)

    def test_bruteforce_success_wp_login(self):
        mock_client = MagicMock()

        def post_mock(url, data=None, **kwargs):
            if isinstance(data, dict):
                pwd = data.get("pwd")
                if pwd == "admin123":
                    # Simulated 302 redirect on successful login
                    return HttpResponse(
                        status_code=302,
                        headers={"Location": "http://test.local/wp-admin/"},
                    )
            return HttpResponse(
                status_code=200,
                text='<div id="login_error">Incorrect password.</div>',
            )

        mock_client.safe_post.side_effect = post_mock

        bf = WordPressBruteforcer(
            target_url="http://test.local",
            client=mock_client,
            delay=0,
            max_attempts=10,
        )
        # Inject admin123 into passwords
        bf.passwords = ["wrongpass", "admin123", "password"]

        result = bf.attack_user("admin")
        self.assertTrue(result.success)
        self.assertEqual(result.cracked_password, "admin123")
        self.assertEqual(result.attempt_count, 2)

    def test_wordlist_fallback(self):
        pwds = load_wordlist(None, limit=5)
        self.assertEqual(len(pwds), 5)
        self.assertIn("admin", pwds)
        self.assertIn("password", pwds)


if __name__ == "__main__":
    unittest.main()
