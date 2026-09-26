import re
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup

from astra_recon.enumerators.base import BaseEnumerator
from astra_recon.models import DiscoveredUser
from astra_recon.utils.http_client import HttpClient


class LoginLeakEnumerator(BaseEnumerator):
    """
    Error-Based Username Leak Enumeration (/wp-login.php)
    WordPress login form by default differentiates between non-existent accounts
    and valid accounts when an incorrect password is supplied.
    - Invalid user: "Unknown username." / "Invalid username."
    - Valid user: "The password you entered for the username <user> is incorrect."
    """

    name = "login_leak"
    description = "Probes wp-login.php to identify accounts based on error message differentiation"

    # Default common username candidates to probe
    CANDIDATE_USERNAMES = [
        "admin",
        "administrator",
        "root",
        "webmaster",
        "editor",
        "author",
        "testuser",
        "test",
        "support",
        "dev",
    ]

    # Regex indicators for confirmed username existence
    PASSWORD_INCORRECT_PATTERNS = [
        re.compile(r"password you entered for the username.*?is incorrect", re.IGNORECASE),
        re.compile(r"The password you entered for the username <strong>(.*?)</strong> is incorrect", re.IGNORECASE),
        re.compile(r"The password you entered for the email address.*?is incorrect", re.IGNORECASE),
        re.compile(r"<strong>Error</strong>: The password you entered", re.IGNORECASE),
        re.compile(r"Incorrect password\.", re.IGNORECASE),
    ]

    INVALID_USER_PATTERNS = [
        re.compile(r"Unknown username", re.IGNORECASE),
        re.compile(r"Invalid username", re.IGNORECASE),
        re.compile(r"Unknown email address", re.IGNORECASE),
    ]

    def _extract_error_message(self, html: str) -> Optional[str]:
        """Extracts the login error div content from wp-login.php response."""
        if not html:
            return None
        soup = BeautifulSoup(html, "html.parser")
        error_div = soup.find("div", id="login_error")
        if error_div:
            return error_div.get_text(separator=" ", strip=True)
        return None

    def _is_username_valid(self, error_text: str, candidate: str) -> bool:
        """Determines if the error message confirms the username exists."""
        if not error_text:
            return False

        # If it explicitly says "Unknown username" or "Invalid username", user does NOT exist
        for pattern in self.INVALID_USER_PATTERNS:
            if pattern.search(error_text):
                return False

        # If it says password is wrong for that user, user DOES exist
        for pattern in self.PASSWORD_INCORRECT_PATTERNS:
            if pattern.search(error_text):
                return True

        return False

    def run(
        self,
        target_url: str,
        client: HttpClient,
        context: Dict[str, Any],
    ) -> List[DiscoveredUser]:
        users: List[DiscoveredUser] = []
        seen_usernames = set()

        login_url = f"{target_url}/wp-login.php"

        # Check if wp-login.php is reachable
        init_resp = client.safe_get(login_url)
        if init_resp.status_code != 200:
            return []

        # Gather usernames to test: candidates + any already spotted
        candidates = list(self.CANDIDATE_USERNAMES)
        prior_users = context.get("known_usernames", [])
        for u in prior_users:
            if u not in candidates:
                candidates.insert(0, u)

        # Limit to avoid unnecessary lockouts/delays
        max_probe = context.get("max_login_probes", 8)
        probes_to_run = candidates[:max_probe]

        dummy_pwd = "AstraAuditProbePassword9981273!"

        for username in probes_to_run:
            payload = {
                "log": username,
                "pwd": dummy_pwd,
                "wp-submit": "Log In",
                "redirect_to": f"{target_url}/wp-admin/",
                "testcookie": "1",
            }

            resp = client.safe_post(
                login_url,
                data=payload,
                allow_redirects=False,
            )

            error_msg = self._extract_error_message(resp.text)
            if not error_msg:
                # Some sites don't use id="login_error" but have it in text
                error_msg = resp.text

            is_valid = self._is_username_valid(error_msg, username)

            # If ambiguous and AI analyzer is available in context, use AI to interpret
            ai_client = context.get("ai_client")
            if not is_valid and ai_client and "error" in resp.text.lower():
                try:
                    ai_verdict = ai_client.analyze_login_response(username, error_msg[:1000])
                    if ai_verdict.get("user_exists", False):
                        is_valid = True
                except Exception:
                    pass

            if is_valid:
                clean_name = username.lower().strip()
                if clean_name not in seen_usernames:
                    seen_usernames.add(clean_name)
                    users.append(
                        DiscoveredUser(
                            username=clean_name,
                            slug=clean_name,
                            evidence="wp-login.php (error-based username leak)",
                            technique="login_leak",
                            is_admin_candidate=(clean_name in ("admin", "administrator", "root")),
                        )
                    )

        return users
