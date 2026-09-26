import json
import logging
import requests
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple, Optional

from astra_recon.models import DiscoveredUser, BruteforceResult, VulnerabilityFinding, ScanConfig
from astra_recon.agent.prompts import (
    AGENT_SYSTEM_PROMPT,
    NEXT_TECHNIQUE_PROMPT,
    LOGIN_ERROR_ANALYSIS_PROMPT,
    FINAL_SUMMARY_PROMPT,
)

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    """Abstract interface for agent intelligence."""

    @abstractmethod
    def plan_next_technique(
        self,
        target_url: str,
        available_techniques: List[str],
        executed_techniques: List[str],
        discovered_users: List[DiscoveredUser],
        last_observation: str,
    ) -> Tuple[str, str]:
        """Returns (chosen_technique, thought_reasoning)."""
        pass

    @abstractmethod
    def analyze_login_response(self, username: str, error_text: str) -> Dict[str, Any]:
        """Returns dict with user_exists bool and reasoning."""
        pass

    @abstractmethod
    def generate_summary(
        self,
        target_url: str,
        techniques_used: List[str],
        discovered_users: List[DiscoveredUser],
        bruteforce_results: Optional[List[BruteforceResult]],
        vulnerabilities: List[VulnerabilityFinding],
    ) -> str:
        """Returns final executive AI summary report."""
        pass

    @property
    def is_offline(self) -> bool:
        return False


class HeuristicLLMClient(BaseLLMClient):
    """
    Built-in Deterministic Cybersecurity Reasoning Engine.
    Provides reliable, zero-dependency autonomous agent logic matching the
    assignment specification when no OpenAI API key is configured.
    """

    @property
    def is_offline(self) -> bool:
        return True

    def plan_next_technique(
        self,
        target_url: str,
        available_techniques: List[str],
        executed_techniques: List[str],
        discovered_users: List[DiscoveredUser],
        last_observation: str,
    ) -> Tuple[str, str]:
        if not available_techniques:
            return "STOP", "All planned enumeration vectors have been exhausted."

        # Preferred sequence: rest_api -> author_archive -> login_leak -> feed_sniffer -> sitemap_sniffer -> oembed_sniffer
        preferred_order = [
            ("rest_api", "Trying REST API enumeration."),
            ("author_archive", "REST API inspection complete. Probing author archive routing (?author=N) to detect 301/302 redirects."),
            ("login_leak", "Analyzing wp-login.php error message differentiation for credential validation leakage."),
            ("feed_sniffer", "Inspecting RSS and Atom feeds (/feed/) for author <dc:creator> tags."),
            ("sitemap_sniffer", "Checking core and SEO sitemaps (/wp-sitemap-users-1.xml) for author index entries."),
            ("oembed_sniffer", "Querying oEmbed API endpoint (/wp-json/oembed/1.0/embed) for author profile data."),
        ]

        for tech, reason in preferred_order:
            if tech in available_techniques:
                # If we already have users from REST API, we can either continue or conclude
                if tech == "rest_api":
                    return tech, "Trying REST API enumeration."
                elif len(discovered_users) > 0 and tech in ("feed_sniffer", "sitemap_sniffer", "oembed_sniffer"):
                    # We already have users and core vectors tested
                    return tech, f"Validating secondary exposure vector via {tech}."
                return tech, reason

        # Pick first available
        chosen = available_techniques[0]
        return chosen, f"Executing vector probe for {chosen}."

    def analyze_login_response(self, username: str, error_text: str) -> Dict[str, Any]:
        lowered = error_text.lower()
        if "unknown username" in lowered or "invalid username" in lowered:
            return {"user_exists": False, "confidence": 0.95, "reasoning": "Explicit unknown user error"}
        if "password you entered" in lowered or "incorrect password" in lowered:
            return {"user_exists": True, "confidence": 0.95, "reasoning": "WordPress confirmed username existence via password failure"}
        return {"user_exists": False, "confidence": 0.5, "reasoning": "Unrecognized error text"}

    def generate_summary(
        self,
        target_url: str,
        techniques_used: List[str],
        discovered_users: List[DiscoveredUser],
        bruteforce_results: Optional[List[BruteforceResult]],
        vulnerabilities: List[VulnerabilityFinding],
    ) -> str:
        count = len(discovered_users)
        usernames_str = ", ".join(f"'{u.username}'" for u in discovered_users) if discovered_users else "none"
        vectors_str = ", ".join(techniques_used)

        if count > 0:
            primary_evidence = discovered_users[0].evidence
            if primary_evidence.startswith("/wp-json"):
                base_summary = (
                    f"The agent successfully discovered {count} WordPress username{'s' if count != 1 else ''} "
                    f"through the {primary_evidence} endpoint. The target site exposes user objects without authentication, "
                    f"posing a risk for targeted brute-force attempts or social engineering. "
                    f"Discovered account{'s' if count != 1 else ''}: {usernames_str}."
                )
            else:
                base_summary = (
                    f"The agent successfully discovered {count} WordPress username{'s' if count != 1 else ''} "
                    f"utilizing {vectors_str} vectors ({primary_evidence}). The target site's routing and response behavior "
                    f"leaks internal account identities, allowing unauthenticated attackers to map system users. "
                    f"Discovered account{'s' if count != 1 else ''}: {usernames_str}."
                )
        else:
            base_summary = (
                f"The agent completed enumeration using {vectors_str} against {target_url}. "
                "No public usernames were exposed via tested endpoints, indicating REST API access control or enumeration hardening."
            )

        # Brute-force addendum
        bf_summary = ""
        if bruteforce_results:
            cracked = [b for b in bruteforce_results if b.success]
            if cracked:
                first = cracked[0]
                bf_summary = (
                    f"\n\n[CRITICAL] Credential testing successfully identified weak credentials for '{first.target_user}' "
                    f"(Password: '{first.cracked_password}') via {first.method_used}. The administrative portal is fully compromised."
                )
            else:
                bf_summary = (
                    f"\n\n[INFO] Credential testing against administrative account(s) using top dictionary passwords "
                    "did not yield an immediate login compromise. Account lockout and complex password policies appear active."
                )

        # Vulnerabilities addendum
        vuln_summary = ""
        if vulnerabilities:
            crit_high = [v for v in vulnerabilities if v.severity in ("CRITICAL", "HIGH")]
            if crit_high:
                vuln_summary = (
                    f"\n\n[ALERT] Additional exploit detection identified {len(vulnerabilities)} security issues, "
                    f"including high-severity misconfigurations: {', '.join(v.title for v in crit_high)}."
                )

        return f"{base_summary}{bf_summary}{vuln_summary}"

class GeminiLLMClient(BaseLLMClient):
    """
    Google Gemini Autonomous Reasoning Client.
    Leverages Gemini models (e.g. gemini-3.1-flash-lite) for agent planning,
    login error analysis, and executive security reporting.
    """

    def __init__(self, api_key: str, model: str = "gemini-3.1-flash-lite", console: Optional[Any] = None):
        self.api_key = api_key
        self.model = model
        self.fallback = HeuristicLLMClient()
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.console = console
        self._fallback_active = False
        self._fallback_notified = False

    @property
    def is_offline(self) -> bool:
        return self._fallback_active

    def _notify_fallback(self, reason: str):
        if not self._fallback_notified:
            self._fallback_active = True
            self._fallback_notified = True
            if self.console and hasattr(self.console, "offline_fallback"):
                self.console.offline_fallback(reason)
            elif not (self.console and getattr(self.console, "quiet", False)):
                clean_reason = " ".join(str(reason).split())
                if len(clean_reason) > 100:
                    clean_reason = clean_reason[:97] + "..."
                print(f"[!] AI service unavailable ({clean_reason}). Falling back to offline system (using offline heuristic engine).\n")

    def _call_gemini(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        timeout: int = 15,
    ) -> str:
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        payload: Dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}
        if json_mode:
            payload["generationConfig"] = {"responseMimeType": "application/json"}

        resp = requests.post(url, json=payload, timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"Gemini API returned HTTP {resp.status_code}: {resp.text}")

        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            raise RuntimeError("Gemini API returned no candidates")

        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            raise RuntimeError("Gemini candidate has no parts")

        return parts[0].get("text", "")

    def plan_next_technique(
        self,
        target_url: str,
        available_techniques: List[str],
        executed_techniques: List[str],
        discovered_users: List[DiscoveredUser],
        last_observation: str,
    ) -> Tuple[str, str]:
        if not available_techniques:
            return "STOP", "All techniques evaluated."

        if self._fallback_active:
            return self.fallback.plan_next_technique(
                target_url, available_techniques, executed_techniques, discovered_users, last_observation
            )

        prompt = NEXT_TECHNIQUE_PROMPT.format(
            target_url=target_url,
            discovered_users_count=len(discovered_users),
            discovered_usernames=", ".join(u.username for u in discovered_users),
            executed_techniques=", ".join(executed_techniques) or "None",
            available_techniques=", ".join(available_techniques),
            last_observation=last_observation or "Initial reconnaissance phase",
        )

        try:
            raw = self._call_gemini(prompt, system_prompt=AGENT_SYSTEM_PROMPT, json_mode=True, timeout=15)
            parsed = json.loads(raw)
            action = parsed.get("action", available_techniques[0])
            thought = parsed.get("thought", f"Trying {action} enumeration.")
            if action not in available_techniques and action != "STOP":
                action = available_techniques[0]
            return action, thought
        except Exception as e:
            self._notify_fallback(str(e))
            logger.warning(f"Gemini planning call failed ({e}); falling back to heuristic engine.")
            return self.fallback.plan_next_technique(
                target_url, available_techniques, executed_techniques, discovered_users, last_observation
            )

    def analyze_login_response(self, username: str, error_text: str) -> Dict[str, Any]:
        if self._fallback_active:
            return self.fallback.analyze_login_response(username, error_text)

        prompt = LOGIN_ERROR_ANALYSIS_PROMPT.format(username=username, error_text=error_text[:1200])
        try:
            raw = self._call_gemini(prompt, system_prompt=AGENT_SYSTEM_PROMPT, json_mode=True, timeout=15)
            return json.loads(raw)
        except Exception as e:
            self._notify_fallback(str(e))
            return self.fallback.analyze_login_response(username, error_text)

    def generate_summary(
        self,
        target_url: str,
        techniques_used: List[str],
        discovered_users: List[DiscoveredUser],
        bruteforce_results: Optional[List[BruteforceResult]],
        vulnerabilities: List[VulnerabilityFinding],
    ) -> str:
        if self._fallback_active:
            return self.fallback.generate_summary(
                target_url, techniques_used, discovered_users, bruteforce_results, vulnerabilities
            )

        prompt = FINAL_SUMMARY_PROMPT.format(
            target_url=target_url,
            techniques_used=", ".join(techniques_used),
            discovered_users=json.dumps([u.to_output_dict() for u in discovered_users]),
            bruteforce_results=json.dumps([b.model_dump() for b in (bruteforce_results or [])]),
            vulnerabilities=json.dumps([v.title for v in vulnerabilities]),
        )
        try:
            return self._call_gemini(prompt, system_prompt=AGENT_SYSTEM_PROMPT, json_mode=False, timeout=25).strip()
        except Exception as e:
            self._notify_fallback(str(e))
            logger.warning(f"Gemini summary generation failed ({e}); using heuristic report generator.")
            return self.fallback.generate_summary(
                target_url, techniques_used, discovered_users, bruteforce_results, vulnerabilities
            )


def get_llm_client(config: ScanConfig, console: Optional[Any] = None) -> BaseLLMClient:
    """Factory to return Google Gemini client or deterministic heuristic engine."""
    api_key = getattr(config, "api_key", None)
    if not api_key or not api_key.strip():
        return HeuristicLLMClient()

    return GeminiLLMClient(
        api_key=api_key.strip(),
        model=getattr(config, "model", None) or "gemini-3.1-flash-lite",
        console=console,
    )
