from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DiscoveredUser(BaseModel):
    """Represents a discovered WordPress user account."""
    username: str
    evidence: str
    slug: Optional[str] = None
    user_id: Optional[int] = None
    display_name: Optional[str] = None
    role: Optional[str] = None
    technique: str = "unknown"
    is_admin_candidate: bool = False

    def to_output_dict(self) -> Dict[str, str]:
        """Output format matching assignment specification (Section 6.2)."""
        return {
            "username": self.username,
            "evidence": self.evidence,
        }


class BruteforceResult(BaseModel):
    """Result of credential brute-force testing against identified accounts."""
    target_user: str
    attempt_count: int = 0
    success: bool = False
    cracked_password: Optional[str] = None
    method_used: str = "wp-login.php"
    details: str = ""


class VulnerabilityFinding(BaseModel):
    """Vulnerability or misconfiguration detected on the target WordPress instance."""
    id: str
    title: str
    severity: str = "MEDIUM"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None


class AgentTraceStep(BaseModel):
    """A single step in the AI Agent's ReAct (Reasoning + Action) execution loop."""
    step_number: int
    thought: str
    action: str
    action_input: Optional[Dict[str, Any]] = None
    observation: str


class ScanConfig(BaseModel):
    """Configuration options for the enumeration and vulnerability scan."""
    target_url: str
    techniques: List[str] = Field(
        default_factory=lambda: [
            "rest_api",
            "author_archive",
            "login_leak",
            "feed_sniffer",
            "sitemap_sniffer",
            "oembed_sniffer",
        ]
    )
    timeout: int = 10
    user_agent: str = "Astra-WP-Recon/1.0"
    max_authors: int = 10
    verify_ssl: bool = False
    bruteforce_enabled: bool = True
    max_bruteforce_attempts: int = 15
    bruteforce_delay: float = 0.2
    wordlist_path: Optional[str] = None
    api_key: Optional[str] = None
    model: str = "gemini-3.1-flash-lite"
    verbose: bool = False
    run_exploit_checks: bool = True


class ScanResult(BaseModel):
    """Complete structured output of the reconnaissance scan."""
    target: str
    techniques_used: List[str]
    users: List[Dict[str, str]]
    full_user_details: List[DiscoveredUser] = Field(default_factory=list)
    bruteforce_results: Optional[List[BruteforceResult]] = None
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    ai_summary: str
    agent_trace: List[AgentTraceStep] = Field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: str = ""

    def to_assignment_json(self) -> Dict[str, Any]:
        """
        Produces exact JSON format specified in Section 6.2 of the assignment:
        {
          "target": "http://localhost:8080",
          "techniques_used": ["rest_api"],
          "users": [
            { "username": "admin", "evidence": "/wp-json/wp/v2/users" },
            { "username": "editor", "evidence": "/wp-json/wp/v2/users" }
          ],
          "ai_summary": "..."
        }
        """
        payload: Dict[str, Any] = {
            "target": self.target,
            "techniques_used": self.techniques_used,
            "users": self.users,
            "ai_summary": self.ai_summary,
        }
        if self.bruteforce_results:
            payload["bruteforce_results"] = [
                res.model_dump() for res in self.bruteforce_results
            ]
        if self.vulnerabilities:
            payload["vulnerabilities"] = [
                v.model_dump() for v in self.vulnerabilities
            ]
        return payload
