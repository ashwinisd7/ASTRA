import os
import json
from astra_recon.models import ScanResult


class ReportGenerator:
    """Generates structured JSON and Markdown audit reports from scan results."""

    @staticmethod
    def to_json(result: ScanResult, pretty: bool = True) -> str:
        """Returns JSON matching assignment specification (Section 6.2)."""
        data = result.to_assignment_json()
        if pretty:
            return json.dumps(data, indent=2)
        return json.dumps(data)

    @staticmethod
    def save_json(result: ScanResult, filepath: str) -> None:
        """Saves JSON report to designated file."""
        parent_dir = os.path.dirname(filepath)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(ReportGenerator.to_json(result, pretty=True))

    @staticmethod
    def to_markdown(result: ScanResult) -> str:
        """Generates an audit report in Markdown format."""
        md = []
        md.append(f"# Astra Security - WordPress Reconnaissance Report\n")
        md.append(f"**Target URL:** `{result.target}`  ")
        md.append(f"**Scan Timestamp:** `{result.timestamp}`  ")
        md.append(f"**Duration:** `{result.duration_seconds}s`  ")
        md.append(f"**Techniques Evaluated:** {', '.join(f'`{t}`' for t in result.techniques_used)}\n")

        md.append("## Executive AI Summary\n")
        md.append(f"> {result.ai_summary}\n")

        md.append("## Discovered User Accounts\n")
        if result.users:
            md.append("| Username | Discovery Vector / Evidence |")
            md.append("| :--- | :--- |")
            for u in result.users:
                md.append(f"| **{u['username']}** | `{u['evidence']}` |")
        else:
            md.append("*No user accounts were exposed through tested endpoints.*")
        md.append("")

        if result.bruteforce_results:
            md.append("## Credential Brute-Force Testing\n")
            md.append("| Target User | Attempts | Status | Cracked Password | Method |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for b in result.bruteforce_results:
                status = "COMPROMISED" if b.success else "NOT COMPROMISED"
                pwd = f"`{b.cracked_password}`" if b.cracked_password else "-"
                md.append(f"| **{b.target_user}** | {b.attempt_count} | **{status}** | {pwd} | `{b.method_used}` |")
            md.append("")

        if result.vulnerabilities:
            md.append("## Exploit & Misconfiguration Findings\n")
            for v in result.vulnerabilities:
                md.append(f"### [{v.severity}] {v.title}")
                md.append(f"- **Description:** {v.description}")
                md.append(f"- **Evidence:** `{v.evidence}`")
                md.append(f"- **Remediation:** {v.remediation}")
                if v.cwe_id:
                    md.append(f"- **Reference:** {v.cwe_id}")
                md.append("")

        if result.agent_trace:
            md.append("## AI Agent ReAct Trace\n")
            for step in result.agent_trace:
                md.append(f"**Step {step.step_number} [{step.action}]**")
                md.append(f"- *Thought:* {step.thought}")
                md.append(f"- *Observation:* {step.observation}")
                md.append("")

        return "\n".join(md)

    @staticmethod
    def save_markdown(result: ScanResult, filepath: str) -> None:
        """Saves Markdown audit report to file."""
        parent_dir = os.path.dirname(filepath)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(ReportGenerator.to_markdown(result))
