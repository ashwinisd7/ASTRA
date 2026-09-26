import sys
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


class ReconConsole:
    """Terminal output formatter matching assignment specifications and Rich styling."""

    def __init__(self, quiet: bool = False, verbose: bool = False):
        self.quiet = quiet
        self.verbose = verbose

    def banner(self):
        """Prints application startup banner."""
        if self.quiet:
            return
        banner_text = (
            "[bold cyan]ASTRA SECURITY[/bold cyan] | "
            "[bold yellow]AI-Driven WordPress User Enumeration & Vulnerability Tool[/bold yellow]\n"
            "[dim]Autonomous reconnaissance, vector probing, and credential security assessment[/dim]"
        )
        try:
            console.print(Panel(banner_text, border_style="cyan", box=box.ASCII))
        except Exception:
            print("=================================================================")
            print("ASTRA SECURITY | AI-Driven WordPress User Enumeration Tool")
            print("=================================================================")

    def target_info(self, target: str):
        if not self.quiet:
            print(f"[+] Target: {target}")
            print("[+] Starting WordPress user enumeration...\n")

    def offline_notice(self, message: str = "Using offline heuristic engine."):
        if not self.quiet:
            print(f"[*] {message}\n")

    def offline_fallback(self, reason: Optional[str] = None):
        if not self.quiet:
            if reason:
                clean_reason = " ".join(str(reason).split())
                if len(clean_reason) > 100:
                    clean_reason = clean_reason[:97] + "..."
                print(f"[!] AI service unavailable ({clean_reason}). Falling back to offline system (using offline heuristic engine).\n")
            else:
                print("[!] AI service unavailable. Falling back to offline system (using offline heuristic engine).\n")

    def agent_thought(self, message: str, offline: bool = False):
        if not self.quiet:
            mode = " (Offline Engine)" if offline else ""
            print(f"[AI Agent]{mode} Selecting technique...")
            print(f"-> {message}")

    def agent_status(self, title: str, details: str):
        if not self.quiet:
            print(f"[AI Agent] {title}")
            print(f"-> {details}")

    def found_users(self, evidence: str, usernames: List[str]):
        if not self.quiet and usernames:
            print(f"\n[+] Found usernames via {evidence}:")
            for u in usernames:
                print(f" - {u}")
            print()

    def bruteforce_status(self, message: str):
        if not self.quiet:
            print(f"[*] [BruteForce] {message}")

    def bruteforce_success(self, username: str, password: str):
        if not self.quiet:
            print(f"[!] [BruteForce SUCCESS] Compromised account '{username}' with password: '{password}'")

    def vulnerability_found(self, severity: str, title: str, evidence: str):
        if not self.quiet:
            print(f"[!] [Vuln: {severity}] {title} (Evidence: {evidence})")

    def ai_summary(self, summary: str, offline: bool = False):
        if not self.quiet:
            mode = " (Offline Heuristic Engine)" if offline else ""
            print(f"[AI Agent] Summary{mode}:")
            print(summary.strip())
            print()

    def complete(self):
        if not self.quiet:
            try:
                "\u2713".encode(sys.stdout.encoding or "ascii")
                print("[\u2713] Enumeration complete.")
            except Exception:
                print("[+] Enumeration complete.")

    def log_verbose(self, message: str):
        if self.verbose:
            console.print(f"[dim gray][DEBUG] {message}[/dim gray]")

    def print_findings_table(self, users: list, vulnerabilities: list):
        """Displays rich tabular summary if in verbose mode or requested."""
        if self.quiet or not self.verbose:
            return

        if users:
            table = Table(title="Enumerated WordPress Accounts", border_style="green", box=box.ASCII)
            table.add_column("Username", style="bold cyan")
            table.add_column("Evidence Vector", style="white")
            table.add_column("Candidate Admin", style="yellow")
            for u in users:
                is_admin = "Yes" if getattr(u, "is_admin_candidate", False) else "No"
                table.add_row(u.username, u.evidence, is_admin)
            console.print(table)

        if vulnerabilities:
            v_table = Table(title="Detected Vulnerabilities & Misconfigurations", border_style="red", box=box.ASCII)
            v_table.add_column("Severity", style="bold red")
            v_table.add_column("Finding", style="white")
            v_table.add_column("Evidence", style="dim")
            for v in vulnerabilities:
                v_table.add_row(v.severity, v.title, v.evidence)
            console.print(v_table)
