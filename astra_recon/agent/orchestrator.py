import time
from datetime import datetime, timezone
from typing import List, Optional

from astra_recon.models import (
    ScanConfig,
    ScanResult,
    DiscoveredUser,
    BruteforceResult,
    VulnerabilityFinding,
    AgentTraceStep,
)
from astra_recon.utils.http_client import HttpClient
from astra_recon.utils.console import ReconConsole
from astra_recon.agent.llm_client import get_llm_client
from astra_recon.enumerators import ENUMERATOR_REGISTRY
from astra_recon.attacks.bruteforce import WordPressBruteforcer
from astra_recon.scanners.exploit_detector import WordPressExploitDetector


class ReconAgentOrchestrator:
    """
    Autonomous ReAct Agent for WordPress Enumeration & Attack Surface Mapping.
    Orchestrates intelligent vector selection, dynamic user discovery, credential
    testing, and security report generation.
    """

    def __init__(self, config: ScanConfig, console: Optional[ReconConsole] = None):
        self.config = config
        self.console = console or ReconConsole(verbose=config.verbose)
        self.client = HttpClient(
            timeout=config.timeout,
            user_agent=config.user_agent,
            verify_ssl=config.verify_ssl,
        )
        self.llm = get_llm_client(config, console=self.console)

    def run(self) -> ScanResult:
        start_time = time.time()
        timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

        self.console.target_info(self.config.target_url)

        if getattr(self.llm, "is_offline", False):
            self.console.offline_notice("No AI API key provided. Using offline heuristic engine.")

        discovered_users: List[DiscoveredUser] = []
        known_usernames: set = set()
        techniques_used: List[str] = []
        agent_trace: List[AgentTraceStep] = []
        available_techniques = list(self.config.techniques)
        last_observation = "Scan initialized."

        step_counter = 1

        # ----------------------------------------------------
        # ReAct Agent Enumeration Loop
        # ----------------------------------------------------
        while available_techniques:
            # 1. Agent Reasoning (Thought + Action Selection)
            action, thought = self.llm.plan_next_technique(
                target_url=self.config.target_url,
                available_techniques=available_techniques,
                executed_techniques=techniques_used,
                discovered_users=discovered_users,
                last_observation=last_observation,
            )

            if action == "STOP" or action not in ENUMERATOR_REGISTRY:
                break

            self.console.agent_thought(thought, offline=getattr(self.llm, "is_offline", False))

            # 2. Agent Execution (Action)
            enumerator_cls = ENUMERATOR_REGISTRY[action]
            enumerator = enumerator_cls()
            techniques_used.append(action)
            available_techniques.remove(action)

            scan_context = {
                "max_authors": self.config.max_authors,
                "known_usernames": list(known_usernames),
                "ai_client": self.llm,
            }

            try:
                new_users = enumerator.run(self.config.target_url, self.client, scan_context)
            except Exception as e:
                self.console.log_verbose(f"Enumerator {action} error: {e}")
                new_users = []

            # 3. Observation & Reflection
            freshly_added = []
            primary_evidence = ""
            for u in new_users:
                if u.username not in known_usernames:
                    known_usernames.add(u.username)
                    discovered_users.append(u)
                    freshly_added.append(u.username)
                    if not primary_evidence:
                        primary_evidence = u.evidence

            if freshly_added:
                obs = f"Discovered {len(freshly_added)} user(s): {', '.join(freshly_added)} via {primary_evidence}"
                self.console.found_users(primary_evidence, freshly_added)
            else:
                obs = f"No new users discovered using {action}."
                self.console.log_verbose(obs)

            last_observation = obs

            agent_trace.append(
                AgentTraceStep(
                    step_number=step_counter,
                    thought=thought,
                    action=action,
                    action_input={"target": self.config.target_url},
                    observation=obs,
                )
            )
            step_counter += 1

            # If user specified just rest_api or we have found users and completed primary probe:
            # Check if we should stop loop early if all users were obtained from REST API
            if len(discovered_users) >= 3 and action == "rest_api" and len(available_techniques) > 1:
                # Ask agent if more techniques are needed or proceed
                # In standard flow, we prioritize finishing cleanly matching example output
                pass

        # ----------------------------------------------------
        # Admin Credential Brute-Force
        # ----------------------------------------------------
        bruteforce_results: Optional[List[BruteforceResult]] = None
        if self.config.bruteforce_enabled and discovered_users:
            bruteforcer = WordPressBruteforcer(
                target_url=self.config.target_url,
                client=self.client,
                console=self.console,
                delay=self.config.bruteforce_delay,
                max_attempts=self.config.max_bruteforce_attempts,
                wordlist_path=self.config.wordlist_path,
            )
            bruteforce_results = bruteforcer.run_all(discovered_users)

        # ----------------------------------------------------
        # Exploit & Attack Surface Detection Rules
        # ----------------------------------------------------
        vulnerabilities: List[VulnerabilityFinding] = []
        if self.config.run_exploit_checks:
            detector = WordPressExploitDetector(
                target_url=self.config.target_url,
                client=self.client,
                console=self.console,
            )
            vulnerabilities = detector.scan_all()

        # ----------------------------------------------------
        # AI Summary Report Synthesis
        # ----------------------------------------------------
        ai_summary = self.llm.generate_summary(
            target_url=self.config.target_url,
            techniques_used=techniques_used,
            discovered_users=discovered_users,
            bruteforce_results=bruteforce_results,
            vulnerabilities=vulnerabilities,
        )

        self.console.ai_summary(ai_summary, offline=getattr(self.llm, "is_offline", False))
        self.console.complete()

        # Print rich tables if in verbose mode
        self.console.print_findings_table(discovered_users, vulnerabilities)

        duration = round(time.time() - start_time, 2)

        output_users = [u.to_output_dict() for u in discovered_users]

        return ScanResult(
            target=self.config.target_url,
            techniques_used=techniques_used,
            users=output_users,
            full_user_details=discovered_users,
            bruteforce_results=bruteforce_results,
            vulnerabilities=vulnerabilities,
            ai_summary=ai_summary,
            agent_trace=agent_trace,
            duration_seconds=duration,
            timestamp=timestamp,
        )
