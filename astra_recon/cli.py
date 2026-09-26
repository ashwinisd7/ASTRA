import sys
import os
from datetime import datetime
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
import click
from astra_recon.config import build_scan_config
from astra_recon.agent.orchestrator import ReconAgentOrchestrator
from astra_recon.agent.reporter import ReportGenerator
from astra_recon.utils.console import ReconConsole


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "-u", "--url",
    help="Target WordPress URL (e.g. http://localhost:8080). Can also be set via TARGET_URL env var.",
    default=None,
)
@click.option(
    "-c", "--config",
    "config_file",
    help="Path to YAML or JSON configuration file.",
    type=click.Path(exists=True),
    default=None,
)
@click.option(
    "-t", "--techniques",
    help="Comma-separated list of techniques: rest_api, author_archive, login_leak, feed_sniffer, sitemap_sniffer, oembed_sniffer",
    default=None,
)
@click.option(
    "--timeout",
    help="HTTP connection and read timeout in seconds (default: 10).",
    type=int,
    default=None,
)
@click.option(
    "--max-authors",
    help="Maximum author IDs to probe for author archive enumeration (default: 10).",
    type=int,
    default=None,
)
@click.option(
    "--no-bruteforce",
    is_flag=True,
    help="Disable admin credential brute-force testing.",
    default=False,
)
@click.option(
    "-w", "--wordlist",
    help="Path to custom password wordlist file for brute-forcing.",
    type=click.Path(exists=True),
    default=None,
)
@click.option(
    "--max-bruteforce",
    help="Maximum passwords to test per admin user (default: 15).",
    type=int,
    default=None,
)
@click.option(
    "--api-key",
    help="Google Gemini API key (or set API_KEY in .env). If omitted, uses built-in Heuristic AI Engine.",
    default=None,
)
@click.option(
    "--model",
    help="Gemini model identifier (default: gemini-3.1-flash-lite).",
    default=None,
)
@click.option(
    "-o", "--output",
    "output_file",
    help="Save structured JSON scan results to this file.",
    type=click.Path(),
    default=None,
)
@click.option(
    "-r", "--report",
    "report_file",
    help="Save comprehensive Markdown report to this file.",
    type=click.Path(),
    default=None,
)
@click.option(
    "--json",
    "json_mode",
    is_flag=True,
    help="Output strictly JSON to stdout (matching assignment Section 6.2 format).",
    default=False,
)
@click.option(
    "--no-exploit-checks",
    is_flag=True,
    help="Skip auxiliary WordPress exploit detection checks (version, sensitive files, XML-RPC).",
    default=False,
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable detailed debug logs and table outputs.",
    default=False,
)
@click.option(
    "-q", "--quiet",
    is_flag=True,
    help="Suppress banners and status messages.",
    default=False,
)
def main(
    url,
    config_file,
    techniques,
    timeout,
    max_authors,
    no_bruteforce,
    wordlist,
    max_bruteforce,
    api_key,
    model,
    output_file,
    report_file,
    json_mode,
    no_exploit_checks,
    verbose,
    quiet,
):
    """
    Astra Security - AI-Driven WordPress User Enumeration & Attack Surface Tool.
    Autonomously probes target WordPress instances, discovers accounts,
    evaluates credentials, and generates AI audit summaries.
    """
    try:
        scan_config = build_scan_config(
            target_url=url,
            config_file=config_file,
            techniques=techniques,
            timeout=timeout,
            max_authors=max_authors,
            no_bruteforce=no_bruteforce,
            wordlist=wordlist,
            max_bruteforce=max_bruteforce,
            api_key=api_key,
            model=model,
            no_exploit_checks=no_exploit_checks,
            verbose=verbose,
        )
    except ValueError as e:
        click.echo(f"[ERROR] Configuration error: {e}", err=True)
        sys.exit(1)

    console = ReconConsole(quiet=quiet or json_mode, verbose=verbose)

    if not json_mode and not quiet:
        console.banner()

    orchestrator = ReconAgentOrchestrator(config=scan_config, console=console)
    result = orchestrator.run()

    # Automatic Report Generation on Scan Completion
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reports", exist_ok=True)
    auto_report_path = os.path.join("reports", f"scan_report_{timestamp_str}.md")
    auto_json_path = os.path.join("reports", f"scan_results_{timestamp_str}.json")

    # Always generate and save reports for every completed scan
    ReportGenerator.save_markdown(result, auto_report_path)
    ReportGenerator.save_markdown(result, "report.md")
    ReportGenerator.save_json(result, auto_json_path)
    ReportGenerator.save_json(result, "results.json")

    # If custom paths were explicitly requested via CLI, save to them as well
    if output_file and output_file not in (auto_json_path, "results.json"):
        ReportGenerator.save_json(result, output_file)

    if report_file and report_file not in (auto_report_path, "report.md"):
        ReportGenerator.save_markdown(result, report_file)

    # Output handling
    if json_mode:
        click.echo(ReportGenerator.to_json(result, pretty=True))
    elif not quiet:
        click.echo("\n[+] Scan complete. Reports automatically generated as report.md and results.json")
        click.echo(f"  - Markdown Report: {auto_report_path} (and report.md)")
        click.echo(f"  - Structured JSON: {auto_json_path} (and results.json)")
        if output_file:
            click.echo(f"  - Custom JSON:    {output_file}")
        if report_file:
            click.echo(f"  - Custom Report:  {report_file}")


cli = main

if __name__ == "__main__":
    main()
