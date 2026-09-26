import os
import json
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from dotenv import load_dotenv

from astra_recon.models import ScanConfig

# Automatically load .env file if available
load_dotenv()


def normalize_url(url: str) -> str:
    """Ensure URL has http/https scheme and no trailing slash."""
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}"
    parsed = urlparse(url)
    # Rebuild normalized URL
    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path.rstrip("/")
    if path:
        return f"{scheme}://{netloc}{path}"
    return f"{scheme}://{netloc}"


def load_config_from_file(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON or YAML file."""
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        if config_path.endswith(".json"):
            return json.load(f)
        elif config_path.endswith((".yaml", ".yml")):
            try:
                import yaml
                return yaml.safe_load(f) or {}
            except ImportError:
                raise ImportError("PyYAML is required to parse YAML config files.")
        else:
            # Fallback to json parsing
            return json.load(f)


def build_scan_config(
    target_url: Optional[str] = None,
    config_file: Optional[str] = None,
    techniques: Optional[str] = None,
    timeout: Optional[int] = None,
    max_authors: Optional[int] = None,
    no_bruteforce: bool = False,
    wordlist: Optional[str] = None,
    max_bruteforce: Optional[int] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    no_exploit_checks: bool = False,
    verbose: bool = False,
    **kwargs,
) -> ScanConfig:
    """
    Builds ScanConfig with hierarchical precedence:
    CLI arguments > Config file > Environment variables > Defaults.
    """
    file_cfg: Dict[str, Any] = {}
    if config_file:
        file_cfg = load_config_from_file(config_file)

    # 1. Target URL
    raw_url = (
        target_url
        or file_cfg.get("target_url")
        or os.getenv("TARGET_URL")
    )
    if not raw_url:
        raise ValueError(
            "Target URL is required! Specify via --url CLI flag, config file, or TARGET_URL env var."
        )
    target = normalize_url(raw_url)

    # 2. Techniques
    if techniques:
        tech_list = [t.strip().lower() for t in techniques.split(",") if t.strip()]
    elif "techniques" in file_cfg:
        tech_list = file_cfg["techniques"]
    elif os.getenv("TECHNIQUES"):
        tech_list = [t.strip().lower() for t in os.getenv("TECHNIQUES", "").split(",") if t.strip()]
    else:
        tech_list = [
            "rest_api",
            "author_archive",
            "login_leak",
            "feed_sniffer",
            "sitemap_sniffer",
            "oembed_sniffer",
        ]

    # 3. Timeout
    req_timeout = (
        timeout
        or file_cfg.get("timeout")
        or int(os.getenv("REQUEST_TIMEOUT", "10"))
    )

    # 4. Max authors
    authors_limit = (
        max_authors
        or file_cfg.get("max_authors")
        or int(os.getenv("MAX_AUTHOR_ID", "10"))
    )

    # 5. Bruteforce settings
    bruteforce_flag = not no_bruteforce
    if "bruteforce_enabled" in file_cfg:
        bruteforce_flag = bool(file_cfg["bruteforce_enabled"])
    elif os.getenv("BRUTEFORCE_ENABLED"):
        bruteforce_flag = os.getenv("BRUTEFORCE_ENABLED", "").lower() in ("true", "1", "yes")

    bf_max = (
        max_bruteforce
        or file_cfg.get("max_bruteforce_attempts")
        or int(os.getenv("MAX_BRUTEFORCE_ATTEMPTS", "15"))
    )

    wordlist_f = (
        wordlist
        or file_cfg.get("wordlist_path")
        or os.getenv("WORDLIST_PATH")
    )

    # 6. AI options
    resolved_key = (
        api_key
        or file_cfg.get("api_key")
        or os.getenv("API_KEY")
    )

    resolved_model = (
        model
        or file_cfg.get("model")
        or os.getenv("MODEL")
        or "gemini-3.1-flash-lite"
    )

    # 7. Exploit checks
    exploit_flag = not no_exploit_checks
    if "run_exploit_checks" in file_cfg:
        exploit_flag = bool(file_cfg["run_exploit_checks"])

    return ScanConfig(
        target_url=target,
        techniques=tech_list,
        timeout=req_timeout,
        max_authors=authors_limit,
        bruteforce_enabled=bruteforce_flag,
        max_bruteforce_attempts=bf_max,
        wordlist_path=wordlist_f,
        api_key=resolved_key,
        model=resolved_model,
        verbose=verbose or file_cfg.get("verbose", False),
        run_exploit_checks=exploit_flag,
    )
