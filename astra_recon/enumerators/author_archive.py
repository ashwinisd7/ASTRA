import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup

from astra_recon.enumerators.base import BaseEnumerator
from astra_recon.models import DiscoveredUser
from astra_recon.utils.http_client import HttpClient


class AuthorArchiveEnumerator(BaseEnumerator):
    """
    Author Archive Routing Enumeration (?author=N)
    WordPress redirects query parameter ?author=N (301/302) to the canonical author
    archive URL /author/<username>/, leaking the username slug in the Location header
    or HTML document body.
    """

    name = "author_archive"
    description = "Queries ?author=N and extracts username slugs from 301/302 redirects or canonical headers"

    # Regex patterns for author slug extraction
    AUTHOR_URL_PATTERN = re.compile(r"/author/([a-zA-Z0-9_\-\.]+)/?", re.IGNORECASE)
    BODY_CLASS_PATTERN = re.compile(r"author-([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)

    def run(
        self,
        target_url: str,
        client: HttpClient,
        context: Dict[str, Any],
    ) -> List[DiscoveredUser]:
        users: List[DiscoveredUser] = []
        seen_usernames = set()
        max_authors = context.get("max_authors", 10)

        consecutive_not_found = 0

        for author_id in range(1, max_authors + 1):
            probe_url = f"{target_url}/?author={author_id}"

            # Step 1: Probe without following redirects to inspect Location header
            resp = client.safe_get(probe_url, allow_redirects=False)

            slug_found = None
            evidence_str = f"?author={author_id}"

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location") or resp.headers.get("location") or ""
                match = self.AUTHOR_URL_PATTERN.search(location)
                if match:
                    slug_found = match.group(1)
                    evidence_str = f"?author={author_id} -> {location}"

            # Step 2: If no redirect header was captured, follow redirect or inspect HTML body
            if not slug_found:
                resp_full = client.safe_get(probe_url, allow_redirects=True)
                if resp_full.is_success and resp_full.url != target_url and resp_full.url != f"{target_url}/":
                    # Check redirected final URL
                    match = self.AUTHOR_URL_PATTERN.search(resp_full.url)
                    if match:
                        slug_found = match.group(1)
                        evidence_str = f"?author={author_id} -> {resp_full.url}"

                # Step 3: Parse HTML tags (canonical link, body classes, feeds)
                if not slug_found and resp_full.text:
                    soup = BeautifulSoup(resp_full.text, "html.parser")

                    # Check canonical link
                    canonical = soup.find("link", rel=lambda r: r and "canonical" in r)
                    if canonical and canonical.get("href"):
                        href_match = self.AUTHOR_URL_PATTERN.search(canonical["href"])
                        if href_match:
                            slug_found = href_match.group(1)
                            evidence_str = f"?author={author_id} canonical link"

                    # Check body class
                    if not slug_found:
                        body = soup.find("body")
                        if body and body.get("class"):
                            body_classes = " ".join(body.get("class", []))
                            class_match = self.BODY_CLASS_PATTERN.search(body_classes)
                            if class_match:
                                candidate = class_match.group(1)
                                if candidate not in ("paged", "archive", "format"):
                                    slug_found = candidate
                                    evidence_str = f"?author={author_id} body.author-{candidate}"

            if slug_found:
                consecutive_not_found = 0
                slug_clean = slug_found.lower().strip()
                if slug_clean not in seen_usernames:
                    seen_usernames.add(slug_clean)
                    users.append(
                        DiscoveredUser(
                            username=slug_clean,
                            slug=slug_clean,
                            user_id=author_id,
                            evidence=evidence_str,
                            technique="author_archive",
                            is_admin_candidate=(
                                slug_clean in ("admin", "administrator", "root")
                                or author_id == 1
                            ),
                        )
                    )
            else:
                consecutive_not_found += 1
                # If 5 IDs in a row return nothing, stop scanning further IDs
                if consecutive_not_found >= 5 and author_id > 5:
                    break

        return users
