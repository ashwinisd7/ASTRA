import re
from typing import List, Dict, Any
from astra_recon.enumerators.base import BaseEnumerator
from astra_recon.models import DiscoveredUser
from astra_recon.utils.http_client import HttpClient


class OembedSnifferEnumerator(BaseEnumerator):
    """
    oEmbed Author Information Leak
    WordPress oEmbed endpoint (/wp-json/oembed/1.0/embed) leaks author_name and
    author_url when given a post URL.
    """

    name = "oembed_sniffer"
    description = "Queries the oEmbed endpoint (/wp-json/oembed/1.0/embed) to discover author profiles"

    AUTHOR_URL_PATTERN = re.compile(r"/author/([a-zA-Z0-9_\-\.]+)/?", re.IGNORECASE)

    def run(
        self,
        target_url: str,
        client: HttpClient,
        context: Dict[str, Any],
    ) -> List[DiscoveredUser]:
        users: List[DiscoveredUser] = []
        seen_usernames = set()

        # Try default post sample URLs (e.g. ?p=1 or hello-world)
        sample_urls = [
            f"{target_url}/?p=1",
            f"{target_url}/hello-world/",
            f"{target_url}/",
        ]

        for sample in sample_urls:
            endpoint = f"{target_url}/wp-json/oembed/1.0/embed"
            resp = client.safe_get(endpoint, params={"url": sample, "format": "json"})

            if resp.is_success:
                data = resp.json()
                if isinstance(data, dict):
                    author_url = data.get("author_url", "")
                    author_name = data.get("author_name", "")

                    slug = None
                    if author_url:
                        match = self.AUTHOR_URL_PATTERN.search(author_url)
                        if match:
                            slug = match.group(1).lower()

                    if not slug and author_name:
                        # Fallback to sanitized author name
                        slug = re.sub(r"[^a-zA-Z0-9_\-]", "", author_name.lower())

                    if slug and slug not in seen_usernames:
                        seen_usernames.add(slug)
                        users.append(
                            DiscoveredUser(
                                username=slug,
                                slug=slug,
                                display_name=author_name,
                                evidence="/wp-json/oembed/1.0/embed",
                                technique="oembed_sniffer",
                                is_admin_candidate=(slug in ("admin", "administrator", "root")),
                            )
                        )

            if users:
                break

        return users
