import re
from typing import List, Dict, Any

from astra_recon.enumerators.base import BaseEnumerator
from astra_recon.models import DiscoveredUser
from astra_recon.utils.http_client import HttpClient


class SitemapSnifferEnumerator(BaseEnumerator):
    """
    WordPress Core & SEO Plugin Sitemap Enumeration
    WordPress 5.5+ and plugins like Yoast / RankMath expose author URLs inside
    dedicated author sitemaps (/wp-sitemap-users-1.xml or /author-sitemap.xml).
    """

    name = "sitemap_sniffer"
    description = "Inspects WordPress XML sitemaps (/wp-sitemap-users-1.xml, /author-sitemap.xml) for author URLs"

    SITEMAP_ENDPOINTS = [
        "/wp-sitemap-users-1.xml",
        "/author-sitemap.xml",
        "/user-sitemap.xml",
        "/wp-sitemap.xml",
    ]

    AUTHOR_URL_PATTERN = re.compile(r"/author/([a-zA-Z0-9_\-\.]+)/?", re.IGNORECASE)

    def run(
        self,
        target_url: str,
        client: HttpClient,
        context: Dict[str, Any],
    ) -> List[DiscoveredUser]:
        users: List[DiscoveredUser] = []
        seen_usernames = set()

        for ep in self.SITEMAP_ENDPOINTS:
            url = f"{target_url}{ep}"
            resp = client.safe_get(url)

            if not resp.is_success or not resp.text:
                continue

            matches = self.AUTHOR_URL_PATTERN.findall(resp.text)
            for raw_slug in matches:
                slug = raw_slug.lower().strip()
                if slug and slug not in seen_usernames:
                    seen_usernames.add(slug)
                    users.append(
                        DiscoveredUser(
                            username=slug,
                            slug=slug,
                            evidence=f"{ep} (<loc> entry)",
                            technique="sitemap_sniffer",
                            is_admin_candidate=(slug in ("admin", "administrator", "root")),
                        )
                    )

            if users:
                break

        return users
