import re
import warnings
from typing import List, Dict, Any
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

from astra_recon.enumerators.base import BaseEnumerator
from astra_recon.models import DiscoveredUser
from astra_recon.utils.http_client import HttpClient


class FeedSnifferEnumerator(BaseEnumerator):
    """
    RSS / Atom Feed Creator Enumeration
    WordPress automatically embeds author usernames inside RSS and Atom feeds
    using <dc:creator> tags or <author> elements.
    """

    name = "feed_sniffer"
    description = "Parses RSS/Atom feeds (/feed/, /?feed=rss2, /comments/feed/) for <dc:creator> author tags"

    FEED_ENDPOINTS = [
        "/feed/",
        "/?feed=rss2",
        "/feed/atom/",
        "/comments/feed/",
    ]

    CREATOR_REGEX = re.compile(r"<dc:creator>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</dc:creator>", re.IGNORECASE)

    def run(
        self,
        target_url: str,
        client: HttpClient,
        context: Dict[str, Any],
    ) -> List[DiscoveredUser]:
        users: List[DiscoveredUser] = []
        seen_usernames = set()

        for ep in self.FEED_ENDPOINTS:
            url = f"{target_url}{ep}"
            resp = client.safe_get(url)

            if not resp.is_success or not resp.text:
                continue

            content = resp.text

            # 1. Regex extraction for dc:creator
            matches = self.CREATOR_REGEX.findall(content)
            for raw_author in matches:
                author_clean = raw_author.strip()
                if author_clean and len(author_clean) < 60:
                    slug = author_clean.lower()
                    if slug not in seen_usernames:
                        seen_usernames.add(slug)
                        users.append(
                            DiscoveredUser(
                                username=slug,
                                slug=slug,
                                display_name=author_clean,
                                evidence=f"{ep} (<dc:creator> tag)",
                                technique="feed_sniffer",
                                is_admin_candidate=(slug in ("admin", "administrator", "root")),
                            )
                        )

            # 2. BeautifulSoup XML parsing fallback
            try:
                soup = BeautifulSoup(content, "html.parser")
                for item in soup.find_all(["item", "entry"]):
                    creator = item.find(["dc:creator", "creator", "name"])
                    if creator and creator.text:
                        slug = creator.text.strip().lower()
                        if slug and slug not in seen_usernames:
                            seen_usernames.add(slug)
                            users.append(
                                DiscoveredUser(
                                    username=slug,
                                    slug=slug,
                                    display_name=creator.text.strip(),
                                    evidence=f"{ep} (feed author tag)",
                                    technique="feed_sniffer",
                                    is_admin_candidate=(slug in ("admin", "administrator", "root")),
                                )
                            )
            except Exception:
                pass

            if users:
                break

        return users
