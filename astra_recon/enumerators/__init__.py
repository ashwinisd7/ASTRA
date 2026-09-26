from typing import Dict, Type
from astra_recon.enumerators.base import BaseEnumerator
from astra_recon.enumerators.rest_api import RestApiEnumerator
from astra_recon.enumerators.author_archive import AuthorArchiveEnumerator
from astra_recon.enumerators.login_leak import LoginLeakEnumerator
from astra_recon.enumerators.feed_sniffer import FeedSnifferEnumerator
from astra_recon.enumerators.sitemap_sniffer import SitemapSnifferEnumerator
from astra_recon.enumerators.oembed_sniffer import OembedSnifferEnumerator

ENUMERATOR_REGISTRY: Dict[str, Type[BaseEnumerator]] = {
    "rest_api": RestApiEnumerator,
    "author_archive": AuthorArchiveEnumerator,
    "login_leak": LoginLeakEnumerator,
    "feed_sniffer": FeedSnifferEnumerator,
    "sitemap_sniffer": SitemapSnifferEnumerator,
    "oembed_sniffer": OembedSnifferEnumerator,
}

__all__ = [
    "BaseEnumerator",
    "RestApiEnumerator",
    "AuthorArchiveEnumerator",
    "LoginLeakEnumerator",
    "FeedSnifferEnumerator",
    "SitemapSnifferEnumerator",
    "OembedSnifferEnumerator",
    "ENUMERATOR_REGISTRY",
]
