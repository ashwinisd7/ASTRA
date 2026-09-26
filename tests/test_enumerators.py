import unittest
from unittest.mock import MagicMock

from astra_recon.enumerators.rest_api import RestApiEnumerator
from astra_recon.enumerators.author_archive import AuthorArchiveEnumerator
from astra_recon.enumerators.login_leak import LoginLeakEnumerator
from astra_recon.enumerators.feed_sniffer import FeedSnifferEnumerator
from astra_recon.enumerators.sitemap_sniffer import SitemapSnifferEnumerator
from astra_recon.enumerators.oembed_sniffer import OembedSnifferEnumerator
from astra_recon.utils.http_client import HttpResponse


class TestEnumerators(unittest.TestCase):

    def test_rest_api_enumerator_standard(self):
        mock_client = MagicMock()
        mock_resp = HttpResponse(
            status_code=200,
            text='[{"id": 1, "slug": "admin", "name": "Admin User"}, {"id": 2, "slug": "editor", "name": "Editor"}]',
        )
        mock_client.safe_get.return_value = mock_resp

        enumerator = RestApiEnumerator()
        users = enumerator.run("http://test-wp.local", mock_client, {})

        self.assertEqual(len(users), 2)
        self.assertEqual(users[0].username, "admin")
        self.assertTrue(users[0].is_admin_candidate)
        self.assertEqual(users[1].username, "editor")
        self.assertEqual(users[0].evidence, "/wp-json/wp/v2/users")

    def test_author_archive_redirect(self):
        mock_client = MagicMock()
        # Mock 301 redirect for author=1, 404 for others
        def side_effect(url, **kwargs):
            if "author=1" in url:
                return HttpResponse(
                    status_code=301,
                    headers={"Location": "http://test-wp.local/author/secadmin/"},
                )
            return HttpResponse(status_code=404)

        mock_client.safe_get.side_effect = side_effect

        enumerator = AuthorArchiveEnumerator()
        users = enumerator.run("http://test-wp.local", mock_client, {"max_authors": 2})

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].username, "secadmin")
        self.assertIn("author=1", users[0].evidence)

    def test_login_leak_enumerator(self):
        mock_client = MagicMock()
        mock_client.safe_get.return_value = HttpResponse(status_code=200, text="loginform")

        def post_side_effect(url, data=None, **kwargs):
            username = data.get("log")
            if username == "admin":
                return HttpResponse(
                    status_code=200,
                    text='<div id="login_error">The password you entered for the username admin is incorrect.</div>',
                )
            return HttpResponse(
                status_code=200,
                text='<div id="login_error">Unknown username. Check again or try your email address.</div>',
            )

        mock_client.safe_post.side_effect = post_side_effect

        enumerator = LoginLeakEnumerator()
        users = enumerator.run("http://test-wp.local", mock_client, {"max_login_probes": 2})

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].username, "admin")
        self.assertEqual(users[0].technique, "login_leak")

    def test_feed_sniffer(self):
        mock_client = MagicMock()
        feed_xml = """<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
        <channel>
            <item>
                <dc:creator><![CDATA[superauthor]]></dc:creator>
            </item>
        </channel>
        </rss>"""
        mock_client.safe_get.return_value = HttpResponse(status_code=200, text=feed_xml)

        enumerator = FeedSnifferEnumerator()
        users = enumerator.run("http://test-wp.local", mock_client, {})

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].username, "superauthor")

    def test_sitemap_sniffer(self):
        mock_client = MagicMock()
        sitemap_xml = """<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>http://test-wp.local/author/sitemapuser/</loc></url>
        </urlset>"""
        mock_client.safe_get.return_value = HttpResponse(status_code=200, text=sitemap_xml)

        enumerator = SitemapSnifferEnumerator()
        users = enumerator.run("http://test-wp.local", mock_client, {})

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].username, "sitemapuser")

    def test_oembed_sniffer(self):
        mock_client = MagicMock()
        mock_client.safe_get.return_value = HttpResponse(
            status_code=200,
            text='{"author_name": "oembed_admin", "author_url": "http://test-wp.local/author/oembed_admin/"}',
        )

        enumerator = OembedSnifferEnumerator()
        users = enumerator.run("http://test-wp.local", mock_client, {})

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].username, "oembed_admin")


if __name__ == "__main__":
    unittest.main()
