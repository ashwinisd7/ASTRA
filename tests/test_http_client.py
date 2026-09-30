import unittest
from unittest.mock import MagicMock, patch
from astra_recon.utils.http_client import HttpClient, HttpResponse


class TestHttpClientRetryAfter(unittest.TestCase):

    @patch("time.sleep")
    def test_retry_after_seconds_on_429(self, mock_sleep):
        client = HttpClient(max_retries=2)

        # Mock first response as 429 with Retry-After: 3, second response as 200 OK
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "3"}
        resp_429.history = []

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = "Success after rate limit"
        resp_200.headers = {"Content-Type": "text/html"}
        resp_200.url = "http://example.com/test"
        resp_200.history = []

        with patch.object(client.session, "get", side_effect=[resp_429, resp_200]) as mock_get:
            res = client.safe_get("http://example.com/test")
            self.assertEqual(mock_get.call_count, 2)
            mock_sleep.assert_called_once_with(3.0)
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.text, "Success after rate limit")

    @patch("time.sleep")
    def test_retry_after_exhaustion(self, mock_sleep):
        client = HttpClient(max_retries=2)

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.text = "Still rate limited"
        resp_429.headers = {"Retry-After": "1"}
        resp_429.url = "http://example.com/rate-limited"
        resp_429.history = []

        with patch.object(client.session, "get", return_value=resp_429) as mock_get:
            res = client.safe_get("http://example.com/rate-limited")
            # 1 initial attempt + 2 retries = 3 calls
            self.assertEqual(mock_get.call_count, 3)
            self.assertEqual(mock_sleep.call_count, 2)
            self.assertEqual(res.status_code, 429)

    @patch("time.sleep")
    def test_retry_after_capped_at_max(self, mock_sleep):
        client = HttpClient(max_retries=1, max_retry_after=10.0)

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "9999"}
        resp_429.history = []

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = "OK"
        resp_200.headers = {}
        resp_200.url = "http://example.com"
        resp_200.history = []

        with patch.object(client.session, "get", side_effect=[resp_429, resp_200]):
            res = client.safe_get("http://example.com")
            # Should cap delay at 10.0 instead of 9999
            mock_sleep.assert_called_once_with(10.0)
            self.assertEqual(res.status_code, 200)

    @patch("time.sleep")
    def test_retry_after_default_fallback(self, mock_sleep):
        client = HttpClient(max_retries=1, default_retry_delay=2.5)

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {}  # No Retry-After header
        resp_429.history = []

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = "OK"
        resp_200.headers = {}
        resp_200.url = "http://example.com"
        resp_200.history = []

        with patch.object(client.session, "post", side_effect=[resp_429, resp_200]):
            res = client.safe_post("http://example.com")
            mock_sleep.assert_called_once_with(2.5)
            self.assertEqual(res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
