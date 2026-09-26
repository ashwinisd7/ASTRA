import logging
from typing import Dict, Any, Optional, List
import requests
import urllib3

# Suppress insecure request warnings when testing self-hosted / local instances with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class HttpResponse:
    """Safe wrapper around requests.Response."""
    def __init__(
        self,
        status_code: int = 0,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
        redirect_history: Optional[List[str]] = None,
        error: Optional[str] = None,
        raw_response: Optional[requests.Response] = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.redirect_history = redirect_history or []
        self.error = error
        self.raw_response = raw_response

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Optional[Any]:
        """Safely parse JSON without raising exceptions."""
        if not self.text:
            return None
        try:
            if self.raw_response:
                return self.raw_response.json()
            import json
            return json.loads(self.text)
        except Exception:
            return None


class HttpClient:
    """Resilient HTTP client with retry logic, timeouts, and error handling."""

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = "Astra-WP-Recon/1.0",
        verify_ssl: bool = False,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

    def safe_get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        timeout: Optional[int] = None,
    ) -> HttpResponse:
        """Safely execute GET request without throwing unhandled exceptions."""
        req_timeout = timeout or self.timeout
        try:
            resp = self.session.get(
                url,
                params=params,
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=req_timeout,
                verify=self.verify_ssl,
            )
            redirects = [r.url for r in resp.history]
            return HttpResponse(
                status_code=resp.status_code,
                text=resp.text,
                headers=dict(resp.headers),
                url=resp.url,
                redirect_history=redirects,
                raw_response=resp,
            )
        except requests.exceptions.Timeout:
            return HttpResponse(error=f"Timeout after {req_timeout}s connecting to {url}")
        except requests.exceptions.SSLError as e:
            return HttpResponse(error=f"SSL certificate validation error: {e}")
        except requests.exceptions.ConnectionError as e:
            return HttpResponse(error=f"Connection refused / Network unreachable: {e}")
        except requests.exceptions.TooManyRedirects:
            return HttpResponse(error="Exceeded maximum redirect loop threshold")
        except Exception as e:
            return HttpResponse(error=f"Unexpected network error: {e}")

    def safe_post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = False,
        timeout: Optional[int] = None,
    ) -> HttpResponse:
        """Safely execute POST request."""
        req_timeout = timeout or self.timeout
        try:
            resp = self.session.post(
                url,
                data=data,
                json=json,
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=req_timeout,
                verify=self.verify_ssl,
            )
            redirects = [r.url for r in resp.history]
            return HttpResponse(
                status_code=resp.status_code,
                text=resp.text,
                headers=dict(resp.headers),
                url=resp.url,
                redirect_history=redirects,
                raw_response=resp,
            )
        except requests.exceptions.Timeout:
            return HttpResponse(error=f"Timeout after {req_timeout}s posting to {url}")
        except requests.exceptions.ConnectionError as e:
            return HttpResponse(error=f"Connection error: {e}")
        except Exception as e:
            return HttpResponse(error=f"POST error: {e}")
