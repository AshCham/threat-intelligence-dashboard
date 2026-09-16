import time
import logging
import requests
from requests.adapters import HTTPAdapter, Retry

log = logging.getLogger(__name__)


# Custom exceptions so Flask routes can handle API failures cleanly
# without needing to inspect raw HTTP status codes everywhere
class VTError(Exception):
    def __init__(self, msg, http_code=None):
        super().__init__(msg)
        self.http_code = http_code

class VTBadKey(VTError):
    pass

class VTRateLimited(VTError):
    pass

class VTNotFound(VTError):
    pass

class VTTimeout(VTError):
    pass


class VirusTotalClient:
    """
    Thin wrapper around VirusTotal API v3.

    Uses a persistent Session for TCP connection reuse - makes a real
    difference on bulk IOC scans where you're hammering the same host repeatedly.

    Note: not safe to share across threads, instantiate per-request.
    """

    BASE = "https://www.virustotal.com/api/v3"
    _POLL_DELAY = 2.5   # seconds between poll attempts
    _MAX_POLLS  = 8     # give up after ~20s

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers["x-apikey"] = api_key

        # retry on transient server errors but NOT on 429 - we handle that ourselves
        # because VT's retry-after header isn't always reliable and we want
        # to return a clean error to the frontend rather than silently spinning
        retry_cfg = Retry(
            total=2,
            backoff_factor=0.4,
            status_forcelist={500, 502, 503},
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry_cfg))

    def _get(self, path):
        log.debug("VT GET /%s", path)
        try:
            vt_resp = self.session.get(f"{self.BASE}/{path}", timeout=15)
        except requests.Timeout:
            raise VTTimeout("VT took too long to respond - try again in a moment.", http_code=504)
        self._check_resp(vt_resp)
        return vt_resp.json()

    def _post(self, path, **kwargs):
        log.debug("VT POST /%s", path)
        try:
            vt_resp = self.session.post(f"{self.BASE}/{path}", timeout=15, **kwargs)
        except requests.Timeout:
            raise VTTimeout("VT took too long to respond.", http_code=504)
        self._check_resp(vt_resp)
        return vt_resp.json()

    @staticmethod
    def _check_resp(vt_resp):
        if vt_resp.status_code == 200:
            return
        if vt_resp.status_code == 401:
            raise VTBadKey("API key rejected - check your .env file.", http_code=401)
        if vt_resp.status_code == 404:
            raise VTNotFound("Target not in VirusTotal database.", http_code=404)
        if vt_resp.status_code == 429:
            # free tier hits this fast, especially during bulk scans
            # TODO: implement exponential backoff + retry here instead of just
            # surfacing the error - would need to track per-minute request count
            raise VTRateLimited(
                "VT rate limit hit (HTTP 429). Wait ~60s and retry, or upgrade to a paid key.",
                http_code=429
            )
        raise VTError(
            f"Unexpected VT response: HTTP {vt_resp.status_code}",
            http_code=vt_resp.status_code,
        )

    def scan_url(self, url: str) -> dict:
        """Submit a URL for scanning and poll until the analysis completes."""
        log.info("Submitting URL to VT: %s", url)

        # had to use the /analyses endpoint here because VT queues fresh URL
        # submissions - the /urls GET endpoint doesn't always have complete
        # scan results ready immediately after submission
        vt_submission = self._post("urls", data={"url": url})
        analysis_id   = vt_submission["data"]["id"]

        for attempt in range(self._MAX_POLLS):
            vt_analysis = self._get(f"analyses/{analysis_id}")
            scan_status = vt_analysis["data"]["attributes"]["status"]
            log.debug("VT poll %d/%d - status: %s", attempt + 1, self._MAX_POLLS, scan_status)
            if scan_status == "completed":
                return vt_analysis
            time.sleep(self._POLL_DELAY)

        # VT occasionally stays stuck in "in-progress" - haven't fully
        # debugged why but it seems to happen more on URLs with a lot of redirects
        raise VTTimeout(
            "Analysis didn't complete within the polling window. Try again shortly.",
            http_code=504,
        )

    def check_ip(self, ip: str) -> dict:
        """Fetch reputation and detection data for an IP address."""
        log.info("Checking IP reputation: %s", ip)
        # TODO: worth caching these lookups locally (Redis/memcached) - the same
        # IPs show up repeatedly in log analysis and each call burns daily quota
        return self._get(f"ip_addresses/{ip}")
