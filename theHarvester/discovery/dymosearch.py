from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname


class SearchDymo:
    """Dymo API data verifier source.

    Dymo provides a verification endpoint that takes a domain (and optionally
    an email/url/ip/phone) and returns metadata such as MX presence, fraud
    flags, free-subdomain detection, ``didYouMean`` suggestions and the
    canonical domain. theHarvester does not call it for bulk discovery; it
    treats it as a low-volume enrichment pass that can confirm the target
    domain and surface near-miss suggestions as additional host candidates.

    API docs: https://docs.tpeoficial.com/docs/dymo-api/private/data-verifier
    """

    VERIFY_URL = 'https://api.tpeoficial.com/v1/private/secure/verify'

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set[str] = set()
        self.results: dict[str, Any] = {}
        self.key = Core.dymo_key()
        if not isinstance(self.key, str) or not self.key.strip():
            raise MissingKey('dymo')
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self.totalhosts else status
        self.stop_reason = reason

    def _headers(self) -> dict[str, str]:
        return {
            'User-Agent': Core.get_user_agent(),
            'Authorization': f'Bearer {self.key}',
            'Content-Type': 'application/json',
        }

    async def do_search(self) -> None:
        payload = {
            'domain': self.word,
            'url': f'https://{self.word}',
        }
        response = await AsyncFetcher.post_fetch(
            self.VERIFY_URL,
            headers=self._headers(),
            json=True,
            json_body=payload,
            proxy=self.proxy,
            include_metadata=True,
        )
        if error := provider_http_error(response):
            self._stop(*error)
            return
        assert isinstance(response, FetcherResponse)
        if not isinstance(response.body, dict):
            self._stop('failed', 'invalid-response')
            return

        self.results = response.body

        raw_domain_block = response.body.get('domain')
        raw_url_block = response.body.get('url')
        malformed = any(block is not None and not isinstance(block, dict) for block in (raw_domain_block, raw_url_block))
        domain_block = raw_domain_block if isinstance(raw_domain_block, dict) else {}
        url_block = raw_url_block if isinstance(raw_url_block, dict) else {}

        for block in (domain_block, url_block):
            candidate = block.get('domain') if isinstance(block, dict) else None
            if normalized := normalize_scoped_hostname(candidate, self.word):
                self.totalhosts.add(normalized)
            elif candidate is not None and not isinstance(candidate, str):
                malformed = True

            suggestion = block.get('didYouMean') if isinstance(block, dict) else None
            if normalized := normalize_scoped_hostname(suggestion, self.word):
                self.totalhosts.add(normalized)
            elif suggestion is not None and not isinstance(suggestion, str):
                malformed = True

        if malformed:
            self._stop('failed', 'invalid-response')
        else:
            self.execution_status = 'completed'
            self.stop_reason = None if self.totalhosts else 'no-results'

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_results(self) -> dict[str, Any]:
        return self.results

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        self.execution_status = None
        self.stop_reason = None
        try:
            await self.do_search()
        except Exception:
            self._stop('failed', 'transport-error')
