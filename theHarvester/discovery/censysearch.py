import asyncio
import ssl
from typing import Any

import aiohttp

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.source_execution import SourceExecutionReport


class SearchCensys:
    MAX_RESULTS_PER_PAGE = 100
    SERVER = 'https://api.platform.censys.io/v3/global/search/query'

    def __init__(self, domain: str, limit: int | None = 500) -> None:
        self.word = domain
        token, self.organization_id = Core.censys_key()
        if not isinstance(token, str) or not token.strip():
            raise MissingKey('Censys Personal Access Token')
        self.token = token.strip()
        self.totalhosts: set[str] = set()
        self.emails: set[str] = set()
        self.limit = limit
        self.proxy = False

    @staticmethod
    def _normalize_emails(email_address: object) -> set[str]:
        if isinstance(email_address, str):
            return {email_address}
        if isinstance(email_address, list):
            return {email for email in email_address if isinstance(email, str)}
        return set()

    def _parse_hit(self, hit: object) -> bool:
        if not isinstance(hit, dict):
            return True
        certificate = hit.get('certificate_v1')
        if certificate is None:
            return False
        if not isinstance(certificate, dict) or not isinstance(certificate.get('resource'), dict):
            return True
        resource: dict[str, Any] = certificate['resource']
        names = resource.get('names', [])
        if not isinstance(names, list):
            return True
        self.totalhosts.update(name for name in names if isinstance(name, str))
        parsed = resource.get('parsed', {})
        if not isinstance(parsed, dict):
            return True
        subject = parsed.get('subject', {})
        if not isinstance(subject, dict):
            return True
        self.emails.update(self._normalize_emails(subject.get('email_address')))
        return False

    async def do_search(self) -> SourceExecutionReport | None:
        if self.limit is not None and self.limit <= 0:
            return None

        headers = {'Accept': 'application/json', 'Authorization': f'Bearer {self.token}'}
        params = (
            {'organization_id': self.organization_id.strip()}
            if isinstance(self.organization_id, str) and self.organization_id.strip()
            else ''
        )
        page_token: str | None = None
        seen_tokens: set[str] = set()
        records_seen = 0
        malformed = False

        async with AsyncFetcher.open_session(headers=headers, proxy=self.proxy, request_timeout=720) as session:
            while self.limit is None or records_seen < self.limit:
                body = {
                    'query': f'cert.names: "{self.word}"',
                    'fields': ['cert.names', 'cert.parsed.subject.email_address'],
                    'page_size': min(self.MAX_RESULTS_PER_PAGE, self.limit - records_seen)
                    if self.limit is not None
                    else self.MAX_RESULTS_PER_PAGE,
                }
                if page_token is not None:
                    body['page_token'] = page_token
                try:
                    response = await AsyncFetcher.post_fetch(
                        self.SERVER,
                        session=session,
                        headers=headers,
                        params=params,
                        json=True,
                        proxy=self.proxy,
                        include_metadata=True,
                        json_body=body,
                    )
                except Exception:
                    return SourceExecutionReport('failed', 'transport-error')
                if not isinstance(response, FetcherResponse):
                    return SourceExecutionReport('failed', 'transport-error')
                if response.status == 429:
                    return SourceExecutionReport('rate-limited', 'http-429')
                if response.status in {401, 403}:
                    return SourceExecutionReport('failed', 'access-denied')
                if not 200 <= response.status < 300:
                    return SourceExecutionReport('failed', f'http-{response.status}')
                if not isinstance(response.body, dict) or not isinstance(response.body.get('result'), dict):
                    return SourceExecutionReport('failed', 'invalid-response')
                result = response.body['result']
                hits = result.get('hits')
                next_page_token = result.get('next_page_token')
                if not isinstance(hits, list) or (next_page_token is not None and not isinstance(next_page_token, str)):
                    return SourceExecutionReport('failed', 'invalid-response')

                for hit in hits:
                    if self.limit is not None and records_seen >= self.limit:
                        break
                    malformed = self._parse_hit(hit) or malformed
                    records_seen += 1
                if self.limit is not None and records_seen >= self.limit:
                    if malformed:
                        return SourceExecutionReport('failed', 'invalid-response')
                    return None
                if not next_page_token:
                    if malformed:
                        return SourceExecutionReport('failed', 'invalid-response')
                    return None
                if next_page_token in seen_tokens:
                    return SourceExecutionReport(
                        'partial' if self.totalhosts or self.emails else 'failed',
                        'repeated-cursor',
                    )
                seen_tokens.add(next_page_token)
                page_token = next_page_token
        return None

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return self.emails

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        try:
            return await self.do_search()
        except asyncio.CancelledError:
            raise
        except aiohttp.ClientError, TimeoutError, OSError, ssl.SSLError, ValueError:
            return SourceExecutionReport('failed', 'transport-error')
