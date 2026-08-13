from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse


class SearchCensys:
    MAX_RESULTS_PER_PAGE = 100
    SERVER = 'https://api.platform.censys.io/v3/global/search/query'

    def __init__(self, domain: str, limit: int = 500) -> None:
        self.word = domain
        token, self.organization_id = Core.censys_key()
        if not isinstance(token, str) or not token.strip():
            raise MissingKey('Censys Personal Access Token')
        self.token = token.strip()
        self.totalhosts: set[str] = set()
        self.emails: set[str] = set()
        self.limit = limit
        self.proxy = False
        self.execution_status: str | None = None
        self.stop_reason: str | None = None

    def _has_results(self) -> bool:
        return bool(self.totalhosts or self.emails)

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self._has_results() else status
        self.stop_reason = reason

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

    async def do_search(self) -> None:
        if self.limit <= 0:
            self.execution_status = 'completed'
            self.stop_reason = 'no-results'
            return

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

        while records_seen < self.limit:
            body = {
                'query': f'cert.names: "{self.word}"',
                'fields': ['cert.names', 'cert.parsed.subject.email_address'],
                'page_size': min(self.MAX_RESULTS_PER_PAGE, self.limit - records_seen),
            }
            if page_token is not None:
                body['page_token'] = page_token
            try:
                response = await AsyncFetcher.post_fetch(
                    self.SERVER,
                    headers=headers,
                    params=params,
                    json=True,
                    proxy=self.proxy,
                    include_metadata=True,
                    json_body=body,
                )
            except Exception:
                self._stop('failed', 'transport-error')
                return
            if not isinstance(response, FetcherResponse):
                self._stop('failed', 'transport-error')
                return
            if response.status == 429:
                self._stop('rate-limited', 'http-429')
                return
            if response.status in {401, 403}:
                self._stop('failed', 'access-denied')
                return
            if not 200 <= response.status < 300:
                self._stop('failed', f'http-{response.status}')
                return
            if not isinstance(response.body, dict) or not isinstance(response.body.get('result'), dict):
                self._stop('failed', 'invalid-response')
                return
            result = response.body['result']
            hits = result.get('hits')
            next_page_token = result.get('next_page_token')
            if not isinstance(hits, list) or (next_page_token is not None and not isinstance(next_page_token, str)):
                self._stop('failed', 'invalid-response')
                return

            for hit in hits:
                if records_seen >= self.limit:
                    break
                malformed = self._parse_hit(hit) or malformed
                records_seen += 1
            if records_seen >= self.limit:
                if malformed:
                    self._stop('failed', 'invalid-response')
                else:
                    self.execution_status = 'completed'
                return
            if not next_page_token:
                if malformed:
                    self._stop('failed', 'invalid-response')
                else:
                    self.execution_status = 'completed'
                    self.stop_reason = None if self._has_results() else 'no-results'
                return
            if next_page_token in seen_tokens:
                self._stop('failed', 'repeated-cursor')
                return
            seen_tokens.add(next_page_token)
            page_token = next_page_token

    async def get_hostnames(self) -> set[str]:
        return self.totalhosts

    async def get_emails(self) -> set[str]:
        return self.emails

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
