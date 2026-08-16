from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from theHarvester.discovery.constants import MissingKey
from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport, SourceReportStatus


class SearchSecurityScorecard:
    PAGE_SIZE = 50

    def __init__(self, word: str, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('SecurityScorecard limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.api_key = Core.securityscorecard_key()
        if not isinstance(self.api_key, str) or not self.api_key.strip():
            raise MissingKey('SecurityScorecard')
        self.base_url = 'https://api.securityscorecard.io'
        self.headers = {
            'Authorization': f'Token {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': Core.get_user_agent(),
        }
        self.hosts: set[str] = set()
        self.score: int = 0
        self.grades: dict[str, Any] = {}
        self.issues: list[dict[str, Any]] = []
        self.recommendations: list[dict[str, Any]] = []
        self.history: list[dict[str, Any]] = []
        self.ips: set[str] = set()
        self._report: SourceExecutionReport | None = None

    def _stop(self, status: SourceReportStatus, reason: str) -> None:
        self._report = SourceExecutionReport(status, reason)

    def _response_body(self, response: Any) -> dict[str, Any] | None:
        if error := provider_http_error(response):
            self._stop(*error)
            return None
        assert isinstance(response, FetcherResponse)
        if not isinstance(response.body, dict):
            self._stop('failed', 'invalid-response')
            return None
        return response.body

    def _extract_summary(self, data: dict[str, Any]) -> bool:
        malformed = False
        score = data.get('score')
        if score is not None:
            if isinstance(score, bool) or not isinstance(score, int):
                malformed = True
            else:
                self.score = score

        grade = data.get('grade')
        if grade is not None:
            if isinstance(grade, str) and grade.strip():
                self.grades['overall'] = grade.strip()
            else:
                malformed = True
        factor_grades = data.get('factor_grades')
        if factor_grades is not None:
            if isinstance(factor_grades, dict):
                self.grades.update(factor_grades)
            else:
                malformed = True
        return malformed

    async def _collect_assets(self, session: Any, route: str, field: str) -> bool:
        page = 0
        records_seen = 0
        page_size = min(self.PAGE_SIZE, self.limit)
        while records_seen < self.limit:
            response = await AsyncFetcher.post_fetch(
                f'{self.base_url}/parent-domains/{self.word}/{route}',
                session=session,
                json=True,
                include_metadata=True,
                json_body={'page': page, 'page_size': page_size},
            )
            body = self._response_body(response)
            if body is None:
                return False
            entries = body.get('entries')
            size = body.get('size')
            if not isinstance(entries, list) or isinstance(size, bool) or not isinstance(size, int | float) or size < 0:
                self._stop('failed', 'invalid-response')
                return False

            remaining = self.limit - records_seen
            page_entries = entries[:remaining]
            records_seen += len(page_entries)
            malformed = False
            for entry in page_entries:
                if not isinstance(entry, dict) or not isinstance(entry.get(field), str):
                    malformed = True
                    continue
                value = entry[field]
                if field == 'domain':
                    if hostname := normalize_scoped_hostname(value, self.word):
                        self.hosts.add(hostname)
                else:
                    try:
                        self.ips.add(str(ip_address(value.strip())))
                    except ValueError:
                        malformed = True
            if malformed:
                self._stop('failed', 'invalid-response')
            if records_seen >= self.limit or len(entries) < page_size:
                return True
            page += 1
        return True

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self._report = None
        try:
            async with AsyncFetcher.open_session(headers=self.headers, proxy=proxy) as session:
                response = await AsyncFetcher.fetch(
                    session=session,
                    url=f'{self.base_url}/companies/{self.word}',
                    json=True,
                    include_metadata=True,
                )
                body = self._response_body(response)
                if body is None:
                    return self._report
                if self._extract_summary(body):
                    self._stop('failed', 'invalid-response')
                if not await self._collect_assets(session, 'domains', 'domain'):
                    return self._report
                if not await self._collect_assets(session, 'ips', 'ip'):
                    return self._report
        except Exception:
            return SourceExecutionReport('failed', 'transport-error')
        return self._report

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_ips(self) -> set[str]:
        return self.ips

    async def get_score(self) -> int:
        return self.score

    async def get_grades(self) -> dict[str, Any]:
        return self.grades

    async def get_issues(self) -> list[dict[str, Any]]:
        return self.issues

    async def get_recommendations(self) -> list[dict[str, Any]]:
        return self.recommendations

    async def get_history(self) -> list[dict[str, Any]]:
        return self.history
