import json
import logging
import re
from urllib.parse import quote

from theHarvester.discovery.provider_response import provider_http_error
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.source_execution import SourceExecutionReport

logger = logging.getLogger(__name__)


class SearchGitlab:
    """Search public GitLab project metadata, README files, and user profiles."""

    def __init__(self, word: str, limit: int | None = None) -> None:
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise ValueError('GitLab limit must be a positive integer')
        self.word = word
        self.limit = limit
        self.totalhosts: set = set()
        self.totalemails: set = set()
        self.totalurls: set = set()
        self.proxy = False
        self.hostname = 'https://gitlab.com'

    @staticmethod
    def _safe_parse_json(payload: object) -> dict | list:
        # If already decoded, return it; if string, try parse; else return {}
        if isinstance(payload, (dict, list)):
            return payload
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except Exception:
                return {}
        return {}

    @staticmethod
    def _combine_reports(
        current: SourceExecutionReport | None,
        candidate: SourceExecutionReport | None,
    ) -> SourceExecutionReport | None:
        if current is None or (current.status == 'completed' and candidate is not None):
            return candidate
        return current

    def _extract_domains_from_text(self, text: str) -> set:
        """Extract domain names that match the target domain."""
        domains: set[str] = set()
        if not text:
            return domains

        for candidate in re.findall(r'[a-zA-Z0-9.-]+', text):
            if domain := normalize_scoped_hostname(candidate.strip('.'), self.word):
                domains.add(domain)

        return domains

    def _extract_emails_from_text(self, text: str) -> set:
        """Extract email addresses that match the target domain."""
        emails: set[str] = set()
        if not text:
            return emails

        for candidate in re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+', text):
            local_part, domain = candidate.lower().split('@', maxsplit=1)
            if normalized_domain := normalize_scoped_hostname(domain, self.word):
                emails.add(f'{local_part}@{normalized_domain}')

        return emails

    def _add_text_evidence(self, text: str) -> bool:
        hosts = self._extract_domains_from_text(text)
        emails = self._extract_emails_from_text(text)
        self.totalhosts.update(hosts)
        self.totalemails.update(emails)
        return bool(hosts or emails)

    async def _fetch_page(
        self,
        endpoint: str,
        term: str,
        page: int,
        per_page: int,
    ) -> tuple[list[object], str | None, SourceExecutionReport | None]:
        url = f'{self.hostname}/api/v4/{endpoint}?search={term}&per_page={per_page}&page={page}'
        response = await AsyncFetcher.fetch_all(
            [url],
            headers={'User-agent': Core.get_user_agent()},
            proxy=self.proxy,
            json=True,
            include_metadata=True,
        )
        if not response:
            return [], None, SourceExecutionReport('failed', 'transport-error')
        payload = response[0]
        headers: dict[str, str] | None = None
        if isinstance(payload, FetcherResponse):
            if error := provider_http_error(payload):
                if page > 1 and payload.status == 400:
                    return [], None, SourceExecutionReport('partial', 'provider-limit')
                return [], None, SourceExecutionReport(*error)
            headers = payload.headers
            payload = payload.body
        records = self._safe_parse_json(payload)
        if not isinstance(records, list):
            return [], None, SourceExecutionReport('failed', 'invalid-response')
        if headers is not None and 'x-next-page' in headers:
            next_page = headers['x-next-page'].strip() or None
        else:
            next_page = str(page + 1) if len(records) >= per_page else None
        return records, next_page, None

    async def search_projects(self) -> SourceExecutionReport | None:
        """Search GitLab projects for references to the target domain."""
        try:
            headers = {'User-agent': Core.get_user_agent()}
            search_terms = [self.word, f'*.{self.word}']
            report = None
            for term in search_terms:
                page = 1
                records_seen = 0
                seen_pages: set[str] = set()
                seen_cursors: set[str] = set()
                while self.limit is None or records_seen < self.limit:
                    per_page = min(100, self.limit - records_seen) if self.limit is not None else 100
                    projects, next_page, page_report = await self._fetch_page('projects', term, page, per_page)
                    if page_report is not None:
                        report = self._combine_reports(report, page_report)
                        break
                    signature = json.dumps(projects, sort_keys=True, default=str)
                    if signature in seen_pages:
                        report = self._combine_reports(report, SourceExecutionReport('partial', 'repeated-page'))
                        break
                    seen_pages.add(signature)
                    accepted = projects[: self.limit - records_seen] if self.limit is not None else projects
                    records_seen += len(accepted)
                    for project in accepted:
                        if not isinstance(project, dict):
                            continue
                        description = project.get('description', '') or ''
                        name = project.get('name', '') or ''
                        path = project.get('path_with_namespace', '') or ''
                        web_url = project.get('web_url', '') or ''
                        all_text = f'{description} {name} {path}'
                        project_is_relevant = self._add_text_evidence(all_text)
                        project_id = project.get('id')
                        default_branch = project.get('default_branch')
                        if project_id and isinstance(default_branch, str) and default_branch:
                            readme_url = (
                                f'{self.hostname}/api/v4/projects/{quote(str(project_id), safe="")}'
                                f'/repository/files/README.md/raw?ref={quote(default_branch, safe="")}'
                            )
                            try:
                                readme_response = await AsyncFetcher.fetch_all([readme_url], headers=headers, proxy=self.proxy)
                                if readme_response and readme_response[0]:
                                    readme_text = (
                                        readme_response[0] if isinstance(readme_response[0], str) else str(readme_response[0])
                                    )
                                    project_is_relevant = self._add_text_evidence(readme_text) or project_is_relevant
                            except Exception:
                                pass  # README might not exist or be accessible

                        if project_is_relevant and isinstance(web_url, str) and web_url.strip():
                            self.totalurls.add(web_url.strip())
                    if self.limit is not None and records_seen >= self.limit:
                        report = self._combine_reports(report, SourceExecutionReport('completed', 'result-limit'))
                        break
                    if next_page is None:
                        break
                    if next_page in seen_cursors or next_page == str(page):
                        report = self._combine_reports(report, SourceExecutionReport('partial', 'repeated-cursor'))
                        break
                    seen_cursors.add(next_page)
                    try:
                        page = int(next_page)
                    except ValueError:
                        report = self._combine_reports(report, SourceExecutionReport('failed', 'invalid-response'))
                        break
            return report
        except Exception as e:
            logger.info(f'GitLab API projects search error: {e}')
            return SourceExecutionReport('failed', 'transport-error')

    async def search_users(self) -> SourceExecutionReport | None:
        """Search GitLab users for references to the target domain."""
        try:
            page = 1
            records_seen = 0
            seen_pages: set[str] = set()
            seen_cursors: set[str] = set()
            while self.limit is None or records_seen < self.limit:
                per_page = min(100, self.limit - records_seen) if self.limit is not None else 100
                users, next_page, report = await self._fetch_page('users', self.word, page, per_page)
                if report is not None:
                    return report
                signature = json.dumps(users, sort_keys=True, default=str)
                if signature in seen_pages:
                    return SourceExecutionReport('partial', 'repeated-page')
                seen_pages.add(signature)
                accepted = users[: self.limit - records_seen] if self.limit is not None else users
                records_seen += len(accepted)
                for user in accepted:
                    if not isinstance(user, dict):
                        continue
                    name = user.get('name', '') or ''
                    username = user.get('username', '') or ''
                    bio = user.get('bio', '') or ''
                    web_url = user.get('web_url', '') or ''
                    website_url = user.get('website_url', '') or ''
                    public_email = user.get('public_email', '') or ''

                    user_hosts = self._extract_domains_from_text(f'{name} {username} {bio}')
                    website_hosts = self._extract_domains_from_text(website_url) if isinstance(website_url, str) else set()
                    user_hosts.update(website_hosts)
                    self.totalhosts.update(user_hosts)
                    user_emails: set[str] = set()
                    if public_email:
                        user_emails = self._extract_emails_from_text(public_email)
                        self.totalemails.update(user_emails)

                    user_is_relevant = bool(user_hosts or user_emails)
                    if website_hosts and isinstance(website_url, str) and website_url.strip():
                        self.totalurls.add(website_url.strip())

                    if user_is_relevant and isinstance(web_url, str) and web_url.strip():
                        self.totalurls.add(web_url.strip())
                if self.limit is not None and records_seen >= self.limit:
                    return SourceExecutionReport('completed', 'result-limit')
                if next_page is None:
                    return None
                if next_page in seen_cursors or next_page == str(page):
                    return SourceExecutionReport('partial', 'repeated-cursor')
                seen_cursors.add(next_page)
                try:
                    page = int(next_page)
                except ValueError:
                    return SourceExecutionReport('failed', 'invalid-response')
            return None
        except Exception as e:
            logger.info(f'GitLab API users search error: {e}')
            return SourceExecutionReport('failed', 'transport-error')

    async def do_search(self) -> SourceExecutionReport | None:
        project_report = await self.search_projects()
        user_report = await self.search_users()
        return self._combine_reports(project_report, user_report)

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_emails(self) -> set:
        return self.totalemails

    async def get_urls(self) -> set:
        return self.totalurls

    async def process(self, proxy: bool = False) -> SourceExecutionReport | None:
        self.proxy = proxy
        return await self.do_search()
