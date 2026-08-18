import json
import logging
import re
from urllib.parse import quote

from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.lib.hostnames import normalize_scoped_hostname

logger = logging.getLogger(__name__)


class SearchGitlab:
    """Search public GitLab project metadata, README files, and user profiles."""

    def __init__(self, word) -> None:
        self.word = word
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

    async def search_projects(self) -> None:
        """Search GitLab projects for references to the target domain."""
        try:
            headers = {'User-agent': Core.get_user_agent()}

            # Search for projects mentioning our domain
            search_terms = [self.word, f'*.{self.word}']

            for term in search_terms:
                # Search projects
                projects_url = f'{self.hostname}/api/v4/projects?search={term}&per_page=20'
                response = await AsyncFetcher.fetch_all([projects_url], headers=headers, proxy=self.proxy)

                if not response or not isinstance(response, list) or not response[0]:
                    continue

                try:
                    projects = self._safe_parse_json(response[0])
                    if not isinstance(projects, list):
                        continue

                    for project in projects:
                        if not isinstance(project, dict):
                            continue

                        # Extract information from project metadata
                        description = project.get('description', '') or ''
                        name = project.get('name', '') or ''
                        path = project.get('path_with_namespace', '') or ''
                        web_url = project.get('web_url', '') or ''

                        # Look for domains in description and name
                        all_text = f'{description} {name} {path}'
                        project_is_relevant = self._add_text_evidence(all_text)

                        # Try to get README content for more detailed search
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

                except Exception as e:
                    logger.info(f'Failed to parse GitLab projects response: {e}')

        except Exception as e:
            logger.info(f'GitLab API projects search error: {e}')

    async def search_users(self) -> None:
        """Search GitLab users for references to the target domain."""
        try:
            headers = {'User-agent': Core.get_user_agent()}

            # Search for users mentioning our domain
            users_url = f'{self.hostname}/api/v4/users?search={self.word}&per_page=10'
            response = await AsyncFetcher.fetch_all([users_url], headers=headers, proxy=self.proxy)

            if not response or not isinstance(response, list) or not response[0]:
                return

            try:
                users = self._safe_parse_json(response[0])
                if not isinstance(users, list):
                    return

                for user in users:
                    if not isinstance(user, dict):
                        continue

                    # Extract information from user metadata
                    name = user.get('name', '') or ''
                    username = user.get('username', '') or ''
                    bio = user.get('bio', '') or ''
                    web_url = user.get('web_url', '') or ''
                    website_url = user.get('website_url', '') or ''
                    public_email = user.get('public_email', '') or ''

                    # Look for domains in user info
                    user_hosts = self._extract_domains_from_text(f'{name} {username} {bio}')
                    website_hosts = self._extract_domains_from_text(website_url) if isinstance(website_url, str) else set()
                    user_hosts.update(website_hosts)
                    self.totalhosts.update(user_hosts)

                    # Check email
                    user_emails: set[str] = set()
                    if public_email:
                        user_emails = self._extract_emails_from_text(public_email)
                        self.totalemails.update(user_emails)

                    user_is_relevant = bool(user_hosts or user_emails)
                    if website_hosts and isinstance(website_url, str) and website_url.strip():
                        self.totalurls.add(website_url.strip())

                    if user_is_relevant and isinstance(web_url, str) and web_url.strip():
                        self.totalurls.add(web_url.strip())

            except Exception as e:
                logger.info(f'Failed to parse GitLab users response: {e}')

        except Exception as e:
            logger.info(f'GitLab API users search error: {e}')

    async def do_search(self) -> None:
        await self.search_projects()
        await self.search_users()

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_emails(self) -> set:
        return self.totalemails

    async def get_urls(self) -> set:
        return self.totalurls

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
