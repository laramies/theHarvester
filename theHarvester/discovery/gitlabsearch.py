import json as _stdlib_json
import re
from types import ModuleType

from theHarvester.lib.core import AsyncFetcher, Core

json: ModuleType = _stdlib_json
try:
    import ujson as _ujson

    json = _ujson
except ImportError:
    pass
except Exception:
    pass


class SearchGitlab:
    """
    Class uses GitLab API to search for domain references in projects and code
    """

    def __init__(self, word) -> None:
        self.word = word
        self.totalhosts: set = set()
        self.totalemails: set = set()
        self.totalurls: set = set()
        self.proxy = False
        self.hostname = 'https://gitlab.com'

    @staticmethod
    def _safe_parse_json(payload: object) -> dict:
        # If already a dict, return it; if string, try parse; else return {}
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except Exception:
                return {}
        return {}

    def _extract_domains_from_text(self, text: str) -> set:
        """Extract domain names from text that match our target domain"""
        domains: set[str] = set()
        if not text:
            return domains

        # Look for subdomains of our target domain
        pattern = rf'[a-zA-Z0-9.-]*\.{re.escape(self.word)}'
        matches = re.findall(pattern, text, re.IGNORECASE)

        for match in matches:
            # Clean up the match
            domain = match.lower().strip('.')
            if domain.endswith(self.word) and domain != self.word:
                domains.add(domain)

        return domains

    def _extract_emails_from_text(self, text: str) -> set:
        """Extract email addresses that match our target domain"""
        emails: set[str] = set()
        if not text:
            return emails

        email_pattern = rf'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*\.?{re.escape(self.word)}'
        matches = re.findall(email_pattern, text, re.IGNORECASE)

        for match in matches:
            email = match.lower()
            if self.word in email:
                emails.add(email)

        return emails

    async def search_projects(self) -> None:
        """Search GitLab projects for domain references"""
        try:
            headers = {'User-agent': Core.get_user_agent()}

            # Search for projects mentioning our domain
            search_terms = [self.word, f'*.{self.word}']

            for term in search_terms:
                # Search projects
                projects_url = f'{self.hostname}/api/v4/projects?search={term}&per_page=100'
                response = await AsyncFetcher.fetch_all([projects_url], headers=headers, proxy=self.proxy)

                if not response or not isinstance(response, list) or not response[0]:
                    continue

                try:
                    projects = self._safe_parse_json(response[0])
                    if not isinstance(projects, list):
                        continue

                    for project in projects[:20]:  # Limit to first 20 projects
                        if not isinstance(project, dict):
                            continue

                        # Extract information from project metadata
                        description = project.get('description', '') or ''
                        name = project.get('name', '') or ''
                        path = project.get('path_with_namespace', '') or ''
                        web_url = project.get('web_url', '') or ''

                        # Look for domains in description and name
                        all_text = f'{description} {name} {path}'
                        self.totalhosts.update(self._extract_domains_from_text(all_text))
                        self.totalemails.update(self._extract_emails_from_text(all_text))

                        # Add the web URL if it contains our domain
                        if web_url and self.word in web_url:
                            self.totalurls.add(web_url)

                        # Try to get README content for more detailed search
                        project_id = project.get('id')
                        if project_id:
                            readme_url = f'{self.hostname}/api/v4/projects/{project_id}/repository/files/README.md/raw?ref=main'
                            try:
                                readme_response = await AsyncFetcher.fetch_all([readme_url], headers=headers, proxy=self.proxy)
                                if readme_response and readme_response[0]:
                                    readme_text = (
                                        readme_response[0] if isinstance(readme_response[0], str) else str(readme_response[0])
                                    )
                                    self.totalhosts.update(self._extract_domains_from_text(readme_text))
                                    self.totalemails.update(self._extract_emails_from_text(readme_text))
                            except Exception:
                                pass  # README might not exist or be accessible

                except Exception as e:
                    print(f'Failed to parse GitLab projects response: {e}')

        except Exception as e:
            print(f'GitLab API projects search error: {e}')

    async def search_users(self) -> None:
        """Search GitLab users for domain references"""
        try:
            headers = {'User-agent': Core.get_user_agent()}

            # Search for users mentioning our domain
            users_url = f'{self.hostname}/api/v4/users?search={self.word}&per_page=50'
            response = await AsyncFetcher.fetch_all([users_url], headers=headers, proxy=self.proxy)

            if not response or not isinstance(response, list) or not response[0]:
                return

            try:
                users = self._safe_parse_json(response[0])
                if not isinstance(users, list):
                    return

                for user in users[:10]:  # Limit to first 10 users
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
                    all_text = f'{name} {username} {bio} {website_url}'
                    self.totalhosts.update(self._extract_domains_from_text(all_text))

                    # Check email
                    if public_email and self.word in public_email:
                        self.totalemails.add(public_email)

                    # Check website URL
                    if website_url and self.word in website_url:
                        self.totalurls.add(website_url)

                    # Add user profile URL if relevant
                    if web_url:
                        self.totalurls.add(web_url)

            except Exception as e:
                print(f'Failed to parse GitLab users response: {e}')

        except Exception as e:
            print(f'GitLab API users search error: {e}')

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
