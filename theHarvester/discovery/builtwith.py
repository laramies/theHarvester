from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core, FetcherResponse, ResponseStreamError
from theHarvester.lib.hostnames import normalize_scoped_hostname
from theHarvester.lib.virtual_host import normalize_virtual_host_hostname


class SearchBuiltWith:
    """Collect scoped technology evidence from the BuiltWith Domain API."""

    SERVER = 'https://api.builtwith.com/v23/api.json'

    def __init__(self, word: str) -> None:
        self.word = normalize_virtual_host_hostname(word)
        self.lookup_domain = self.word.removeprefix('www.')
        self.api_key = Core.builtwith_key()
        if not isinstance(self.api_key, str) or not self.api_key.strip():
            raise MissingKey('BuiltWith')
        self.api_key = self.api_key.strip()
        self.hosts: set[str] = set()
        self.tech_stack: dict[str, Any] = {}
        self.urls: set[str] = set()
        self.frameworks: set[str] = set()
        self.languages: set[str] = set()
        self.servers: set[str] = set()
        self.cms: set[str] = set()
        self.analytics: set[str] = set()
        self.execution_status = 'completed'
        self.stop_reason: str | None = None

    def _has_results(self) -> bool:
        return bool(self.hosts or self.urls or self.frameworks or self.languages or self.servers or self.cms or self.analytics)

    def _stop(self, status: str, reason: str) -> None:
        self.execution_status = 'partial' if self._has_results() else status
        self.stop_reason = reason

    def _path_hostname(self, path: dict[str, object]) -> tuple[str | None, bool]:
        domain = path.get('Domain')
        subdomain = path.get('SubDomain')
        if not isinstance(domain, str) or not isinstance(subdomain, str):
            return None, True
        try:
            domain = normalize_virtual_host_hostname(domain)
        except ValueError:
            return None, True
        normalized_domain = normalize_scoped_hostname(domain, self.lookup_domain)
        if normalized_domain is None:
            return None, False
        candidate = normalized_domain if not subdomain.strip() else f'{subdomain.strip()}.{normalized_domain}'
        try:
            candidate = normalize_virtual_host_hostname(candidate)
        except ValueError:
            return None, True
        return normalize_scoped_hostname(candidate, self.word), False

    def _path_url(self, value: object, hostname: str) -> tuple[str | None, bool]:
        if not isinstance(value, str) or not (value := value.strip()):
            return None, True
        if value == 'dd':
            return None, False
        try:
            parsed = urlsplit(value)
            if parsed.scheme or parsed.netloc:
                if (
                    parsed.scheme.lower() not in {'http', 'https'}
                    or parsed.hostname is None
                    or parsed.username is not None
                    or parsed.password is not None
                ):
                    return None, True
                parsed_hostname = normalize_virtual_host_hostname(parsed.hostname)
                scoped_hostname = normalize_scoped_hostname(parsed_hostname, self.word)
                if scoped_hostname is None:
                    return None, False
                port = f':{parsed.port}' if parsed.port is not None else ''
                return (
                    urlunsplit((parsed.scheme.lower(), f'{scoped_hostname}{port}', parsed.path, parsed.query, parsed.fragment)),
                    False,
                )
            if not parsed.path.startswith('/'):
                return None, True
            return urlunsplit(('https', hostname, parsed.path, parsed.query, parsed.fragment)), False
        except (UnicodeError, ValueError):
            return None, True

    def _extract_technology(self, technology: object) -> bool:
        if not isinstance(technology, dict):
            return True
        name = technology.get('Name')
        if not isinstance(name, str) or not (name := name.strip()):
            return True

        malformed = False
        categories: list[str] = []
        tag = technology.get('Tag')
        if tag is not None:
            if isinstance(tag, str):
                if tag := tag.strip():
                    categories.append(tag)
                else:
                    malformed = True
            else:
                malformed = True
        nested_categories = technology.get('Categories')
        if nested_categories is not None:
            if not isinstance(nested_categories, list):
                malformed = True
            else:
                for category in nested_categories:
                    if isinstance(category, str) and (category := category.strip()):
                        categories.append(category)
                    else:
                        malformed = True

        if not categories:
            return True

        category_text = ' '.join(categories).lower()
        for category, results in (
            ('framework', self.frameworks),
            ('language', self.languages),
            ('server', self.servers),
            ('cms', self.cms),
            ('analytics', self.analytics),
        ):
            if category in category_text:
                results.add(name)
                break
        return malformed

    def _extract_data(self) -> bool:
        results = self.tech_stack.get('Results')
        if not isinstance(results, list):
            return True
        malformed = False
        for envelope in results:
            if not isinstance(envelope, dict) or not isinstance(envelope.get('Result'), dict):
                malformed = True
                continue
            paths = envelope['Result'].get('Paths')
            if not isinstance(paths, list):
                malformed = True
                continue
            for path in paths:
                if not isinstance(path, dict):
                    malformed = True
                    continue
                hostname, path_malformed = self._path_hostname(path)
                malformed = path_malformed or malformed
                if hostname is None:
                    continue
                self.hosts.add(hostname)
                path_url, url_malformed = self._path_url(path.get('Url'), hostname)
                malformed = url_malformed or malformed
                if path_url is not None:
                    self.urls.add(path_url)
                technologies = path.get('Technologies')
                if not isinstance(technologies, list):
                    malformed = True
                    continue
                for technology in technologies:
                    malformed = self._extract_technology(technology) or malformed
        return malformed

    async def process(self, proxy: bool = False) -> None:
        headers = {
            'Accept': 'application/json',
            'Authorization': f'API {self.api_key}',
            'User-Agent': Core.get_user_agent(),
        }
        params = {
            'HIDEDL': 'yes',
            'LOOKUP': self.lookup_domain,
            'NOATTR': 'yes',
            'NOMETA': 'yes',
            'NOPII': 'yes',
        }
        try:
            response = await AsyncFetcher.fetch_json(
                self.SERVER,
                params=params,
                proxy=proxy,
                headers=headers,
            )
        except ResponseStreamError as error:
            self._stop('failed', error.reason)
            return
        except Exception:
            self._stop('failed', 'transport-error')
            return
        if not isinstance(response, FetcherResponse):
            self._stop('failed', 'transport-error')
            return
        if response.status in {401, 403}:
            self._stop('failed', 'access-denied')
            return
        if response.status == 429:
            self._stop('rate-limited', 'http-429')
            return
        if not 200 <= response.status < 300 or not isinstance(response.body, dict):
            reason = f'http-{response.status}' if not 200 <= response.status < 300 else 'invalid-response'
            self._stop('failed', reason)
            return
        if not isinstance(response.body.get('Results'), list):
            self._stop('failed', 'invalid-response')
            return

        self.tech_stack = response.body
        if self._extract_data():
            self._stop('failed', 'invalid-response')
        else:
            self.execution_status = 'completed'
            self.stop_reason = None if self._has_results() else 'no-results'

    async def get_hostnames(self) -> set[str]:
        return self.hosts

    async def get_tech_stack(self) -> dict[str, Any]:
        return self.tech_stack

    async def get_urls(self) -> set[str]:
        return self.urls

    async def get_frameworks(self) -> set[str]:
        return self.frameworks

    async def get_languages(self) -> set[str]:
        return self.languages

    async def get_servers(self) -> set[str]:
        return self.servers

    async def get_cms(self) -> set[str]:
        return self.cms

    async def get_analytics(self) -> set[str]:
        return self.analytics
