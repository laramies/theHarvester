#!/usr/bin/env python3
"""Tests for the THC (ip.thc.org) discovery source.

THC provides multiple endpoints:
- Subdomain enumeration
- CNAME lookup
- Reverse DNS lookup

API documentation: https://ip.thc.org/docs/
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from theHarvester.discovery import thc
from theHarvester.lib.core import Core

if TYPE_CHECKING:
    from types import TracebackType


class FakeResponse:
    def __init__(self, text: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._text = text
        self.status = status
        self.headers = headers or {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> bool:
        return False

    async def text(self) -> str:
        return self._text


class FakeSession:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> bool:
        return False

    def get(self, url: str) -> FakeResponse:
        domain = parse_qs(urlparse(url).query).get('domain', ['example.com'])[0]
        return FakeResponse(f'WWW.{domain}\napi.{domain}\napi.{domain}\n')


def session_for(*outcomes: FakeResponse | Exception) -> type[FakeSession]:
    remaining = iter(outcomes)

    class SequencedSession(FakeSession):
        def get(self, _url: str) -> FakeResponse:
            outcome = next(remaining)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    return SequencedSession


@pytest.fixture(autouse=True)
def fake_thc_session(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    session_options: list[dict[str, Any]] = []

    @asynccontextmanager
    async def open_session(**kwargs: Any):
        session_options.append(kwargs)
        async with thc.aiohttp.ClientSession(**kwargs) as session:
            yield session

    monkeypatch.setattr(thc.aiohttp, 'ClientSession', FakeSession)
    monkeypatch.setattr(thc.AsyncFetcher, 'open_session', open_session)
    return session_options


@pytest.fixture
def recorded_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    sleeps: list[int] = []

    async def record_sleep(seconds: int) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(thc.asyncio, 'sleep', record_sleep)
    return sleeps


# =============================================================================
# 1. Direct API Tests (Endpoint Validation)
# =============================================================================
@pytest.mark.live_network
class TestThcApi:
    """Check the THC API contract."""

    def test_api_subdomains_download_endpoint_responds(self, live_test_domain: str) -> None:
        """The subdomain download endpoint responds."""
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={live_test_domain}&limit=10&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert response.status_code == 200

    def test_api_subdomains_returns_text_format(self, live_test_domain: str) -> None:
        """The subdomain response is plain text."""
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={live_test_domain}&limit=5&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        content_type = response.headers.get('content-type', '')
        assert 'text' in content_type or 'octet-stream' in content_type

    def test_api_cli_subdomain_endpoint(self, live_test_domain: str) -> None:
        """The CLI endpoint accepts ``/sb/{domain}``."""
        url = f'https://ip.thc.org/sb/{live_test_domain}?l=5&noheader'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert response.status_code == 200

    def test_api_returns_rate_limit_headers(self, live_test_domain: str) -> None:
        """The API returns rate-limit headers."""
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={live_test_domain}&limit=1&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert 'x-ratelimit-limit' in response.headers
        assert 'x-ratelimit-remaining' in response.headers


# =============================================================================
# 2. Subdomain Search Tests (Main Functionality)
# =============================================================================
class TestThcSubdomainSearch:
    """Check THC subdomain searches."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @staticmethod
    def small_domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_search_returns_set(self) -> None:
        """Return hostnames as a set."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_finds_subdomains(self) -> None:
        """Find subdomains for a known domain."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        assert len(result) > 0, 'Should find at least one subdomain for example.com'

    @pytest.mark.asyncio
    async def test_search_results_contain_target_domain(self) -> None:
        """Keep every result within the target domain."""
        search = thc.SearchThc(self.small_domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert self.small_domain() in hostname, f'{hostname} should contain {self.small_domain()}'

    @pytest.mark.asyncio
    async def test_search_no_duplicates(self) -> None:
        """Deduplicate the results."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        result_list = list(result)
        assert len(result_list) == len(set(result_list))

    @pytest.mark.asyncio
    async def test_proxy_is_stable_across_the_retry_conversation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_thc_session: list[dict[str, Any]],
        recorded_sleeps: list[int],
    ) -> None:
        monkeypatch.setattr(
            thc.aiohttp,
            'ClientSession',
            session_for(FakeResponse('', status=429), FakeResponse('api.example.com\n')),
        )

        report = await thc.SearchThc(self.domain()).process(proxy=True)

        assert report is None
        assert recorded_sleeps == [2]
        assert len(fake_thc_session) == 1
        assert fake_thc_session[0]['proxy'] is True

    @pytest.mark.asyncio
    async def test_unlimited_uses_provider_max_and_reports_saturation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        requested_urls: list[str] = []

        class RecordingSession(FakeSession):
            def get(self, url: str) -> FakeResponse:
                requested_urls.append(url)
                return FakeResponse('one.example.com\ntwo.example.com\n')

        monkeypatch.setattr(thc.SearchThc, 'PROVIDER_MAX_RESULTS', 2)
        monkeypatch.setattr(thc.aiohttp, 'ClientSession', RecordingSession)

        report = await thc.SearchThc(self.domain(), None).process()

        assert parse_qs(urlparse(requested_urls[0]).query)['limit'] == ['2']
        assert report.status == 'partial'
        assert report.stop_reason == 'provider-limit'

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('outcomes', 'message'),
        [
            (
                tuple(FakeResponse('', status=429) for _ in range(3)),
                'THC returned status 429 after 3 attempts',
            ),
            (
                tuple(RuntimeError('429 too many requests') for _ in range(3)),
                'THC rate limit failure after 3 attempts',
            ),
        ],
    )
    async def test_final_rate_limit_is_attributed_without_an_extra_sleep(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recorded_sleeps: list[int],
        caplog: pytest.LogCaptureFixture,
        outcomes: tuple[FakeResponse | Exception, ...],
        message: str,
    ) -> None:
        monkeypatch.setattr(
            thc.aiohttp,
            'ClientSession',
            session_for(FakeResponse('kept.example.com\n'), *outcomes),
        )
        search = thc.SearchThc(self.domain())
        await search.process()

        with caplog.at_level('INFO', logger=thc.__name__):
            await search.process()

        assert await search.get_hostnames() == {'kept.example.com'}
        assert recorded_sleeps == [2, 4]
        assert message in caplog.text

    @pytest.mark.asyncio
    async def test_rate_limit_retry_recovers(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recorded_sleeps: list[int],
    ) -> None:
        monkeypatch.setattr(
            thc.aiohttp,
            'ClientSession',
            session_for(FakeResponse('', status=429), FakeResponse('WWW.example.com\napi.example.com\n')),
        )
        search = thc.SearchThc(self.domain())

        await search.process()

        assert recorded_sleeps == [2]
        assert await search.get_hostnames() == {'www.example.com', 'api.example.com'}

    @pytest.mark.asyncio
    async def test_non_success_status_is_attributed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(thc.aiohttp, 'ClientSession', session_for(FakeResponse('', status=503)))
        search = thc.SearchThc(self.domain())

        with caplog.at_level('INFO', logger=thc.__name__):
            await search.process()

        assert await search.get_hostnames() == set()
        assert 'THC returned status 503' in caplog.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize('payload', ['', '\n\t\n', 'not a hostname'])
    async def test_empty_or_malformed_payloads_fail_safely(
        self,
        monkeypatch: pytest.MonkeyPatch,
        payload: str,
    ) -> None:
        monkeypatch.setattr(thc.aiohttp, 'ClientSession', session_for(FakeResponse(payload)))
        search = thc.SearchThc(self.domain())

        await search.process()

        assert await search.get_hostnames() == set()


# =============================================================================
# 3. Edge Case Tests
# =============================================================================
class TestThcEdgeCases:
    """Check unusual and invalid targets."""

    @pytest.mark.asyncio
    async def test_search_nonexistent_domain(self) -> None:
        """Handle a nonexistent domain."""
        search = thc.SearchThc('this-domain-definitely-does-not-exist-12345.com')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_empty_domain(self) -> None:
        """Handle an empty domain."""
        search = thc.SearchThc('')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_special_characters_domain(self) -> None:
        """Handle special characters in a domain."""
        search = thc.SearchThc('example.com; DROP TABLE domains;--')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_unicode_domain(self) -> None:
        """Handle an internationalized domain name."""
        search = thc.SearchThc('xn--mnchen-3ya.de')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_subdomain_as_input(self) -> None:
        """Accept a subdomain as the target."""
        search = thc.SearchThc('www.example.com')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)


# =============================================================================
# 4. Proxy Tests
# =============================================================================
class TestThcProxy:
    """Check proxy configuration."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_process_accepts_proxy_parameter(self) -> None:
        """Accept the proxy argument in ``process()``."""
        search = thc.SearchThc(self.domain())
        await search.process(proxy=False)
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_proxy_attribute_is_set(self) -> None:
        """Store the configured proxy value."""
        search = thc.SearchThc(self.domain())
        assert search.proxy is False


# =============================================================================
# 5. Initialization and Attributes Tests
# =============================================================================
class TestThcInitialization:
    """Check the initial search state."""

    def test_init_sets_word(self) -> None:
        """Store the target domain."""
        domain = 'test.com'
        search = thc.SearchThc(domain)
        assert search.word == domain

    def test_init_creates_empty_results(self) -> None:
        """Start with no results."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'results')
        assert len(search.results) == 0

    def test_init_proxy_default_false(self) -> None:
        """Disable the proxy by default."""
        search = thc.SearchThc('test.com')
        assert search.proxy is False

    def test_init_has_rate_limit_settings(self) -> None:
        """Initialize the rate-limit settings."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'max_retries')
        assert hasattr(search, 'base_delay')
        assert search.max_retries == 3
        assert search.base_delay == 2

    def test_class_has_required_methods(self) -> None:
        """Expose the methods required by the source runner."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'do_search')
        assert hasattr(search, 'get_hostnames')
        assert hasattr(search, 'process')
        assert callable(search.do_search)
        assert callable(search.get_hostnames)
        assert callable(search.process)


# =============================================================================
# 6. Response Format Tests
# =============================================================================
class TestThcResponseFormat:
    """Check normalized hostname results."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_hostnames_are_strings(self) -> None:
        """Return every hostname as a string."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert isinstance(hostname, str)

    @pytest.mark.asyncio
    async def test_hostnames_are_valid_format(self) -> None:
        """Return valid hostname syntax."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert ' ' not in hostname
            assert '\n' not in hostname
            assert '\t' not in hostname

    @pytest.mark.asyncio
    async def test_hostnames_are_lowercase(self) -> None:
        """Return lowercase hostnames."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert hostname == hostname.lower()


# =============================================================================
# 7. Integration Tests with theHarvester
# =============================================================================
class TestThcIntegration:
    """Check the source-runner interface."""

    @pytest.mark.asyncio
    async def test_module_can_be_imported(self) -> None:
        """Import the THC discovery module."""
        from theHarvester.discovery import thc as thc_module

        assert thc_module is not None

    @pytest.mark.asyncio
    async def test_search_class_exists(self) -> None:
        """Expose the ``SearchThc`` adapter."""
        from theHarvester.discovery import thc as thc_module

        assert hasattr(thc_module, 'SearchThc')

    @pytest.mark.asyncio
    async def test_compatible_with_store_function(self) -> None:
        """Return results accepted by the main result store."""
        search = thc.SearchThc('example.com')
        assert hasattr(search, 'process')
        assert hasattr(search, 'get_hostnames')


if __name__ == '__main__':
    pytest.main()


pytestmark = pytest.mark.provider_contract('thc')
