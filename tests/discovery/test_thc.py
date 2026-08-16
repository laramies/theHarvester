#!/usr/bin/env python3
# coding=utf-8
"""
Tests for THC (ip.thc.org) discovery module.

THC provides multiple endpoints:
- Subdomain enumeration
- CNAME lookup
- Reverse DNS lookup

API Documentation: https://ip.thc.org/docs/
"""
from types import TracebackType
from typing import Any, Self
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from theHarvester.discovery import thc
from theHarvester.lib.core import Core


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
def fake_thc_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(thc.aiohttp, 'ClientSession', FakeSession)


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
    """Tests to validate that the THC API responds correctly."""

    def test_api_subdomains_download_endpoint_responds(self, live_test_domain: str) -> None:
        """Verify that the subdomain download endpoint responds."""
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={live_test_domain}&limit=10&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert response.status_code == 200

    def test_api_subdomains_returns_text_format(self, live_test_domain: str) -> None:
        """Verify that the response is plain text."""
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={live_test_domain}&limit=5&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        content_type = response.headers.get('content-type', '')
        assert 'text' in content_type or 'octet-stream' in content_type

    def test_api_cli_subdomain_endpoint(self, live_test_domain: str) -> None:
        """Verify CLI endpoint /sb/{domain}."""
        url = f'https://ip.thc.org/sb/{live_test_domain}?l=5&noheader'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert response.status_code == 200

    def test_api_returns_rate_limit_headers(self, live_test_domain: str) -> None:
        """Verify that the API returns rate limit headers."""
        url = f'https://ip.thc.org/api/v1/subdomains/download?domain={live_test_domain}&limit=1&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        response = httpx.get(url, headers=headers, timeout=30)
        assert 'x-ratelimit-limit' in response.headers
        assert 'x-ratelimit-remaining' in response.headers


# =============================================================================
# 2. Subdomain Search Tests (Main Functionality)
# =============================================================================
class TestThcSubdomainSearch:
    """Tests for subdomain search functionality."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @staticmethod
    def small_domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_search_returns_set(self) -> None:
        """Verify that get_hostnames() returns a set."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_finds_subdomains(self) -> None:
        """Verify that it finds subdomains for a known domain."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        assert len(result) > 0, 'Should find at least one subdomain for example.com'

    @pytest.mark.asyncio
    async def test_search_results_contain_target_domain(self) -> None:
        """Verify that all results contain the target domain."""
        search = thc.SearchThc(self.small_domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert self.small_domain() in hostname, f'{hostname} should contain {self.small_domain()}'

    @pytest.mark.asyncio
    async def test_search_no_duplicates(self) -> None:
        """Verify that there are no duplicates in the results."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        result_list = list(result)
        assert len(result_list) == len(set(result_list))

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
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_search_nonexistent_domain(self) -> None:
        """Verify behavior with non-existent domain."""
        search = thc.SearchThc('this-domain-definitely-does-not-exist-12345.com')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_empty_domain(self) -> None:
        """Verify behavior with empty domain."""
        search = thc.SearchThc('')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_special_characters_domain(self) -> None:
        """Verify behavior with special characters."""
        search = thc.SearchThc('example.com; DROP TABLE domains;--')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_unicode_domain(self) -> None:
        """Verify behavior with IDN/unicode domain."""
        search = thc.SearchThc('xn--mnchen-3ya.de')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_subdomain_as_input(self) -> None:
        """Verify behavior when a subdomain is passed as input."""
        search = thc.SearchThc('www.example.com')
        await search.process()
        result = await search.get_hostnames()
        assert isinstance(result, set)


# =============================================================================
# 4. Proxy Tests
# =============================================================================
class TestThcProxy:
    """Tests for proxy functionality."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_process_accepts_proxy_parameter(self) -> None:
        """Verify that process() accepts proxy parameter."""
        search = thc.SearchThc(self.domain())
        await search.process(proxy=False)
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_proxy_attribute_is_set(self) -> None:
        """Verify that the proxy attribute is set correctly."""
        search = thc.SearchThc(self.domain())
        assert search.proxy is False


# =============================================================================
# 5. Initialization and Attributes Tests
# =============================================================================
class TestThcInitialization:
    """Tests for class initialization and structure."""

    def test_init_sets_word(self) -> None:
        """Verify that __init__ sets the domain."""
        domain = 'test.com'
        search = thc.SearchThc(domain)
        assert search.word == domain

    def test_init_creates_empty_results(self) -> None:
        """Verify that results is initialized empty."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'results')
        assert len(search.results) == 0

    def test_init_proxy_default_false(self) -> None:
        """Verify that proxy is False by default."""
        search = thc.SearchThc('test.com')
        assert search.proxy is False

    def test_init_has_rate_limit_settings(self) -> None:
        """Verify that rate limit settings are initialized."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'max_retries')
        assert hasattr(search, 'base_delay')
        assert search.max_retries == 3
        assert search.base_delay == 2

    def test_class_has_required_methods(self) -> None:
        """Verify that the class has the required methods."""
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
    """Tests to verify response format."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_hostnames_are_strings(self) -> None:
        """Verify that all hostnames are strings."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert isinstance(hostname, str)

    @pytest.mark.asyncio
    async def test_hostnames_are_valid_format(self) -> None:
        """Verify that hostnames have valid format."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert ' ' not in hostname
            assert '\n' not in hostname
            assert '\t' not in hostname

    @pytest.mark.asyncio
    async def test_hostnames_are_lowercase(self) -> None:
        """Verify that hostnames are lowercase."""
        search = thc.SearchThc(self.domain())
        await search.process()
        result = await search.get_hostnames()
        for hostname in result:
            assert hostname == hostname.lower()


# =============================================================================
# 7. Integration Tests with theHarvester
# =============================================================================
class TestThcIntegration:
    """Integration tests with theHarvester framework."""

    @pytest.mark.asyncio
    async def test_module_can_be_imported(self) -> None:
        """Verify that the module can be imported."""
        from theHarvester.discovery import thc as thc_module
        assert thc_module is not None

    @pytest.mark.asyncio
    async def test_search_class_exists(self) -> None:
        """Verify that SearchThc class exists."""
        from theHarvester.discovery import thc as thc_module
        assert hasattr(thc_module, 'SearchThc')

    @pytest.mark.asyncio
    async def test_compatible_with_store_function(self) -> None:
        """Verify compatibility with store function from __main__.py."""
        search = thc.SearchThc('example.com')
        assert hasattr(search, 'process')
        assert hasattr(search, 'get_hostnames')


if __name__ == '__main__':
    pytest.main()


pytestmark = pytest.mark.provider_contract('thc')
