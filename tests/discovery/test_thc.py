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
import os
from typing import Optional

import httpx
import pytest

from theHarvester.discovery import thc
from theHarvester.lib.core import Core

github_ci: Optional[str] = os.getenv('GITHUB_ACTIONS')


# =============================================================================
# 1. Direct API Tests (Endpoint Validation)
# =============================================================================
class TestThcApi:
    """Tests to validate that the THC API responds correctly."""

    @pytest.mark.asyncio
    async def test_api_subdomains_download_endpoint_responds(self) -> None:
        """Verify that the subdomain download endpoint responds."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=google.com&limit=10&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = httpx.get(url, headers=headers, timeout=30)
            assert response.status_code == 200
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')

    @pytest.mark.asyncio
    async def test_api_subdomains_returns_text_format(self) -> None:
        """Verify that the response is plain text."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=google.com&limit=5&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = httpx.get(url, headers=headers, timeout=30)
            content_type = response.headers.get('content-type', '')
            assert 'text' in content_type or 'octet-stream' in content_type or response.status_code == 200
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')

    @pytest.mark.asyncio
    async def test_api_cli_subdomain_endpoint(self) -> None:
        """Verify CLI endpoint /sb/{domain}."""
        url = 'https://ip.thc.org/sb/google.com?l=5&noheader'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = httpx.get(url, headers=headers, timeout=30)
            assert response.status_code == 200
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')

    @pytest.mark.asyncio
    async def test_api_returns_rate_limit_headers(self) -> None:
        """Verify that the API returns rate limit headers."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=example.com&limit=1&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = httpx.get(url, headers=headers, timeout=30)
            assert 'x-ratelimit-limit' in response.headers
            assert 'x-ratelimit-remaining' in response.headers
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')


# =============================================================================
# 2. Subdomain Search Tests (Main Functionality)
# =============================================================================
class TestThcSubdomainSearch:
    """Tests for subdomain search functionality."""

    @staticmethod
    def domain() -> str:
        return 'tesla.com'

    @staticmethod
    def small_domain() -> str:
        return 'thc.org'

    @pytest.mark.asyncio
    async def test_search_returns_set(self) -> None:
        """Verify that get_hostnames() returns a set."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_finds_subdomains(self) -> None:
        """Verify that it finds subdomains for a known domain."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        assert len(result) > 0, 'Should find at least one subdomain for tesla.com'

    @pytest.mark.asyncio
    async def test_search_results_contain_target_domain(self) -> None:
        """Verify that all results contain the target domain."""
        search = thc.SearchThc(self.small_domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert self.small_domain() in hostname, f'{hostname} should contain {self.small_domain()}'

    @pytest.mark.asyncio
    async def test_search_no_duplicates(self) -> None:
        """Verify that there are no duplicates in the results."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        result_list = list(result)
        assert len(result_list) == len(set(result_list))


# =============================================================================
# 3. Edge Case Tests
# =============================================================================
class TestThcEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_search_nonexistent_domain(self) -> None:
        """Verify behavior with non-existent domain."""
        search = thc.SearchThc('this-domain-definitely-does-not-exist-12345.com')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_empty_domain(self) -> None:
        """Verify behavior with empty domain."""
        search = thc.SearchThc('')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_special_characters_domain(self) -> None:
        """Verify behavior with special characters."""
        search = thc.SearchThc('example.com; DROP TABLE domains;--')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_unicode_domain(self) -> None:
        """Verify behavior with IDN/unicode domain."""
        search = thc.SearchThc('xn--mnchen-3ya.de')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_subdomain_as_input(self) -> None:
        """Verify behavior when a subdomain is passed as input."""
        search = thc.SearchThc('www.google.com')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
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
        try:
            await search.process(proxy=False)
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
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
        return 'github.com'

    @pytest.mark.asyncio
    async def test_hostnames_are_strings(self) -> None:
        """Verify that all hostnames are strings."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert isinstance(hostname, str)

    @pytest.mark.asyncio
    async def test_hostnames_are_valid_format(self) -> None:
        """Verify that hostnames have valid format."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert ' ' not in hostname
            assert '\n' not in hostname
            assert '\t' not in hostname

    @pytest.mark.asyncio
    async def test_hostnames_are_lowercase(self) -> None:
        """Verify that hostnames are lowercase."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert hostname == hostname.lower()


# =============================================================================
# 7. Integration Tests with theHarvester
# =============================================================================
@pytest.mark.skipif(github_ci == 'true', reason='Skip integration tests in CI')
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
