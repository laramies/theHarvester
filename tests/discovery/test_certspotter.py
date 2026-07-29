#!/usr/bin/env python3
# coding=utf-8
import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from theHarvester.discovery import certspottersearch
from theHarvester.lib.core import Core


class TestCertspotter(object):
    @staticmethod
    def domain() -> str:
        return 'example.com'


class TestCertspotterSearch(object):
    @pytest.mark.live_network
    def test_api(self) -> None:
        base_url = f"https://api.certspotter.com/v1/issuances?domain={TestCertspotter.domain()}&expand=dns_names"
        headers = {"User-Agent": Core.get_user_agent()}
        request = httpx.get(base_url, headers=headers, timeout=30)
        assert request.status_code == 200
        payload = request.json()
        assert isinstance(payload, list)
        assert all(isinstance(item, dict) for item in payload)

    @pytest.mark.asyncio
    async def test_search(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[list[dict[str, list[str]]]]:
            return [[{'dns_names': ['api.example.com', 'www.example.com']}]]

        monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        await search.process()
        assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}

    @pytest.mark.asyncio
    async def test_search_collects_all_pages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pages = [
            [{'id': '1', 'dns_names': ['first.example.com']}],
            [{'id': '2', 'dns_names': ['second.example.com']}],
            [],
        ]
        requested_urls: list[str] = []

        async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[list[dict[str, Any]]]:
            requested_urls.extend(urls)
            return [pages.pop(0)]

        monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        await search.process()

        assert await search.get_hostnames() == {'first.example.com', 'second.example.com'}
        assert [parse_qs(urlparse(url).query) for url in requested_urls] == [
            {'domain': ['example.com'], 'include_subdomains': ['true'], 'expand': ['dns_names']},
            {
                'domain': ['example.com'],
                'include_subdomains': ['true'],
                'expand': ['dns_names'],
                'after': ['1'],
            },
            {
                'domain': ['example.com'],
                'include_subdomains': ['true'],
                'expand': ['dns_names'],
                'after': ['2'],
            },
        ]

    @pytest.mark.asyncio
    async def test_search_returns_only_normalized_scoped_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pages = [
            [
                {
                    'id': '1',
                    'dns_names': [
                        'WWW.Example.COM.',
                        '*.api.example.com',
                        'example.com',
                        'outside.test',
                        'not example.com',
                        '.example.com',
                        'bad..example.com',
                        '-bad.example.com',
                        None,
                    ],
                }
            ],
            [],
        ]

        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[list[dict[str, Any]]]:
            return [pages.pop(0)]

        monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = certspottersearch.SearchCertspoter(' Example.COM. ')
        await search.process()

        assert await search.get_hostnames() == {'api.example.com', 'example.com', 'www.example.com'}

    @pytest.mark.asyncio
    async def test_search_preserves_results_when_rate_limited(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        responses: list[Any] = [
            [{'id': '1', 'dns_names': ['first.example.com']}],
            {'code': 'rate_limited', 'message': 'provider details must not be logged'},
        ]

        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[Any]:
            return [responses.pop(0)]

        monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        with caplog.at_level(logging.WARNING, logger=certspottersearch.__name__):
            await search.process()

        assert await search.get_hostnames() == {'first.example.com'}
        assert 'rate_limited' in caplog.text
        assert 'results may be incomplete' in caplog.text
        assert 'provider details must not be logged' not in caplog.text

    @pytest.mark.asyncio
    async def test_search_reports_transport_failure_as_incomplete(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        responses: list[Any] = [
            [{'id': '1', 'dns_names': ['first.example.com']}],
            '',
        ]

        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[Any]:
            return [responses.pop(0)]

        monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        with caplog.at_level(logging.WARNING, logger=certspottersearch.__name__):
            await search.process()

        assert await search.get_hostnames() == {'first.example.com'}
        assert 'results may be incomplete' in caplog.text

    @pytest.mark.asyncio
    async def test_search_stops_on_repeated_cursor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pages = [
            [{'id': 'repeated', 'dns_names': ['first.example.com']}],
            [{'id': 'repeated', 'dns_names': ['second.example.com']}],
        ]
        calls = 0

        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[list[dict[str, Any]]]:
            nonlocal calls
            calls += 1
            return [pages.pop(0)]

        monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        await search.process()

        assert await search.get_hostnames() == {'first.example.com', 'second.example.com'}
        assert calls == 2

    @pytest.mark.asyncio
    async def test_search_reports_safety_cap_as_incomplete(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(certspottersearch.SearchCertspoter, 'MAX_PAGES', 2)
        calls = 0

        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[list[dict[str, Any]]]:
            nonlocal calls
            calls += 1
            return [[{'id': str(calls), 'dns_names': [f'page-{calls}.example.com']}]]

        monkeypatch.setattr(certspottersearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        with caplog.at_level(logging.WARNING, logger=certspottersearch.__name__):
            await search.process()

        assert await search.get_hostnames() == {'page-1.example.com', 'page-2.example.com'}
        assert 'results may be incomplete' in caplog.text


if __name__ == "__main__":
    pytest.main()
