#!/usr/bin/env python3
# coding=utf-8
from typing import Any

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


if __name__ == "__main__":
    pytest.main()
