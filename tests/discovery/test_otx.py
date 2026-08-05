#!/usr/bin/env python3
# coding=utf-8
from typing import Any

import httpx
import pytest

from theHarvester.discovery import otxsearch
from theHarvester.lib.core import Core


class TestOtx(object):
    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.live_network
    def test_api(self) -> None:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.domain()}/passive_dns'
        response = httpx.get(url, headers={'User-Agent': Core.get_user_agent()}, timeout=30)

        assert response.status_code == 200
        assert isinstance(response.json().get('passive_dns'), list)

    @pytest.mark.asyncio
    async def test_search(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_fetch_all(*_args: Any, **_kwargs: Any) -> list[dict[str, list[dict[str, Any]]]]:
            return [
                {
                    'passive_dns': [
                        {'hostname': 'api.example.com', 'address': '192.0.2.1'},
                        {'hostname': 'api.example.com', 'address': '2001:0db8::1'},
                        {'hostname': 'api.example.com', 'address': '999.0.0.1'},
                        {'hostname': 'www.example.com', 'address': 'NXDOMAIN'},
                        {'hostname': 'www.example.com', 'address': 1234},
                    ]
                }
            ]

        monkeypatch.setattr(otxsearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = otxsearch.SearchOtx(TestOtx.domain())
        await search.process()
        assert await search.get_hostnames() == {'api.example.com', 'www.example.com'}
        assert await search.get_ips() == {'192.0.2.1', '2001:db8::1'}


if __name__ == "__main__":
    pytest.main()
