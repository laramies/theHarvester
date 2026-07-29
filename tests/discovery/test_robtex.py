from typing import Any

import pytest

from theHarvester.discovery import robtex


@pytest.mark.asyncio
async def test_robtex_does_not_send_domain_to_reverse_ip_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    async def fake_fetch_all(urls: list[str], **_kwargs: Any) -> list[str]:
        requested_urls.extend(urls)
        return ['{"rrname":"api.example.com","rrtype":"A","rrdata":"192.0.2.1"}']

    monkeypatch.setattr(robtex.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = robtex.SearchRobtex('example.com')
    await search.process()

    assert requested_urls == ['https://freeapi.robtex.com/pdns/forward/example.com']
    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_ips() == {'192.0.2.1'}
