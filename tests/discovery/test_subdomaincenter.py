import pytest

from theHarvester.discovery import subdomaincenter


@pytest.mark.asyncio
async def test_process_preserves_www_hostname(monkeypatch):
    async def fake_fetch_all(urls, headers=None, proxy=False, json=False):
        return [['www.example.com']]

    monkeypatch.setattr(subdomaincenter.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all))
    search = subdomaincenter.SubdomainCenter('example.com')

    await search.process()

    assert await search.get_hostnames() == {'www.example.com'}
