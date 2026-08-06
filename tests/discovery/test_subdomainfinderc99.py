import pytest

from theHarvester.discovery import subdomainfinderc99


@pytest.mark.asyncio
async def test_successful_response_returns_only_scoped_hostnames(monkeypatch) -> None:
    async def fake_fetch_all(*_args, **_kwargs):
        return ['<div class="input-group"><input name="token" value="abc"></div>']

    async def fake_post_fetch(*_args, **_kwargs):
        return 'api.example.test www.notexample.test'

    async def no_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(subdomainfinderc99.asyncio, 'sleep', no_sleep)

    search = subdomainfinderc99.SearchSubdomainfinderc99('example.test')
    await search.process()

    assert set(await search.get_hostnames()) == {'api.example.test'}


@pytest.mark.asyncio
async def test_empty_initial_response_completes_without_evidence(monkeypatch) -> None:
    async def fake_fetch_all(*_args, **_kwargs):
        return []

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = subdomainfinderc99.SearchSubdomainfinderc99('example.test')
    await search.process()

    assert not await search.get_hostnames()


@pytest.mark.asyncio
async def test_malformed_scan_response_completes_without_evidence(monkeypatch) -> None:
    async def fake_fetch_all(*_args, **_kwargs):
        return ['<div class="input-group"><input name="token" value="abc"></div>']

    async def fake_post_fetch(*_args, **_kwargs):
        return None

    async def no_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(subdomainfinderc99.AsyncFetcher, 'post_fetch', fake_post_fetch)
    monkeypatch.setattr(subdomainfinderc99.asyncio, 'sleep', no_sleep)

    search = subdomainfinderc99.SearchSubdomainfinderc99('example.test')
    await search.process()

    assert not await search.get_hostnames()
