import logging

import pytest

from theHarvester.discovery import onyphe


@pytest.mark.asyncio
async def test_failed_response_body_is_not_logged(monkeypatch, caplog) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    monkeypatch.setattr(onyphe.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch_all(*args, **kwargs):
        return [{'text': 'Failed', 'secret': 'provider-secret-payload'}]

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)
    caplog.set_level(logging.INFO, logger=onyphe.__name__)

    search = onyphe.SearchOnyphe('example.com')
    await search.process()

    assert 'provider-secret-payload' not in caplog.text
    assert 'did not succeed' in caplog.text


@pytest.mark.asyncio
async def test_unexpected_response_body_is_not_in_error(monkeypatch) -> None:
    monkeypatch.setattr(onyphe.Core, 'onyphe_key', lambda: 'test-key')
    monkeypatch.setattr(onyphe.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch_all(*args, **kwargs):
        return ['provider-secret-payload']

    monkeypatch.setattr(onyphe.AsyncFetcher, 'fetch_all', fake_fetch_all)

    with pytest.raises(TypeError) as error:
        await onyphe.SearchOnyphe('example.com').process()

    assert 'provider-secret-payload' not in str(error.value)
