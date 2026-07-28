import logging

import pytest

from theHarvester.discovery import leakix


@pytest.mark.asyncio
async def test_authentication_response_body_is_not_logged(monkeypatch, caplog) -> None:
    monkeypatch.setattr(leakix.Core, 'leakix_key', lambda: None)
    monkeypatch.setattr(leakix.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch_all(*args, **kwargs):
        return ['Incorrect API Key: provider-secret-payload']

    monkeypatch.setattr(leakix.AsyncFetcher, 'fetch_all', fake_fetch_all)
    caplog.set_level(logging.INFO, logger=leakix.__name__)

    await leakix.SearchLeakix('example.com').process()

    assert 'provider-secret-payload' not in caplog.text
    assert 'requires authentication' in caplog.text
