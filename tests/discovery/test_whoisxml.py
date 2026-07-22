import logging

import pytest

from theHarvester.discovery import whoisxml


@pytest.mark.asyncio
async def test_response_body_is_not_logged_and_records_are_returned(monkeypatch, caplog) -> None:
    monkeypatch.setattr(whoisxml.Core, 'whoisxml_key', lambda: 'test-key')
    monkeypatch.setattr(whoisxml.Core, 'get_user_agent', lambda: 'test-agent')

    async def fake_fetch_all(*args, **kwargs):
        return [
            {
                'secret': 'provider-secret-payload',
                'result': {'records': [{'domain': 'www.example.com'}]},
            }
        ]

    monkeypatch.setattr(whoisxml.AsyncFetcher, 'fetch_all', fake_fetch_all)
    caplog.set_level(logging.INFO, logger=whoisxml.__name__)

    search = whoisxml.SearchWhoisXML('example.com')
    await search.process()

    assert await search.get_hostnames() == ['www.example.com']
    assert 'provider-secret-payload' not in caplog.text
