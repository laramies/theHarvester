import pytest

from theHarvester.discovery import takeover
from theHarvester.lib.core import FetcherResponse


@pytest.mark.asyncio
async def test_takeover_distinguishes_transport_failure_from_successful_empty_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    search = takeover.TakeOver(['api.example.com', 'timeout.example.com'])
    monkeypatch.setattr(search, 'fingerprints', {'No such app': 'Heroku'})

    async def fake_fetch_all(urls, **kwargs):
        assert kwargs['include_metadata'] is True
        assert kwargs['headers'] == {'User-Agent': takeover.Core.get_browser_user_agent()}
        assert set(urls) == {
            'https://api.example.com',
            'http://api.example.com',
            'https://timeout.example.com',
            'http://timeout.example.com',
        }
        return [
            ('https://api.example.com', FetcherResponse(body='No such app', status=200, headers={})),
            ('http://api.example.com', FetcherResponse(body='', status=204, headers={})),
            ('https://timeout.example.com', None),
            ('http://timeout.example.com', FetcherResponse(body='not vulnerable', status=200, headers={})),
        ]

    monkeypatch.setattr(takeover.AsyncFetcher, 'fetch_all', fake_fetch_all)

    assert await search.process() is None

    assert search.request_count == 4
    assert search.request_error_count == 1
    assert search.request_error_types == {'TransportError'}
    assert search.scan_error_type is None
    assert await search.get_takeover_results() == {'https://api.example.com': [{'No such app': 'Heroku'}]}
