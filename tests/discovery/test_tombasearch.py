import pytest

from theHarvester.discovery import tombasearch
from theHarvester.discovery.constants import MissingKey


@pytest.mark.parametrize(
    'credentials',
    [
        (None, 'test-secret'),
        ('test-key', None),
        ('  ', 'test-secret'),
        ('test-key', '  '),
    ],
)
def test_tomba_rejects_missing_or_blank_credentials(monkeypatch, credentials) -> None:
    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: credentials)

    with pytest.raises(MissingKey):
        tombasearch.SearchTomba('example.test', 10, 0)


@pytest.mark.asyncio
async def test_paid_tomba_search_uses_documented_pages_and_page_size(monkeypatch) -> None:
    requests: list[tuple[str, bool]] = []
    responses = iter(
        [
            {
                'data': {
                    'pricing': {'name': 'Growth'},
                    'requests': {'domains': {'available': 10, 'used': 0}},
                }
            },
            {'data': {'total': 120}},
            {
                'data': {
                    'emails': [
                        {'email': 'alice@example.test', 'sources': [{'website_url': 'api.example.test'}]},
                    ]
                }
            },
            {
                'data': {
                    'emails': [
                        {'email': 'bob@example.test', 'sources': [{'website_url': 'www.example.test'}]},
                    ]
                }
            },
            {'data': {'emails': []}},
        ]
    )

    async def fake_fetch_all(urls, *, proxy=False, **_kwargs):
        requests.append((urls[0], proxy))
        return [next(responses)]

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    monkeypatch.setattr(tombasearch.asyncio, 'sleep', no_sleep)

    search = tombasearch.SearchTomba('example.test', 120, 0)
    await search.process(proxy=True)

    assert requests == [
        ('https://api.tomba.io/v1/me', True),
        ('https://api.tomba.io/v1/email-count?domain=example.test', True),
        ('https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=1', True),
        ('https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=2', True),
        ('https://api.tomba.io/v1/domain-search?domain=example.test&limit=50&page=3', True),
    ]
    assert await search.get_emails() == ['alice@example.test', 'bob@example.test']
    assert await search.get_hostnames() == ['api.example.test', 'www.example.test']


@pytest.mark.asyncio
async def test_paid_tomba_search_stops_before_exceeding_quota(monkeypatch) -> None:
    requests: list[str] = []
    responses = iter(
        [
            {
                'data': {
                    'pricing': {'name': 'Growth'},
                    'requests': {'domains': {'available': 2, 'used': 0}},
                }
            },
            {'data': {'total': 120}},
        ]
    )

    async def fake_fetch_all(urls, **_kwargs):
        requests.append(urls[0])
        return [next(responses)]

    monkeypatch.setattr(tombasearch.Core, 'tomba_key', lambda: ('test-key', 'test-secret'))
    monkeypatch.setattr(tombasearch.Core, 'get_user_agent', lambda: 'test-agent')
    monkeypatch.setattr(tombasearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = tombasearch.SearchTomba('example.test', 120, 0)
    await search.process()

    assert requests == [
        'https://api.tomba.io/v1/me',
        'https://api.tomba.io/v1/email-count?domain=example.test',
    ]
    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
