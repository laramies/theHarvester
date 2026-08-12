from typing import Any

import pytest

from theHarvester.discovery import yahoosearch


@pytest.mark.asyncio
async def test_yahoo_uses_exact_pages_and_normalizes_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, Any]] = []

    async def fake_fetch_all(
        urls: list[str] | set[str],
        headers: dict[str, str] | None = None,
        proxy: bool = False,
        **_kwargs: Any,
    ) -> list[str]:
        requests.append({'urls': list(urls), 'headers': headers, 'proxy': proxy})
        return [
            'Contact Admin@Example.COM. at Blog.Example.COM.',
            'Ignore outsider@example.net and api.example.net',
        ]

    monkeypatch.setattr(yahoosearch.Core, 'get_browser_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(yahoosearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = yahoosearch.SearchYahoo('example.com', 20)
    await search.process(proxy=True)

    assert requests == [
        {
            'urls': [
                'https://search.yahoo.com/search?p=%40example.com&b=0&pz=10',
                'https://search.yahoo.com/search?p=%40example.com&b=10&pz=10',
            ],
            'headers': {'Host': 'search.yahoo.com', 'User-Agent': 'UA'},
            'proxy': True,
        }
    ]
    assert set(await search.get_emails()) == {'admin@example.com'}
    assert await search.get_hostnames() == ['blog.example.com', 'example.com']


@pytest.mark.parametrize(
    'response',
    ['', None, '<html>Access denied at api.example.net</html>'],
    ids=['empty', 'malformed', 'blocked'],
)
@pytest.mark.asyncio
async def test_yahoo_unusable_responses_return_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    response: str | None,
) -> None:
    async def fake_fetch_all(urls: list[str] | set[str], **_kwargs: Any) -> list[str | None]:
        return [response] * len(urls)

    monkeypatch.setattr(yahoosearch.AsyncFetcher, 'fetch_all', fake_fetch_all)

    search = yahoosearch.SearchYahoo('example.com', 20)
    await search.process()

    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
