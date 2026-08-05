from typing import Any

import pytest

from theHarvester.discovery import duckduckgosearch


@pytest.mark.asyncio
async def test_duckduckgo_does_not_fetch_provider_returned_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[list[str], bool]] = []
    payload = """
    {
      "AbstractURL": "https://api.example.com",
      "AbstractText": "Contact admin@example.com.",
      "Results": [{"FirstURL": "https://outside.test"}]
    }
    """

    async def fake_fetch_all(
        urls: list[str] | set[str],
        *,
        headers: dict[str, str] | None = None,
        proxy: bool = False,
        **_kwargs: Any,
    ) -> list[str]:
        requests.append((list(urls), proxy))
        return [payload]

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = duckduckgosearch.SearchDuckDuckGo('example.com', 100)
    await search.process(proxy=True)

    assert requests == [(['https://api.duckduckgo.com/?q=example.com&format=json&pretty=1'], True)]
    assert await search.get_hostnames() == ['api.example.com', 'example.com']
    assert await search.get_emails() == {'admin@example.com'}


@pytest.mark.parametrize(
    'payload',
    [
        '',
        '{"broken": ',
        '{"error": "Access denied", "url": "https://api.example.net"}',
    ],
    ids=['empty', 'malformed', 'blocked'],
)
@pytest.mark.asyncio
async def test_duckduckgo_unusable_response_returns_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
) -> None:
    async def fake_fetch_all(urls: list[str] | set[str], **_kwargs: Any) -> list[str]:
        return [payload]

    monkeypatch.setattr(duckduckgosearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
    search = duckduckgosearch.SearchDuckDuckGo('example.com', 100)

    await search.process()

    assert await search.get_hostnames() == []
    assert await search.get_emails() == set()
