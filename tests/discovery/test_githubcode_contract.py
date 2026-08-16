import contextlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from theHarvester.discovery import githubcode


class FakeResponse:
    status = 200

    def __init__(self, payload: dict[str, Any], links: dict[str, Any]) -> None:
        self.payload = payload
        self.links = links

    async def __aenter__(self) -> 'FakeResponse':
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def text(self) -> str:
        return ''

    async def json(self) -> dict[str, Any]:
        return self.payload


@pytest.fixture
def install_github_responses(monkeypatch: pytest.MonkeyPatch):
    requested_urls: list[str] = []

    def install(*responses: FakeResponse) -> list[str]:
        response_iterator = iter(responses)

        class FakeSession:
            def __init__(self, *, headers: dict[str, str]) -> None:
                pass

            async def __aenter__(self) -> 'FakeSession':
                return self

            async def __aexit__(self, *_args: Any) -> None:
                return None

            def get(self, url: str, *, proxy: str | None = None) -> FakeResponse:
                requested_urls.append(url)
                return next(response_iterator)

        @contextlib.asynccontextmanager
        async def fake_open_session(**_kwargs: object) -> AsyncIterator[FakeSession]:
            async with FakeSession(headers={}) as session:
                yield session

        monkeypatch.setattr(githubcode.AsyncFetcher, 'open_session', fake_open_session)
        return requested_urls

    monkeypatch.setattr(githubcode.Core, 'github_key', staticmethod(lambda: 'test-token'))
    monkeypatch.setattr(githubcode.Core, 'get_user_agent', staticmethod(lambda: 'test-agent'))
    monkeypatch.setattr(githubcode, 'get_delay', lambda: 0)
    return install


@pytest.mark.asyncio
async def test_github_code_retains_only_the_requested_fragments_across_pages(install_github_responses) -> None:
    requested_urls = install_github_responses(
        FakeResponse(
            {
                'items': [
                    {'text_matches': [{'fragment': 'Contact Admin@Example.COM'}]},
                    {'text_matches': [{'fragment': 'API host API.EXAMPLE.COM'}]},
                ]
            },
            {
                'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
                'last': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
            },
        ),
        FakeResponse(
            {
                'items': [
                    {'text_matches': [{'fragment': 'Docs host Docs.Example.Com'}]},
                    {'text_matches': [{'fragment': 'Ignored host ignored.example.com'}]},
                ]
            },
            {},
        ),
    )
    search = githubcode.SearchGithubCode('example.com', limit=3)

    await search.process()

    assert requested_urls == [
        'https://api.github.com/search/code?q="example.com"&page=1',
        'https://api.github.com/search/code?q="example.com"&page=2',
    ]
    assert search.counter == 3
    assert await search.get_emails() == {'admin@example.com'}
    assert await search.get_hostnames() == ['api.example.com', 'docs.example.com', 'example.com']


@pytest.mark.asyncio
async def test_github_code_exact_limit_makes_no_additional_request(install_github_responses) -> None:
    requested_urls = install_github_responses(
        FakeResponse(
            {
                'items': [
                    {'text_matches': [{'fragment': 'api.example.com'}]},
                    {'text_matches': [{'fragment': 'docs.example.com'}]},
                ]
            },
            {
                'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
                'last': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
            },
        )
    )
    search = githubcode.SearchGithubCode('example.com', limit=2)

    await search.process()

    assert requested_urls == ['https://api.github.com/search/code?q="example.com"&page=1']
    assert await search.get_hostnames() == ['api.example.com', 'docs.example.com']


@pytest.mark.asyncio
async def test_github_code_keeps_provider_fragments_separate(install_github_responses) -> None:
    install_github_responses(
        FakeResponse(
            {
                'items': [
                    {
                        'text_matches': [
                            {'fragment': 'admin'},
                            {'fragment': '@example.com'},
                        ]
                    }
                ]
            },
            {},
        )
    )
    search = githubcode.SearchGithubCode('example.com', limit=10)

    await search.process()

    assert await search.get_emails() == set()


@pytest.mark.asyncio
async def test_github_code_ignores_non_string_fragments_without_repeating_the_page(install_github_responses) -> None:
    requested_urls = install_github_responses(
        FakeResponse(
            {
                'items': [
                    {
                        'text_matches': [
                            {'fragment': None},
                            {'fragment': 42},
                            {'fragment': ''},
                            {'fragment': 'API host api.example.com'},
                        ]
                    }
                ]
            },
            {},
        ),
        FakeResponse({'items': []}, {}),
    )
    search = githubcode.SearchGithubCode('example.com', limit=10)

    await search.process()

    assert requested_urls == ['https://api.github.com/search/code?q="example.com"&page=1']
    assert await search.get_hostnames() == ['api.example.com']


@pytest.mark.parametrize(
    'payload',
    [
        {'items': 'not-a-list'},
        {'items': [{'text_matches': 'not-a-list'}]},
    ],
    ids=['malformed-items', 'malformed-text-matches'],
)
@pytest.mark.asyncio
async def test_github_code_malformed_page_terminates_without_following_pagination(
    install_github_responses,
    payload: dict[str, Any],
) -> None:
    requested_urls = install_github_responses(
        FakeResponse(
            payload,
            {
                'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
                'last': {'url': 'https://api.github.com/search/code?q=example.com&page=2'},
            },
        ),
        FakeResponse({'items': []}, {}),
    )
    search = githubcode.SearchGithubCode('example.com', limit=10)

    await search.process()

    assert requested_urls == ['https://api.github.com/search/code?q="example.com"&page=1']
    assert await search.get_emails() == set()
    assert await search.get_hostnames() == []


pytestmark = pytest.mark.provider_contract('github-code')
