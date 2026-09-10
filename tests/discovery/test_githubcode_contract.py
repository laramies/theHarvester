from __future__ import annotations

import asyncio
import contextlib
import json
from typing import TYPE_CHECKING, Any

import pytest

from theHarvester.discovery import githubcode

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class FakeResponse:
    status = 200

    def __init__(self, payload: dict[str, Any], links: dict[str, Any]) -> None:
        self.payload = payload
        self.links = links
        self.headers: dict[str, str] = {}
        self.content = self

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def text(self) -> str:
        return ''

    async def json(self) -> dict[str, Any]:
        return self.payload

    async def iter_any(self):
        yield json.dumps(self.payload).encode()


@pytest.fixture
def install_github_responses(monkeypatch: pytest.MonkeyPatch):
    requested_urls: list[str] = []

    def install(*responses: FakeResponse) -> list[str]:
        response_iterator = iter(responses)

        class FakeSession:
            def __init__(self, *, headers: dict[str, str]) -> None:
                pass

            async def __aenter__(self) -> FakeSession:
                return self

            async def __aexit__(self, *_args: Any) -> None:
                return None

            def get(self, url: str, *, proxy: str | None = None) -> FakeResponse:
                requested_urls.append(url)
                return next(response_iterator)

            def request(self, method: str, url: str, **_kwargs: Any) -> FakeResponse:
                assert method == 'GET'
                return self.get(url)

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


@pytest.mark.asyncio
async def test_github_code_unlimited_pagination_cycle_preserves_partial_evidence(install_github_responses) -> None:
    requested_urls = install_github_responses(
        FakeResponse(
            {'items': [{'text_matches': [{'fragment': 'api.example.com'}]}]},
            {'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'}},
        ),
        FakeResponse(
            {'items': [{'text_matches': [{'fragment': 'docs.example.com'}]}]},
            {'next': {'url': 'https://api.github.com/search/code?q=example.com&page=1'}},
        ),
    )
    search = githubcode.SearchGithubCode('example.com', limit=None)

    report = await search.process()

    assert requested_urls == [
        'https://api.github.com/search/code?q="example.com"&page=1',
        'https://api.github.com/search/code?q="example.com"&page=2',
    ]
    assert await search.get_hostnames() == ['api.example.com', 'docs.example.com']
    assert report == githubcode.SourceExecutionReport('partial', 'repeated-page')


@pytest.mark.asyncio
async def test_github_code_unlimited_repeated_content_stops_before_counting_duplicates(
    install_github_responses,
) -> None:
    requested_urls = install_github_responses(
        FakeResponse(
            {
                'items': [
                    {'text_matches': [{'fragment': 'api.example.com'}, {'fragment': 'docs.example.com'}]},
                ]
            },
            {'next': {'url': 'https://api.github.com/search/code?q=example.com&page=2'}},
        ),
        FakeResponse(
            {
                'items': [
                    {'text_matches': [{'fragment': 'docs.example.com'}, {'fragment': 'api.example.com'}]},
                ]
            },
            {'next': {'url': 'https://api.github.com/search/code?q=example.com&page=3'}},
        ),
    )
    search = githubcode.SearchGithubCode('example.com', limit=None)

    report = await search.process()

    assert requested_urls == [
        'https://api.github.com/search/code?q="example.com"&page=1',
        'https://api.github.com/search/code?q="example.com"&page=2',
    ]
    assert search.counter == 2
    assert await search.get_hostnames() == ['api.example.com', 'docs.example.com']
    assert report == githubcode.SourceExecutionReport('partial', 'repeated-page')


@pytest.mark.parametrize('fragments', [[], ['api.example.com']], ids=['no-evidence', 'partial-evidence'])
@pytest.mark.asyncio
async def test_github_code_persistent_exceptions_stop_with_truthful_report(
    monkeypatch: pytest.MonkeyPatch,
    fragments: list[str],
) -> None:
    monkeypatch.setattr(githubcode.Core, 'github_key', staticmethod(lambda: 'test-token'))
    monkeypatch.setattr(githubcode, 'get_delay', lambda: 0)
    search = githubcode.SearchGithubCode('example.com', limit=None)
    search.total_results = ' '.join(fragments)
    search.counter = len(fragments)
    search.max_retries = 1
    calls = 0

    async def fail_search(*_args: Any, **_kwargs: Any) -> tuple[str, dict, int, Any]:
        nonlocal calls
        calls += 1
        raise RuntimeError('persistent provider failure')

    monkeypatch.setattr(search, 'do_search', fail_search)

    report = await search.process()

    assert calls == 2
    assert report == githubcode.SourceExecutionReport('partial' if fragments else 'failed', 'transport-error')


@pytest.mark.asyncio
async def test_github_code_cancellation_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(githubcode.Core, 'github_key', staticmethod(lambda: 'test-token'))
    search = githubcode.SearchGithubCode('example.com', limit=None)

    async def cancel_search(*_args: Any, **_kwargs: Any) -> tuple[str, dict, int, Any]:
        raise asyncio.CancelledError('operator-stop')

    monkeypatch.setattr(search, 'do_search', cancel_search)

    with pytest.raises(asyncio.CancelledError, match='operator-stop'):
        await search.process()


pytestmark = pytest.mark.provider_contract('github-code')
