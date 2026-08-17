from __future__ import annotations

from typing import Any

import pytest

from theHarvester.discovery.bravesearch import SearchBrave
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import AsyncFetcher, FetcherResponse


@pytest.mark.asyncio
async def test_brave_collects_with_in_memory_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    request_headers: list[dict[str, str]] = []

    async def fetch(*_args: Any, headers: dict[str, str], **_kwargs: Any) -> FetcherResponse:
        request_headers.append(headers)
        return FetcherResponse(
            {
                'query': {'more_results_available': False},
                'web': {
                    'results': [
                        {
                            'title': 'Documentation',
                            'description': 'Example documentation',
                            'url': 'https://docs.example.com',
                        }
                    ]
                },
            },
            200,
            {},
        )

    monkeypatch.setattr(AsyncFetcher, 'fetch_json', fetch)
    search = SearchBrave(
        'example.com',
        1,
        credential_adapter=InMemoryCredentialAdapter({'brave': {'key': 'memory-key'}}),
    )

    await search.process()

    assert set(await search.get_hostnames()) == {'docs.example.com'}
    assert request_headers
    assert {headers['X-Subscription-Token'] for headers in request_headers} == {'memory-key'}


def test_brave_rejects_empty_in_memory_credentials() -> None:
    credentials = InMemoryCredentialAdapter({'brave': {'key': ''}})

    with pytest.raises(MissingKey, match='Brave Search'):
        SearchBrave('example.com', 1, credential_adapter=credentials)
