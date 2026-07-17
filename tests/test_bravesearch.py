from __future__ import annotations

from typing import Any

import pytest

from theHarvester.discovery.bravesearch import SearchBrave
from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.configuration import InMemoryCredentialAdapter
from theHarvester.lib.core import AsyncFetcher


@pytest.mark.asyncio
async def test_brave_collects_with_in_memory_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    request_headers: list[dict[str, str]] = []

    async def fetch(*, headers: dict[str, str], **_kwargs: Any) -> dict[str, Any]:
        request_headers.append(headers)
        return {
            'web': {
                'results': [
                    {
                        'title': 'Documentation',
                        'description': 'Example documentation',
                        'url': 'https://docs.example.com',
                    }
                ]
            }
        }

    monkeypatch.setattr(AsyncFetcher, 'fetch', fetch)
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
