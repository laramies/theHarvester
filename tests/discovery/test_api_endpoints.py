from types import SimpleNamespace

import aiohttp
import pytest

from theHarvester.discovery import api_endpoints


class FakeResponse:
    async def __aenter__(self) -> 'FakeResponse':
        return self

    async def __aexit__(self, *_args) -> None:
        return None


class FakeSession:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    async def __aenter__(self) -> 'FakeSession':
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def get(self, *_args, **_kwargs) -> FakeResponse:
        if self.error:
            raise self.error
        return FakeResponse()


def test_process_response_extracts_only_string_json_parameter_names(monkeypatch):
    search = api_endpoints.SearchApiEndpoints('example.com')
    response = SimpleNamespace(
        status=200,
        headers={'Content-Type': 'application/json'},
        content=b'{"name": "value"}',
    )

    monkeypatch.setattr(api_endpoints.json, 'loads', lambda _content: {'name': 'value', 1: 'ignored'})

    result = search._process_response('https://example.com/api/v1/users', 'GET', response, 0.1)

    assert result is not None
    assert result.parameters == ['name']


@pytest.mark.parametrize('error', [aiohttp.ClientConnectionError(), TimeoutError()])
@pytest.mark.asyncio
async def test_detect_schema_falls_back_only_when_https_cannot_connect(monkeypatch, error: Exception) -> None:
    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', lambda **_kwargs: FakeSession(error))
    search = api_endpoints.SearchApiEndpoints('example.com')

    assert await search._detect_schema() == 'http'


@pytest.mark.asyncio
async def test_detect_schema_does_not_downgrade_after_https_client_error(monkeypatch) -> None:
    monkeypatch.setattr(
        api_endpoints.aiohttp,
        'ClientSession',
        lambda **_kwargs: FakeSession(aiohttp.ClientPayloadError('bad payload')),
    )
    search = api_endpoints.SearchApiEndpoints('example.com')

    with pytest.raises(aiohttp.ClientPayloadError, match='bad payload'):
        await search._detect_schema()
