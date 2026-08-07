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
        self.requests: list[tuple[str, dict[str, object]]] = []

    async def __aenter__(self) -> 'FakeSession':
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def get(self, url: str, **kwargs) -> FakeResponse:
        self.requests.append((url, kwargs))
        if self.error:
            raise self.error
        return FakeResponse()


class TestNetResolver:
    async def resolve(self, *_args, **_kwargs):
        return [{'host': '192.0.2.1'}]

    async def close(self) -> None:
        return None


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


@pytest.mark.asyncio
async def test_api_endpoint_scan_uses_only_observational_http_methods(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('192.0.2.1')
    search.common_api_paths = ['/api']
    methods = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])
    monkeypatch.setattr(api_endpoints, 'PublicResolver', TestNetResolver)

    async def detect_schema():
        return 'https'

    async def fetch(*_args, method='GET', **_kwargs):
        methods.append(method)
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert methods == ['GET', 'HEAD', 'OPTIONS']


@pytest.mark.asyncio
async def test_api_endpoint_scan_rejects_a_non_public_target_before_http(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('100.64.0.1')
    search.common_api_paths = ['/api']
    requests = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def fetch(*_args, **_kwargs):
        requests.append(True)
        return ''

    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == []


@pytest.mark.asyncio
async def test_api_endpoint_scan_refuses_an_unpinned_proxy(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('192.0.2.1', proxy='http://proxy.example:8080')
    sessions = []

    def unexpected_session(*_args, **_kwargs):
        sessions.append(True)
        raise AssertionError('HTTP session should not be created')

    monkeypatch.setattr(api_endpoints.aiohttp, 'ClientSession', unexpected_session)

    await search.do_search()

    assert sessions == []


@pytest.mark.parametrize('error', [aiohttp.ClientConnectionError(), TimeoutError()])
@pytest.mark.asyncio
async def test_detect_schema_falls_back_only_when_https_cannot_connect(monkeypatch, error: Exception) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search._session = FakeSession(error)

    assert await search._detect_schema() == 'http'


@pytest.mark.asyncio
async def test_detect_schema_does_not_downgrade_after_https_client_error(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search._session = FakeSession(aiohttp.ClientPayloadError('bad payload'))

    with pytest.raises(aiohttp.ClientPayloadError, match='bad payload'):
        await search._detect_schema()


@pytest.mark.asyncio
async def test_detect_schema_reuses_pinned_session_without_redirects(monkeypatch) -> None:
    session = FakeSession()
    search = api_endpoints.SearchApiEndpoints('example.com', follow_redirects=True)
    search._session = session

    monkeypatch.setattr(
        api_endpoints.aiohttp,
        'ClientSession',
        lambda **_kwargs: pytest.fail('schema detection must reuse the pinned session'),
    )

    assert await search._detect_schema() == 'https'
    assert session.requests == [
        (
            'https://example.com',
            {'proxy': None, 'ssl': True, 'allow_redirects': False},
        )
    ]
