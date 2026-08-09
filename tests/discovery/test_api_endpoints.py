from types import SimpleNamespace

import aiohttp
import pytest

from theHarvester.discovery import api_endpoints
from theHarvester.lib.core import FetcherResponse


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


def test_api_endpoint_scan_defaults_to_direct_requests_with_redirects() -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')

    assert search.proxy is None
    assert search.follow_redirects is True


@pytest.mark.asyncio
async def test_api_endpoint_scan_uses_only_observational_http_methods(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('192.0.2.1')
    search.common_api_paths = ['/api']
    methods = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

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
async def test_api_endpoint_scan_uses_only_the_configured_wordlist(monkeypatch, tmp_path) -> None:
    wordlist = tmp_path / 'operator-paths.txt'
    wordlist.write_text('/health\n', encoding='utf-8')
    search = api_endpoints.SearchApiEndpoints('example.com', wordlist=str(wordlist), exact_paths=True)
    detected_paths: list[str] = []
    requested_urls: list[str] = []

    async def detect_schema(path: str = '') -> str:
        detected_paths.append(path)
        return 'https'

    async def fetch(url: str, *_args, **_kwargs):
        requested_urls.append(url)
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert detected_paths == ['/health']
    assert requested_urls == ['https://example.com/health'] * 3


@pytest.mark.asyncio
async def test_schema_detection_can_probe_an_exact_listed_path() -> None:
    search = api_endpoints.SearchApiEndpoints('example.com', exact_paths=True)
    session = FakeSession()
    search._session = session

    assert await search._detect_schema('/health') == 'https'
    assert session.requests[0][0] == 'https://example.com/health'


@pytest.mark.asyncio
async def test_api_endpoint_scan_exposes_shared_fetcher_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search.common_api_paths = ['/api']
    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema() -> str:
        return 'https'

    async def fetch(*_args, **kwargs):
        assert kwargs['include_metadata'] is True
        return FetcherResponse(
            body='{"status":"ok"}',
            status=200,
            headers={'content-type': 'application/json'},
        )

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    result = search.get_found_endpoints()['https://example.com/api']
    assert result.status_code == 200
    assert result.method == 'GET'
    assert result.content_type == 'application/json'
    assert result.content_length == len('{"status":"ok"}')
    assert result.content_preview == '{"status":"ok"}'


@pytest.mark.asyncio
async def test_api_endpoint_scan_counts_suppressed_request_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')
    search.common_api_paths = ['/api']
    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema() -> str:
        return 'https'

    async def fail_request(*_args, **kwargs):
        assert kwargs['include_metadata'] is True
        return None

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fail_request)

    await search.do_search()

    assert search.request_error_count == 3
    assert search.request_error_types == {'TransportError'}
    assert search.get_found_endpoints() == {}


@pytest.mark.asyncio
async def test_api_endpoint_scan_reports_suppressed_top_level_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    search = api_endpoints.SearchApiEndpoints('example.com')

    async def fail_schema_detection() -> str:
        raise RuntimeError('scan setup failed')

    monkeypatch.setattr(search, '_detect_schema', fail_schema_detection)

    assert await search.do_search() is None
    assert search.scan_error_type == 'RuntimeError'


@pytest.mark.asyncio
async def test_api_endpoint_scan_allows_an_operator_selected_private_target(monkeypatch) -> None:
    search = api_endpoints.SearchApiEndpoints('100.64.0.1')
    search.common_api_paths = ['/api']
    requests = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema():
        return 'https'

    async def fetch(*_args, **_kwargs):
        requests.append(True)
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == [True, True, True]


@pytest.mark.asyncio
async def test_api_endpoint_scan_uses_a_configured_proxy(monkeypatch) -> None:
    proxy = 'http://proxy.example:8080'
    search = api_endpoints.SearchApiEndpoints('192.0.2.1', proxy=proxy)
    search.common_api_paths = ['/api']
    requests = []

    monkeypatch.setattr(search, '_load_wordlist', lambda: [])

    async def detect_schema():
        return 'https'

    async def fetch(*_args, **kwargs):
        requests.append((kwargs['proxy'], kwargs['follow_redirects']))
        return ''

    monkeypatch.setattr(search, '_detect_schema', detect_schema)
    monkeypatch.setattr(api_endpoints.AsyncFetcher, 'fetch', fetch)

    await search.do_search()

    assert requests == [(proxy, True), (proxy, True), (proxy, True)]


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
async def test_detect_schema_reuses_session_with_configured_request_policy(monkeypatch) -> None:
    session = FakeSession()
    search = api_endpoints.SearchApiEndpoints('example.com', follow_redirects=True)
    search._session = session

    monkeypatch.setattr(
        api_endpoints.aiohttp,
        'ClientSession',
        lambda **_kwargs: pytest.fail('schema detection must reuse the scan session'),
    )

    assert await search._detect_schema() == 'https'
    assert session.requests == [
        (
            'https://example.com',
            {'proxy': None, 'ssl': True, 'allow_redirects': True},
        )
    ]
