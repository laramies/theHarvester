from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import yaml

import theHarvester.lib.core as core_module
from theHarvester.lib.core import CONFIG_DIRS, DATA_DIR, AsyncFetcher, Core, FetcherResponse
from theHarvester.lib.output import configure_logging
from theHarvester.lib.source_catalog import SOURCE_SPECS, ActivityClass


@pytest.fixture(autouse=True)
def mock_environ(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))


def test_email_capability_expands_to_email_sources() -> None:
    assert Core.expand_source_selection("emails") == [
        "baidu",
        "brave",
        "censys",
        "dehashed",
        "duckduckgo",
        "github-code",
        "gitlab",
        "hibpverified",
        "hudsonrock",
        "hunter",
        "intelx",
        "leaklookup",
        "mojeek",
        "rocketreach",
        "sherlockeye",
        "tomba",
        "windvane",
        "yahoo",
        "zoomeye",
    ]


def test_capabilities_and_explicit_sources_form_a_union() -> None:
    assert Core.expand_source_selection("certspotter, urls") == [
        "bevigil",
        "builtwith",
        "certspotter",
        "gitlab",
        "intelx",
        "rocketreach",
        "urlscan",
        "zoomeye",
    ]


def test_multiple_capabilities_form_a_union() -> None:
    assert Core.expand_source_selection("asns,people") == [
        "criminalip",
        "onyphe",
        "urlscan",
        "zoomeye",
    ]


def test_breach_capability_includes_every_matching_source() -> None:
    assert Core.expand_source_selection('breaches') == ['haveibeenpwned', 'hibpverified', 'leaklookup']


def test_named_source_can_be_combined_with_a_capability() -> None:
    assert Core.expand_source_selection('breaches,hibpverified') == ['haveibeenpwned', 'hibpverified', 'leaklookup']


def test_all_selects_only_passive_catalog_sources() -> None:
    assert Core.expand_source_selection("ALL") == sorted(
        spec.name
        for spec in SOURCE_SPECS.values()
        if spec.activity is ActivityClass.PASSIVE
    )
    assert {
        name: spec.activity for name, spec in SOURCE_SPECS.items() if spec.activity is not ActivityClass.PASSIVE
    } == {
        "criminalip": ActivityClass.DIRECT,
        "pentesttools": ActivityClass.DNS,
        "shodan": ActivityClass.DNS,
        "shodanInternetDB": ActivityClass.DNS,
        "subdomainfinderc99": ActivityClass.DNS,
        "windvane": ActivityClass.DNS,
    }


@pytest.mark.parametrize(
    'source',
    ['criminalip', 'pentesttools', 'shodan', 'shodanInternetDB', 'subdomainfinderc99', 'windvane'],
)
def test_non_passive_sources_run_only_when_explicitly_selected(source: str) -> None:
    assert source not in Core.expand_source_selection('all')
    assert Core.expand_source_selection(source) == [source]


def mock_read_text(mocked: dict[Path, str | Exception]):
    read_text = Path.read_text

    def _read_text(self: Path, *args, **kwargs):
        if result := mocked.get(self):
            if isinstance(result, Exception):
                raise result
            return result
        return read_text(self, *args, **kwargs)

    return _read_text


@pytest.mark.parametrize(
    ("name", "contents", "expected"),
    [
        ("api-keys", "apikeys: {}", {}),
        ("proxies", "http: [localhost:8080]", {"http": ["http://localhost:8080"], "socks5": []}),
    ],
)
@pytest.mark.parametrize("dir", CONFIG_DIRS)
def test_read_config_searches_config_dirs(
    name: str, contents: str, expected: Any, dir: Path, caplog
):
    caplog.set_level(logging.INFO, logger=core_module.__name__)
    file = dir.expanduser() / f"{name}.yaml"
    config_files = [d.expanduser() / file.name for d in CONFIG_DIRS]
    side_effect = mock_read_text(
        {f: contents if f == file else FileNotFoundError() for f in config_files}
    )

    with mock.patch("pathlib.Path.read_text", autospec=True, side_effect=side_effect):
        got = Core.api_keys() if name == "api-keys" else Core.proxy_list()

    assert got == expected
    assert f"Read {file.name} from {file}" in caplog.messages


@pytest.mark.parametrize("name", ("api-keys", "proxies"))
def test_read_config_copies_default_to_home(name: str, capsys):
    configure_logging(verbose=False)
    file = Path(f"~/.theHarvester/{name}.yaml").expanduser()
    config_files = [d.expanduser() / file.name for d in CONFIG_DIRS]
    side_effect = mock_read_text({f: FileNotFoundError() for f in config_files})

    with mock.patch("pathlib.Path.read_text", autospec=True, side_effect=side_effect):
        got = Core.api_keys() if name == "api-keys" else Core.proxy_list()

    default = yaml.safe_load((DATA_DIR / file.name).read_text())
    expected = (
        default["apikeys"]
        if name == "api-keys"
        else {
            "http": [f"http://{h}" for h in default["http"]] if default.get("http") else [],
            "socks5": [f"socks5://{h}" for h in default["socks5"]] if default.get("socks5") else [],
        }
    )
    assert got == expected
    assert f"Created default {file.name} at {file}" in capsys.readouterr().out
    assert file.exists()


_DEFAULT_JSON = object()


class DummyResponse:
    def __init__(
        self,
        text_value: str = 'response-text',
        json_value: Any = _DEFAULT_JSON,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ):
        self.text_value = text_value
        self.json_value = {'ok': True} if json_value is _DEFAULT_JSON else json_value
        self.status = status
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self.text_value

    async def json(self):
        if isinstance(self.json_value, Exception):
            raise self.json_value
        return self.json_value


class DummySession:
    instances: list[DummySession] = []

    def __init__(self, *, headers=None, timeout=None, connector=None):
        self.headers = headers
        self.timeout = timeout
        self.connector = connector
        self.closed = False
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        DummySession.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
        return False

    def request(self, method: str, url: str, **kwargs):
        self.requests.append((method, url, kwargs))
        return DummyResponse()

    def get(self, url: str, **kwargs):
        self.requests.append(('GET', url, kwargs))
        return DummyResponse()

    def post(self, url: str, **kwargs):
        self.requests.append(('POST', url, kwargs))
        return DummyResponse(json_value={'posted': True})

    async def close(self):
        self.closed = True


def reset_dummy_sessions() -> None:
    DummySession.instances.clear()


async def fake_sleep(_seconds: float) -> None:
    return None


def test_api_keys_yaml_is_in_sync_with_core_accessors():
    required = core_module.Core._API_KEY_FIELDS
    assert required, "No API-key references were detected in `Core`"

    config = yaml.safe_load((DATA_DIR / "api-keys.yaml").read_text(encoding="utf-8"))
    apikeys = config["apikeys"]

    missing_providers = sorted(set(required) - set(apikeys))
    assert not missing_providers, f"Missing providers in api-keys.yaml: {missing_providers}"

    missing_fields: dict[str, list[str]] = {}
    for provider, fields in required.items():
        for field in sorted(fields):
            if field not in apikeys[provider]:
                missing_fields.setdefault(provider, []).append(field)

    assert not missing_fields, f"Missing fields in api-keys.yaml: {missing_fields}"


@pytest.mark.parametrize(
    ("accessor_name", "expected"),
    [
        ("bevigil_key", "bevigil-key"),
        ("censys_key", ("censys-id", "censys-secret")),
        ("fofa_key", ("fofa-key", "fofa-email")),
        ("tomba_key", ("tomba-key", "tomba-secret")),
    ],
)
def test_api_key_accessors_delegate_to_shared_mapping(monkeypatch, accessor_name: str, expected: Any):
    monkeypatch.setattr(
        Core,
        'api_keys',
        staticmethod(
            lambda: {
                'bevigil': {'key': 'bevigil-key'},
                'censys': {'id': 'censys-id', 'secret': 'censys-secret'},
                'fofa': {'key': 'fofa-key', 'email': 'fofa-email'},
                'tomba': {'key': 'tomba-key', 'secret': 'tomba-secret'},
            }
        ),
    )

    accessor = getattr(Core, accessor_name)
    assert accessor() == expected


@pytest.mark.asyncio
async def test_fetch_creates_session_with_default_headers(monkeypatch) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)
    monkeypatch.setattr(Core, 'get_user_agent', staticmethod(lambda: 'test-agent'))

    result = await AsyncFetcher.fetch(url='https://example.com', follow_redirects=False)

    assert result == 'response-text'
    assert len(DummySession.instances) == 1
    session = DummySession.instances[0]
    assert session.headers == {'User-Agent': 'test-agent'}
    assert session.closed is True
    assert session.requests == [
        ('GET', 'https://example.com', {'ssl': 'ssl-context', 'allow_redirects': False})
    ]


@pytest.mark.asyncio
async def test_fetch_can_include_buffered_response_metadata(monkeypatch) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)

    def request_with_metadata(self, method: str, url: str, **kwargs):
        self.requests.append((method, url, kwargs))
        return DummyResponse(
            text_value='rate limited',
            status=429,
            headers={'Retry-After': '60', 'X-RateLimit-Remaining': '0'},
        )

    monkeypatch.setattr(DummySession, 'request', request_with_metadata)

    result = await AsyncFetcher.fetch(url='https://example.com', include_metadata=True)

    assert result == FetcherResponse(
        body='rate limited',
        status=429,
        headers={'retry-after': '60', 'x-ratelimit-remaining': '0'},
    )


@pytest.mark.asyncio
async def test_fetch_metadata_distinguishes_transport_failure(monkeypatch) -> None:
    async def failed_request(*_args: Any, **_kwargs: Any) -> str:
        raise OSError('network unavailable')

    monkeypatch.setattr(AsyncFetcher, '_request', failed_request)

    result = await AsyncFetcher.fetch(session=DummySession(), url='https://example.com', include_metadata=True)

    assert result is None


@pytest.mark.asyncio
async def test_fetch_metadata_preserves_non_json_error_body(monkeypatch) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)

    def request_with_invalid_json(self, method: str, url: str, **kwargs):
        self.requests.append((method, url, kwargs))
        return DummyResponse(text_value='upstream error', json_value=ValueError(), status=502)

    monkeypatch.setattr(DummySession, 'request', request_with_invalid_json)

    result = await AsyncFetcher.fetch(url='https://example.com', json=True, include_metadata=True)

    assert result == FetcherResponse(body='upstream error', status=502, headers={})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('text_value', 'expected_body'),
    [('', ''), ('null', None)],
)
async def test_fetch_metadata_distinguishes_empty_json_from_null(
    monkeypatch,
    text_value: str,
    expected_body: Any,
) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)

    def request_with_json(self, method: str, url: str, **kwargs):
        self.requests.append((method, url, kwargs))
        return DummyResponse(text_value=text_value, json_value=None)

    monkeypatch.setattr(DummySession, 'request', request_with_json)

    result = await AsyncFetcher.fetch(url='https://example.com', json=True, include_metadata=True)

    assert result == FetcherResponse(body=expected_body, status=200, headers={})


@pytest.mark.asyncio
async def test_fetch_all_propagates_metadata_opt_in(monkeypatch) -> None:
    seen: list[bool] = []

    async def fake_fetch(*_args: Any, include_metadata: bool = False, **_kwargs: Any) -> FetcherResponse:
        seen.append(include_metadata)
        return FetcherResponse(body='limited', status=429, headers={'retry-after': '60'})

    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(AsyncFetcher, 'fetch', fake_fetch)

    results = await AsyncFetcher.fetch_all(['https://one.example', 'https://two.example'], include_metadata=True)

    assert seen == [True, True]
    assert [result.status for result in results] == [429, 429]


@pytest.mark.asyncio
async def test_takeover_fetch_rejects_a_non_public_discovered_host() -> None:
    class NoRequestSession:
        def get(self, *_args, **_kwargs):
            raise AssertionError('HTTP request should not be created')

    result = await AsyncFetcher.takeover_fetch(NoRequestSession(), 'http://100.64.0.1')

    assert result == ('http://100.64.0.1', '')


@pytest.mark.asyncio
async def test_takeover_fetch_refuses_a_proxy_that_cannot_pin_the_target() -> None:
    class NoRequestSession:
        def get(self, *_args, **_kwargs):
            raise AssertionError('HTTP request should not be created')

    class PublicResolver:
        async def resolve(self, *_args, **_kwargs):
            return [{'host': '192.0.2.1'}]

    result = await AsyncFetcher.takeover_fetch(
        NoRequestSession(),
        'http://example.com',
        proxy='http://proxy.example:8080',
        resolver=PublicResolver(),
    )

    assert result == ('http://example.com', '')


@pytest.mark.asyncio
async def test_takeover_fetch_all_refuses_direct_egress_when_proxy_pool_is_empty(monkeypatch) -> None:
    reset_dummy_sessions()
    calls = []
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.aiohttp, 'TCPConnector', lambda **_kwargs: 'connector')
    monkeypatch.setattr(AsyncFetcher, '_get_random_proxy', staticmethod(lambda _proxy_dict: (None, None)))

    async def unexpected_takeover_fetch(*args, **kwargs):
        calls.append((args, kwargs))
        return 'http://example.com', 'direct response'

    monkeypatch.setattr(AsyncFetcher, 'takeover_fetch', unexpected_takeover_fetch)

    result = await AsyncFetcher.fetch_all(['http://example.com'], takeover=True, proxy=True)

    assert result == [('http://example.com', '')]
    assert calls == []


@pytest.mark.asyncio
async def test_fetch_uses_http_proxy_when_enabled(monkeypatch) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)
    monkeypatch.setattr(AsyncFetcher, '_get_random_proxy', staticmethod(lambda proxy_dict: ('http://proxy.local:8080', 'http')))

    async def fake_create_connector(proxy_url, proxy_type, ssl_context=None):
        return 'connector'

    monkeypatch.setattr(AsyncFetcher, '_create_connector', fake_create_connector)

    result = await AsyncFetcher.fetch(url='https://example.com', proxy=True)

    assert result == 'response-text'
    session = DummySession.instances[0]
    assert session.connector == 'connector'
    assert session.requests == [
        ('GET', 'https://example.com', {'ssl': 'ssl-context', 'proxy': 'http://proxy.local:8080'})
    ]


@pytest.mark.asyncio
async def test_post_fetch_decodes_string_payload_and_posts_params(monkeypatch) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')
    monkeypatch.setattr(Core, 'get_user_agent', staticmethod(lambda: 'test-agent'))

    result = await AsyncFetcher.post_fetch(
        'https://example.com/api',
        data='{"query": "example"}',
        params={'page': 2},
        json=True,
    )

    assert result == {'ok': True}
    session = DummySession.instances[0]
    assert session.headers == {'User-Agent': 'test-agent'}
    assert session.requests == [
        ('POST', 'https://example.com/api', {'data': {'query': 'example'}, 'ssl': 'ssl-context', 'params': {'page': 2}})
    ]


@pytest.mark.asyncio
async def test_post_fetch_sends_json_body(monkeypatch) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')

    result = await AsyncFetcher.post_fetch(
        'https://example.com/api',
        json_body={'scan': 'example'},
        json=True,
    )

    assert result == {'ok': True}
    session = DummySession.instances[0]
    assert session.requests == [
        ('POST', 'https://example.com/api', {'json': {'scan': 'example'}})
    ]


@pytest.mark.asyncio
async def test_post_fetch_can_include_response_metadata(monkeypatch) -> None:
    reset_dummy_sessions()
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)

    def request_with_metadata(self, method: str, url: str, **kwargs):
        self.requests.append((method, url, kwargs))
        return DummyResponse(text_value='unavailable', status=503, headers={'Retry-After': '30'})

    monkeypatch.setattr(DummySession, 'request', request_with_metadata)

    result = await AsyncFetcher.post_fetch('https://example.com/api', data='{}', include_metadata=True)

    assert result == FetcherResponse(body='unavailable', status=503, headers={'retry-after': '30'})


@pytest.mark.asyncio
async def test_post_fetch_proxy_branch_posts_body_and_params_with_http_proxy(monkeypatch) -> None:
    reset_dummy_sessions()
    created_connectors = []
    monkeypatch.setattr(core_module.aiohttp, 'ClientSession', DummySession)
    monkeypatch.setattr(core_module.asyncio, 'sleep', fake_sleep)
    monkeypatch.setattr(core_module.ssl, 'create_default_context', lambda cafile=None: 'ssl-context')
    monkeypatch.setattr(core_module.certifi, 'where', lambda: '/tmp/cacert.pem')
    monkeypatch.setattr(AsyncFetcher, '_get_random_proxy', staticmethod(lambda proxy_dict: ('http://proxy.local:8080', 'http')))

    async def fake_create_connector(proxy_url, proxy_type, ssl_context=None):
        created_connectors.append((proxy_url, proxy_type, ssl_context))
        return 'connector'

    monkeypatch.setattr(AsyncFetcher, '_create_connector', fake_create_connector)

    result = await AsyncFetcher.post_fetch(
        'https://example.com/resource',
        json_body={'scan': 'example'},
        params={'page': 2},
        json=True,
        proxy=True,
    )

    assert result == {'ok': True}
    assert created_connectors == [('http://proxy.local:8080', 'http', 'ssl-context')]
    session = DummySession.instances[0]
    assert session.connector == 'connector'
    assert session.requests == [
        (
            'POST',
            'https://example.com/resource',
            {'json': {'scan': 'example'}, 'params': {'page': 2}, 'proxy': 'http://proxy.local:8080'},
        )
    ]
