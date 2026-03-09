from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import yaml

import theHarvester.lib.core as core_module
from theHarvester.lib.core import CONFIG_DIRS, DATA_DIR, AsyncFetcher, Core


@pytest.fixture(autouse=True)
def mock_environ(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))


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
    name: str, contents: str, expected: Any, dir: Path, capsys
):
    file = dir.expanduser() / f"{name}.yaml"
    config_files = [d.expanduser() / file.name for d in CONFIG_DIRS]
    side_effect = mock_read_text(
        {f: contents if f == file else FileNotFoundError() for f in config_files}
    )

    with mock.patch("pathlib.Path.read_text", autospec=True, side_effect=side_effect):
        got = Core.api_keys() if name == "api-keys" else Core.proxy_list()

    assert got == expected
    assert f"Read {file.name} from {file}" in capsys.readouterr().out


@pytest.mark.parametrize("name", ("api-keys", "proxies"))
def test_read_config_copies_default_to_home(name: str, capsys):
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


class DummyResponse:
    def __init__(self, text_value: str = 'response-text', json_value: Any = None):
        self.text_value = text_value
        self.json_value = {'ok': True} if json_value is None else json_value

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self.text_value

    async def json(self):
        return self.json_value


class DummySession:
    instances: list['DummySession'] = []

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
async def test_post_fetch_proxy_branch_uses_get_with_http_proxy(monkeypatch) -> None:
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

    result = await AsyncFetcher.post_fetch('https://example.com/resource', proxy=True)

    assert result == 'response-text'
    assert created_connectors == [('http://proxy.local:8080', 'http', 'ssl-context')]
    session = DummySession.instances[0]
    assert session.connector == 'connector'
    assert session.requests == [
        ('GET', 'https://example.com/resource', {'proxy': 'http://proxy.local:8080'})
    ]
