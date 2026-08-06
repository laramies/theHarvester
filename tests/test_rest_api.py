from argparse import Namespace

import pytest
from fastapi.testclient import TestClient

from theHarvester.lib.api import api
from theHarvester.lib.core import Core


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    api.limiter.reset()
    yield
    api.limiter.reset()


def test_query_expands_source_capability(monkeypatch) -> None:
    captured: list[tuple[Namespace, bool]] = []

    async def fake_start(args: Namespace, *, persist_completed_result: bool = False):
        captured.append((args, persist_completed_result))
        return ([], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=subdomains')

    assert response.status_code == 200
    assert captured[0][0].source == ','.join(Core.expand_source_selection('subdomains'))
    assert captured[0][1] is True


def test_query_unions_capabilities_and_explicit_sources(monkeypatch) -> None:
    captured: list[tuple[Namespace, bool]] = []

    async def fake_start(args: Namespace, *, persist_completed_result: bool = False):
        captured.append((args, persist_completed_result))
        return ([], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=emails&source=certspotter')

    assert response.status_code == 200
    expected_sources = [source for source in Core.expand_source_selection('emails,certspotter') if source != 'hibpverified']
    assert captured[0][0].source == ','.join(expected_sources)
    assert captured[0][1] is True


def test_query_rejects_unknown_source_or_capability(monkeypatch) -> None:
    async def unexpected_start(_args: Namespace):
        raise AssertionError('enumeration must not start')

    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=unknown')

    assert response.status_code == 400
    assert response.json()['detail'].startswith("Source 'unknown' is not supported")


def test_query_rejects_explicit_verified_hibp_source(monkeypatch) -> None:
    async def unexpected_start(_args: Namespace, *, persist_completed_result: bool = False):
        raise AssertionError('enumeration must not start')

    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=hibpverified')

    assert response.status_code == 400
    assert response.json()['detail'] == "Source 'hibpverified' is available only through the CLI"


def test_query_omits_verified_hibp_from_capability_selection(monkeypatch) -> None:
    captured: list[Namespace] = []

    async def fake_start(args: Namespace, *, persist_completed_result: bool = False):
        captured.append(args)
        return ([], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=breaches')

    assert response.status_code == 200
    assert captured[0].source == 'haveibeenpwned'


def test_sources_omits_cli_only_verified_hibp(monkeypatch) -> None:
    monkeypatch.setattr(api.__main__.Core, 'get_supportedengines', lambda: ['crtsh', 'hibpverified'])

    response = TestClient(api.app).get('/sources')

    assert response.status_code == 200
    assert response.json() == {'sources': ['crtsh']}
