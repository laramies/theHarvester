from argparse import Namespace

from fastapi.testclient import TestClient

from theHarvester.lib.api import api
from theHarvester.lib.core import Core


def test_query_expands_source_capability(monkeypatch) -> None:
    captured: list[Namespace] = []

    async def fake_start(args: Namespace):
        captured.append(args)
        return ([], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=subdomains')

    assert response.status_code == 200
    assert captured[0].source == ','.join(Core.expand_source_selection('subdomains'))


def test_query_unions_capabilities_and_explicit_sources(monkeypatch) -> None:
    captured: list[Namespace] = []

    async def fake_start(args: Namespace):
        captured.append(args)
        return ([], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=emails&source=certspotter')

    assert response.status_code == 200
    assert captured[0].source == ','.join(Core.expand_source_selection('emails,certspotter'))


def test_query_rejects_unknown_source_or_capability(monkeypatch) -> None:
    async def unexpected_start(_args: Namespace):
        raise AssertionError('enumeration must not start')

    monkeypatch.setattr(api.__main__, 'start', unexpected_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=unknown')

    assert response.status_code == 400
    assert response.json()['detail'].startswith("Source 'unknown' is not supported")
