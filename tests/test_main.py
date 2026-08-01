import argparse
import logging

import pytest

from theHarvester import __main__ as theharvester_main


def _start_args(source: str = 'crtsh') -> argparse.Namespace:
    return argparse.Namespace(
        api_scan=False,
        dns_brute=False,
        dns_lookup=False,
        dns_resolve='',
        dns_server=None,
        domain='example.com',
        filename='',
        limit=500,
        proxies=False,
        quiet=True,
        shodan=False,
        source=source,
        start=0,
        take_over=False,
        wordlist='',
    )


def _patch_stash(monkeypatch: pytest.MonkeyPatch, stored: list[tuple[str, tuple[str, ...], str, str]]) -> None:
    class FakeStashManager:
        async def do_init(self) -> None:
            return None

        async def store_all(self, domain: str, values: list[str], result_type: str, source: str) -> None:
            stored.append((domain, tuple(values), result_type, source))

    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStashManager)


@pytest.mark.asyncio
async def test_crtsh_collection_executes_once_and_feeds_legacy_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    process_calls: list[bool] = []
    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FakeCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, proxy: bool = False) -> None:
            process_calls.append(proxy)

        async def get_hostnames(self) -> list[str]:
            return ['WWW.EXAMPLE.COM.', 'api.example.com', 'example.com.evil.test']

    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FakeCrtshSearch)
    _patch_stash(monkeypatch, stored)

    await theharvester_main.start(_start_args())

    assert process_calls == [False]
    assert stored == [('example.com', ('api.example.com', 'www.example.com'), 'host', 'CRTsh')]


@pytest.mark.asyncio
async def test_crtsh_collection_reports_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    process_calls: list[bool] = []
    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FailingCrtshSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, proxy: bool = False) -> None:
            process_calls.append(proxy)
            raise RuntimeError('provider unavailable')

        async def get_hostnames(self) -> list[str]:
            raise AssertionError('failed sources have no results')

    monkeypatch.setattr(theharvester_main.crtsh, 'SearchCrtsh', FailingCrtshSearch)
    _patch_stash(monkeypatch, stored)
    caplog.set_level(logging.INFO, logger='theHarvester.output')

    await theharvester_main.start(_start_args())

    assert process_calls == [False]
    assert stored == []
    assert 'Source CRTsh failed: RuntimeError' in caplog.text


@pytest.mark.asyncio
async def test_invalid_subdomains_do_not_suppress_other_source_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    process_calls: list[bool] = []
    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FakeBaiduSearch:
        def __init__(self, target: str, limit: int) -> None:
            assert (target, limit) == ('example.com', 500)

        async def process(self, proxy: bool = False) -> None:
            process_calls.append(proxy)

        async def get_hostnames(self) -> list[str]:
            return ['bad host']

        async def get_emails(self) -> list[str]:
            return ['ops@example.com']

    monkeypatch.setattr(theharvester_main.baidusearch, 'SearchBaidu', FakeBaiduSearch)
    _patch_stash(monkeypatch, stored)

    await theharvester_main.start(_start_args('baidu'))

    assert process_calls == [False]
    assert stored == [('example.com', ('ops@example.com',), 'email', 'baidu')]
