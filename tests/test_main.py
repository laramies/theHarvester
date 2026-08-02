import argparse
import logging
import sys

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


@pytest.mark.asyncio
async def test_selected_sources_execute_once_through_central_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    process_calls = {'builtwith': 0, 'securityscorecard': 0}
    stored: list[tuple[str, tuple[str, ...], str, str]] = []

    class FakeBuiltWithSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False
            process_calls['builtwith'] += 1

        async def get_hostnames(self) -> list[str]:
            return ['app.example.com']

        async def get_interestingurls(self) -> list[str]:
            return ['https://example.com/login']

    class FakeSecurityScorecardSearch:
        def __init__(self, target: str) -> None:
            assert target == 'example.com'

        async def process(self, proxy: bool = False) -> None:
            assert proxy is False
            process_calls['securityscorecard'] += 1

        async def get_hostnames(self) -> list[str]:
            return ['score.example.com']

        async def get_ips(self) -> list[str]:
            return ['192.0.2.10']

    monkeypatch.setattr(theharvester_main.builtwith, 'SearchBuiltWith', FakeBuiltWithSearch)
    monkeypatch.setattr(theharvester_main.securityscorecard, 'SearchSecurityScorecard', FakeSecurityScorecardSearch)
    _patch_stash(monkeypatch, stored)

    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'builtwith,securityscorecard', '--quiet'],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    assert process_calls == {'builtwith': 1, 'securityscorecard': 1}
    assert ('example.com', ('https://example.com/login',), 'interestingurls', 'builtwith') in stored
    assert ('example.com', ('192.0.2.10',), 'ip', 'securityscorecard') in stored
