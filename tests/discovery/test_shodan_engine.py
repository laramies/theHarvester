import asyncio
import logging
import socket
import sys
import threading
import time
from collections import OrderedDict
from datetime import UTC
from types import SimpleNamespace

import pytest


def patch_shodan_resolution(monkeypatch, shodansearch, address='203.0.113.10'):
    class Resolver:
        async def getaddrinfo(self, target, *, family):
            assert family == socket.AF_INET
            return SimpleNamespace(nodes=[SimpleNamespace(addr=(address, 0))])

    monkeypatch.setattr(shodansearch.aiodns, 'DNSResolver', lambda **_kwargs: Resolver())


class TestShodanEngine:
    @pytest.mark.asyncio
    async def test_shodan_retains_sourced_asn_organization_attribution(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        class SuccessfulShodan:
            def host(self, _ip):
                return {
                    'asn': 'AS64496',
                    'org': 'Example Transit',
                    'isp': 'Example ISP Label',
                    'data': [{'ip_str': '198.51.100.20'}],
                }

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: SuccessfulShodan())
        search = shodansearch.SearchShodan()

        await search.search_ip('192.0.2.10')

        attributions = await search.get_asn_attributions()
        assert len(attributions) == 1
        attribution = next(iter(attributions))
        assert attribution.producer_kind == 'action'
        assert attribution.producer == 'shodan'
        assert attribution.asn == 'AS64496'
        assert attribution.organization_label == 'Example Transit'
        assert attribution.subject_kind == 'ip'
        assert attribution.subject_value == '192.0.2.10'
        assert attribution.collected_at.tzinfo is UTC

    @pytest.mark.asyncio
    async def test_shodan_provider_failure_returns_attributed_empty_evidence(self, monkeypatch, caplog):
        from theHarvester.discovery import shodansearch

        class FailingShodan:
            def host(self, _ip):
                raise shodansearch.exception.APIError('No information available for that IP.')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: FailingShodan())
        caplog.set_level(logging.INFO, logger=shodansearch.__name__)

        search = shodansearch.SearchShodan()
        result = await search.search_ip('203.0.113.1')

        assert result == OrderedDict({'203.0.113.1': 'Not in Shodan'})
        assert search.error_type is None
        assert '203.0.113.1: Not in Shodan' in caplog.text

    @pytest.mark.asyncio
    async def test_shodan_api_failure_exposes_only_its_error_type(self, monkeypatch, caplog):
        from theHarvester.discovery import shodansearch

        class FailingShodan:
            def host(self, _ip):
                raise shodansearch.exception.APIError('provider-secret-payload')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: FailingShodan())
        caplog.set_level(logging.INFO, logger=shodansearch.__name__)

        search = shodansearch.SearchShodan()
        result = await search.search_ip('203.0.113.1')

        assert result == OrderedDict({'203.0.113.1': 'Shodan request failed'})
        assert search.error_type == 'APIError'
        assert 'provider-secret-payload' not in caplog.text

    @pytest.mark.asyncio
    async def test_shodan_unexpected_failure_exposes_only_its_error_type(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        class FailingShodan:
            def host(self, _ip):
                raise RuntimeError('provider-secret-payload')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: FailingShodan())

        search = shodansearch.SearchShodan()
        result = await search.search_ip('203.0.113.1')

        assert result == OrderedDict({'203.0.113.1': 'Shodan request failed'})
        assert search.error_type == 'RuntimeError'

    @pytest.mark.asyncio
    async def test_shodan_discovery_resolves_target_and_returns_only_normalized_scoped_hostnames(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        class SuccessfulShodan:
            def host(self, ip):
                assert ip == '203.0.113.10'
                return {
                    'data': [{'ip_str': ip}],
                    'hostnames': [
                        'API.Example.TEST.',
                        'example.test',
                        'www.notexample.test',
                    ],
                }

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: SuccessfulShodan())
        patch_shodan_resolution(monkeypatch, shodansearch)

        search = shodansearch.SearchShodan(' Example.TEST. ')
        await search.process()

        assert await search.get_hostnames() == {'api.example.test'}
        assert search.execution_status == 'completed'
        assert search.stop_reason is None

    @pytest.mark.asyncio
    async def test_shodan_discovery_resolves_www_input_but_uses_the_canonical_scope(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        queried_targets = []

        class Resolver:
            async def getaddrinfo(self, target, *, family):
                queried_targets.append((target, family))
                return SimpleNamespace(nodes=[SimpleNamespace(addr=('203.0.113.10', 0))])

        class SuccessfulShodan:
            def host(self, ip):
                return {
                    'data': [{'ip_str': ip}],
                    'hostnames': ['api.example.test', 'www.example.test', 'example.test', 'outside.test'],
                }

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: SuccessfulShodan())
        monkeypatch.setattr(shodansearch.aiodns, 'DNSResolver', lambda **_kwargs: Resolver())

        search = shodansearch.SearchShodan('WWW.Example.TEST.')
        await search.process()

        assert queried_targets == [('www.example.test', socket.AF_INET)]
        assert await search.get_hostnames() == {'api.example.test', 'www.example.test'}

    def test_shodan_discovery_requires_a_configured_key(self, monkeypatch):
        from theHarvester.discovery import shodansearch
        from theHarvester.discovery.constants import MissingKey

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: None)

        with pytest.raises(MissingKey):
            shodansearch.SearchShodan('example.test')

    @pytest.mark.asyncio
    async def test_shodan_discovery_reports_dns_failure_without_calling_provider(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        class UnexpectedShodan:
            def host(self, _ip):
                raise AssertionError('provider lookup must not run')

        class FailingResolver:
            async def getaddrinfo(self, _target, *, family):
                raise shodansearch.aiodns.error.DNSError(shodansearch.aiodns.error.ARES_ENOTFOUND, 'not found')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: UnexpectedShodan())
        monkeypatch.setattr(shodansearch.aiodns, 'DNSResolver', lambda **_kwargs: FailingResolver())

        search = shodansearch.SearchShodan('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert search.execution_status == 'failed'
        assert search.stop_reason == 'dns-resolution-failed'

    @pytest.mark.asyncio
    async def test_shodan_discovery_reports_provider_failure_without_exposing_payload(self, monkeypatch, caplog):
        from theHarvester.discovery import shodansearch

        class FailingShodan:
            def host(self, _ip):
                raise shodansearch.exception.APIError('provider-secret-payload')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: FailingShodan())
        patch_shodan_resolution(monkeypatch, shodansearch)
        caplog.set_level(logging.INFO, logger=shodansearch.__name__)

        search = shodansearch.SearchShodan('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert search.execution_status == 'failed'
        assert search.stop_reason == 'provider-error'
        assert 'provider-secret-payload' not in caplog.text

    @pytest.mark.asyncio
    async def test_shodan_discovery_reports_a_successful_zero_yield(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        class EmptyShodan:
            def host(self, _ip):
                raise shodansearch.exception.APIError('No information available for that IP.')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: EmptyShodan())
        patch_shodan_resolution(monkeypatch, shodansearch)

        search = shodansearch.SearchShodan('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert search.execution_status == 'completed'
        assert search.stop_reason == 'no-results'

    @pytest.mark.asyncio
    async def test_shodan_discovery_cancellation_propagates_while_provider_thread_finishes(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        entered = threading.Event()
        release = threading.Event()

        class BlockingShodan:
            def host(self, ip):
                entered.set()
                release.wait(1)
                return {'data': [{'ip_str': ip}], 'hostnames': []}

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: BlockingShodan())
        patch_shodan_resolution(monkeypatch, shodansearch)

        task = asyncio.create_task(shodansearch.SearchShodan('example.test').process())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()

    @pytest.mark.asyncio
    async def test_shodan_discovery_keeps_event_loop_responsive_during_blocking_calls(self, monkeypatch):
        from theHarvester.discovery import shodansearch

        dns_entered = asyncio.Event()
        dns_release = asyncio.Event()
        provider_entered = threading.Event()
        provider_release = threading.Event()

        class BlockingResolver:
            async def getaddrinfo(self, _target, *, family):
                dns_entered.set()
                await dns_release.wait()
                return SimpleNamespace(nodes=[SimpleNamespace(addr=('203.0.113.10', 0))])

        class BlockingShodan:
            def host(self, ip):
                provider_entered.set()
                provider_release.wait(1)
                return {'data': [{'ip_str': ip}], 'hostnames': ['api.example.test']}

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: BlockingShodan())
        monkeypatch.setattr(shodansearch.aiodns, 'DNSResolver', lambda **_kwargs: BlockingResolver())
        provider_timer = threading.Timer(0.4, provider_release.set)
        provider_timer.start()

        task = asyncio.create_task(shodansearch.SearchShodan('example.test').process())
        try:
            await asyncio.wait_for(dns_entered.wait(), 1)
            assert not task.done()
            dns_release.set()
            assert await asyncio.to_thread(provider_entered.wait, 1)
            assert not task.done()
            provider_release.set()
            await task
        finally:
            dns_release.set()
            provider_release.set()
            provider_timer.cancel()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ('blocking_stage', 'expected_reason'),
        [('dns', 'dns-timeout'), ('provider', 'provider-timeout')],
    )
    async def test_shodan_discovery_bounds_blocking_calls(self, monkeypatch, blocking_stage, expected_reason):
        from theHarvester.discovery import shodansearch

        class NeverResolver:
            async def getaddrinfo(self, _target, *, family):
                await asyncio.Event().wait()

        class TimeoutSession:
            def request(self, *_args, timeout=None, **_kwargs):
                assert timeout == 0.01
                time.sleep(timeout)
                raise TimeoutError

        class BoundedShodan:
            def __init__(self):
                self._session = TimeoutSession()

            def host(self, ip):
                if blocking_stage == 'provider':
                    self._session.request('GET')
                return {'data': [{'ip_str': ip}], 'hostnames': []}

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: BoundedShodan())
        monkeypatch.setattr(shodansearch.SearchShodan, 'REQUEST_TIMEOUT_SECONDS', 0.01)
        monkeypatch.setattr(shodansearch.SearchShodan, 'AWAIT_TIMEOUT_SECONDS', 0.02)
        if blocking_stage == 'dns':
            monkeypatch.setattr(shodansearch.aiodns, 'DNSResolver', lambda **_kwargs: NeverResolver())
        else:
            patch_shodan_resolution(monkeypatch, shodansearch)

        search = shodansearch.SearchShodan('example.test')
        started = time.monotonic()
        await search.process()

        assert time.monotonic() - started < 0.5
        assert search.execution_status == 'failed'
        assert search.stop_reason == expected_reason

    @pytest.mark.asyncio
    async def test_shodan_engine_processes_without_work_item_error_and_yields_hostnames(self, monkeypatch, capsys):
        # Import inside the test so monkeypatching affects the already-imported module namespace.
        import theHarvester.__main__ as main_module

        # Avoid filesystem/sqlite side effects.
        class DummyResultStore:
            async def initialize(self) -> None:
                return None

            async def record_observations(self, domain, all, res_type, source) -> None:
                return None

        monkeypatch.setattr(main_module, 'ResultStore', DummyResultStore, raising=True)

        # Stub Shodan search to avoid network and API key requirements.
        class DummySearchShodan:
            def __init__(self, domain):
                assert domain == 'example.com'

            async def process(self, proxy=False):
                return None

            async def get_hostnames(self):
                return {'a.example.com', 'b.example.com'}

        monkeypatch.setattr(main_module.shodansearch, 'SearchShodan', DummySearchShodan, raising=True)

        # Run the CLI path that uses the engine queue/worker (`-b shodan`).
        monkeypatch.setattr(sys, 'argv', ['theHarvester', '-d', 'example.com', '-b', 'shodan'], raising=True)

        with pytest.raises(SystemExit) as excinfo:
            await main_module.start()
        assert excinfo.value.code == 0

        out = capsys.readouterr().out
        assert 'An error occurred while processing a "work item"' not in out
        output_tokens = set(out.split())
        assert {'a.example.com', 'b.example.com'} <= output_tokens

    @pytest.mark.asyncio
    async def test_shodan_internetdb_ignores_non_string_resolved_addresses(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        monkeypatch.setattr(
            shodan_internetdb.socket,
            'getaddrinfo',
            lambda *_args: [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('203.0.113.1', 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', (12345, 0)),
            ],
            raising=True,
        )

        async def fake_fetch_all(urls, json=False, proxy=False):
            assert urls == ['https://internetdb.shodan.io/203.0.113.1']
            return [{'ip': '203.0.113.1', 'hostnames': ['www.example.com']}]

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fake_fetch_all, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB('example.com')
        await search.process()

        assert await search.get_hostnames() == {'www.example.com'}
        assert await search.get_ips() == {'203.0.113.1'}

    @pytest.mark.asyncio
    async def test_shodan_internetdb_normalizes_scoped_provider_evidence(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        monkeypatch.setattr(
            shodan_internetdb.socket,
            'getaddrinfo',
            lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('203.0.113.1', 0))],
            raising=True,
        )

        async def fake_fetch_all(_urls, json=False, proxy=False):
            return [
                {
                    'ip': '203.0.113.1',
                    'hostnames': ['API.Example.TEST.', 'www.notexample.test', None],
                    'ports': [443],
                },
                {'ip': '198.51.100.2', 'ports': [80]},
            ]

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fake_fetch_all, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB(' Example.TEST. ')
        await search.process()

        assert await search.get_hostnames() == {'api.example.test'}
        assert await search.get_ips() == {'203.0.113.1'}

    @pytest.mark.asyncio
    async def test_shodan_internetdb_rejects_evidence_for_an_unrequested_ip(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        monkeypatch.setattr(
            shodan_internetdb.socket,
            'getaddrinfo',
            lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('203.0.113.1', 0))],
            raising=True,
        )

        async def fake_fetch_all(_urls, json=False, proxy=False):
            return [
                {
                    'ip': '198.51.100.2',
                    'hostnames': ['injected.example.test'],
                    'ports': [443],
                    'vulns': ['CVE-2026-0001'],
                    'tags': ['injected'],
                    'cpes': ['cpe:/a:injected'],
                }
            ]

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fake_fetch_all, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert not await search.get_ips()
        assert not await search.get_ports()
        assert not await search.get_vulns()
        assert not await search.get_tags()
        assert not await search.get_cpes()

    @pytest.mark.asyncio
    async def test_shodan_internetdb_retains_a_matching_ip_with_empty_details(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        monkeypatch.setattr(
            shodan_internetdb.socket,
            'getaddrinfo',
            lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('203.0.113.1', 0))],
            raising=True,
        )

        async def fake_fetch_all(_urls, json=False, proxy=False):
            return [{'ip': '203.0.113.1', 'hostnames': [], 'ports': [], 'vulns': [], 'tags': [], 'cpes': []}]

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fake_fetch_all, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB('example.test')
        await search.process()

        assert await search.get_ips() == {'203.0.113.1'}

    @pytest.mark.asyncio
    async def test_shodan_internetdb_resolution_failure_skips_provider_request(self, monkeypatch):
        from theHarvester.discovery import shodan_internetdb

        def fail_resolution(*_args):
            raise socket.gaierror

        async def fail_fetch(*_args, **_kwargs):
            raise AssertionError('provider request must not run')

        monkeypatch.setattr(shodan_internetdb.socket, 'getaddrinfo', fail_resolution, raising=True)
        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fail_fetch, raising=True)

        search = shodan_internetdb.SearchShodanInternetDB('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert not await search.get_ips()

    @pytest.mark.asyncio
    async def test_shodan_internetdb_provider_failure_completes_without_evidence(self, monkeypatch, caplog):
        from theHarvester.discovery import shodan_internetdb

        monkeypatch.setattr(
            shodan_internetdb.socket,
            'getaddrinfo',
            lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('203.0.113.1', 0))],
            raising=True,
        )

        async def fail_fetch(*_args, **_kwargs):
            raise RuntimeError('provider-secret-payload')

        monkeypatch.setattr(shodan_internetdb.AsyncFetcher, 'fetch_all', fail_fetch, raising=True)
        caplog.set_level(logging.INFO, logger=shodan_internetdb.__name__)

        search = shodan_internetdb.SearchShodanInternetDB('example.test')
        await search.process()

        assert not await search.get_hostnames()
        assert not await search.get_ips()
        assert 'Shodan InternetDB request failed' in caplog.text
        assert 'provider-secret-payload' not in caplog.text
