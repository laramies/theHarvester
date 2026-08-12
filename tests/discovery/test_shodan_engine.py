import logging
import socket
import sys
from collections import OrderedDict
from datetime import UTC

import pytest


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
    async def test_shodan_engine_processes_without_work_item_error_and_yields_hostnames(self, monkeypatch, capsys):
        # Import inside the test so monkeypatching affects the already-imported module namespace.
        import theHarvester.__main__ as main_module

        # Make DNS resolution deterministic and offline.
        monkeypatch.setattr(socket, 'gethostbyname', lambda _domain: '1.2.3.4', raising=True)

        # Avoid filesystem/sqlite side effects.
        class DummyResultStore:
            async def initialize(self) -> None:
                return None

            async def record_observations(self, domain, all, res_type, source) -> None:
                return None

        monkeypatch.setattr(main_module, 'ResultStore', DummyResultStore, raising=True)

        # Stub Shodan search to avoid network and API key requirements.
        class DummySearchShodan:
            async def search_ip(self, ip):
                return OrderedDict({ip: {'hostnames': ['a.example.com', 'b.example.com']}})

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
