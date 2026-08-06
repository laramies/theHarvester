import logging
import socket
import sys
from collections import OrderedDict

import pytest


class TestShodanEngine:
    @pytest.mark.asyncio
    async def test_shodan_provider_failure_returns_attributed_empty_evidence(self, monkeypatch, caplog):
        from theHarvester.discovery import shodansearch

        class FailingShodan:
            def host(self, _ip):
                raise shodansearch.exception.APIError('provider-secret-payload')

        monkeypatch.setattr(shodansearch.Core, 'shodan_key', lambda: 'test-key')
        monkeypatch.setattr(shodansearch, 'Shodan', lambda _key: FailingShodan())
        caplog.set_level(logging.INFO, logger=shodansearch.__name__)

        result = await shodansearch.SearchShodan().search_ip('203.0.113.1')

        assert result == OrderedDict({'203.0.113.1': 'Not in Shodan'})
        assert '203.0.113.1: Not in Shodan' in caplog.text
        assert 'provider-secret-payload' not in caplog.text

    @pytest.mark.asyncio
    async def test_shodan_engine_processes_without_work_item_error_and_yields_hostnames(self, monkeypatch, capsys):
        # Import inside the test so monkeypatching affects the already-imported module namespace.
        import theHarvester.__main__ as main_module

        # Make DNS resolution deterministic and offline.
        monkeypatch.setattr(socket, "gethostbyname", lambda _domain: "1.2.3.4", raising=True)

        # Avoid filesystem/sqlite side effects.
        class DummyStashManager:
            async def do_init(self) -> None:
                return None

            async def store_all(self, domain, all, res_type, source) -> None:  # noqa: A002
                return None

        monkeypatch.setattr(main_module.stash, "StashManager", DummyStashManager, raising=True)

        # Stub Shodan search to avoid network and API key requirements.
        class DummySearchShodan:
            async def search_ip(self, ip):
                return OrderedDict({ip: {"hostnames": ["a.example.com", "b.example.com"]}})

        monkeypatch.setattr(main_module.shodansearch, "SearchShodan", DummySearchShodan, raising=True)

        # Run the CLI path that uses the engine queue/worker (`-b shodan`).
        monkeypatch.setattr(sys, "argv", ["theHarvester", "-d", "example.com", "-b", "shodan"], raising=True)

        with pytest.raises(SystemExit) as excinfo:
            await main_module.start()
        assert excinfo.value.code == 0

        out = capsys.readouterr().out
        assert 'An error occurred while processing a "work item"' not in out
        assert "a.example.com" in out
        assert "b.example.com" in out

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
