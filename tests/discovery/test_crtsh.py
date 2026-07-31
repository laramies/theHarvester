import asyncio

import pytest

from theHarvester.discovery import crtsh
from theHarvester.lib.run import SourceIncompleteError


def _patch_fetch(monkeypatch, payload):
    import theHarvester.lib.core as core_module

    calls = []

    async def fake_fetch_all(urls, headers=None, proxy=False, json=False):
        calls.append(urls)
        return [payload]

    monkeypatch.setattr(core_module.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all), raising=True)
    return calls


def _patch_sleep(monkeypatch):
    delays = []

    async def fake_sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(asyncio, 'sleep', fake_sleep)
    return delays


class TestCrtshSearch:
    def test_init_sets_state(self):
        search = crtsh.SearchCrtsh('example.com')
        assert search.word == 'example.com'
        assert search.data == []
        assert search.proxy is False

    @pytest.mark.asyncio
    async def test_process_collects_hostnames(self, monkeypatch):
        _patch_fetch(monkeypatch, [{'name_value': 'www.example.com'}, {'name_value': 'mail.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process(proxy=True)
        assert search.proxy is True
        assert set(await search.get_hostnames()) == {'www.example.com', 'mail.example.com'}

    @pytest.mark.asyncio
    async def test_wildcard_prefix_is_stripped(self, monkeypatch):
        _patch_fetch(monkeypatch, [{'name_value': '*.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        assert set(await search.get_hostnames()) == {'example.com'}

    @pytest.mark.asyncio
    async def test_multiline_name_value_is_split(self, monkeypatch):
        # crt.sh packs several names into one name_value separated by newlines.
        _patch_fetch(monkeypatch, [{'name_value': 'a.example.com\nb.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        assert set(await search.get_hostnames()) == {'a.example.com', 'b.example.com'}

    @pytest.mark.asyncio
    async def test_numeric_prefixed_entries_are_filtered(self, monkeypatch):
        _patch_fetch(monkeypatch, [{'name_value': '1234.example.com'}, {'name_value': 'good.example.com'}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        # The numeric-prefixed entry is filtered out, leaving only the valid hostname.
        assert set(await search.get_hostnames()) == {'good.example.com'}

    @pytest.mark.asyncio
    async def test_empty_response_returns_no_hostnames(self, monkeypatch):
        fetches = _patch_fetch(monkeypatch, [])
        delays = _patch_sleep(monkeypatch)
        search = crtsh.SearchCrtsh('example.com')
        await search.process()

        assert len(fetches) == 1
        assert delays == []
        assert await search.get_hostnames() == []

    @pytest.mark.asyncio
    async def test_failed_fetches_are_retried_with_delay(self, monkeypatch):
        import theHarvester.lib.core as core_module

        payloads = iter(['', '', [{'name_value': 'api.example.com'}]])
        fetch_count = 0

        async def fake_fetch_all(urls, headers=None, proxy=False, json=False):
            nonlocal fetch_count
            fetch_count += 1
            return [next(payloads)]

        monkeypatch.setattr(core_module.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all), raising=True)
        delays = _patch_sleep(monkeypatch)

        search = crtsh.SearchCrtsh('example.com')
        await search.process()

        assert fetch_count == 3
        assert delays == [2, 2]
        assert await search.get_hostnames() == ['api.example.com']

    @pytest.mark.asyncio
    async def test_invalid_responses_report_failure(self, monkeypatch):
        fetches = _patch_fetch(monkeypatch, '')
        delays = _patch_sleep(monkeypatch)
        search = crtsh.SearchCrtsh('example.com')

        with pytest.raises(SourceIncompleteError):
            await search.process()

        assert len(fetches) == 3
        assert delays == [2, 2]

    @pytest.mark.asyncio
    async def test_missing_name_value_key_reports_failure(self, monkeypatch):
        fetches = _patch_fetch(monkeypatch, [{'issuer_ca_id': 1}])
        delays = _patch_sleep(monkeypatch)
        search = crtsh.SearchCrtsh('example.com')

        with pytest.raises(SourceIncompleteError):
            await search.process()

        assert len(fetches) == 1
        assert delays == []


class TestCrtshIntegration:
    def test_supportedengines_lists_crtsh(self):
        from theHarvester.lib.core import Core

        assert 'crtsh' in Core.get_supportedengines()
