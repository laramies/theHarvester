import pytest

from theHarvester.discovery import crtsh


def _patch_fetch(monkeypatch, payload):
    import theHarvester.lib.core as core_module

    async def fake_fetch_all(urls, headers=None, proxy=False, json=False):
        return [payload]

    monkeypatch.setattr(core_module.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all), raising=True)


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
        import theHarvester.lib.core as core_module

        async def fake_fetch_all(urls, headers=None, proxy=False, json=False):
            return []

        monkeypatch.setattr(core_module.AsyncFetcher, 'fetch_all', staticmethod(fake_fetch_all), raising=True)
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        assert await search.get_hostnames() == []

    @pytest.mark.asyncio
    async def test_missing_name_value_key_is_handled(self, monkeypatch):
        _patch_fetch(monkeypatch, [{'issuer_ca_id': 1}])
        search = crtsh.SearchCrtsh('example.com')
        await search.process()
        assert await search.get_hostnames() == []


class TestCrtshIntegration:
    def test_supportedengines_lists_crtsh(self):
        from theHarvester.lib.core import Core

        assert 'crtsh' in Core.get_supportedengines()
