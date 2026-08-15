import pytest

from theHarvester.discovery import dymosearch
from theHarvester.discovery.constants import MissingKey


def _patch_dymo_key(monkeypatch, value):
    import theHarvester.lib.core as core_module

    monkeypatch.setattr(core_module.Core, 'dymo_key', staticmethod(lambda: value), raising=True)
    monkeypatch.setattr(core_module.Core, 'get_user_agent', staticmethod(lambda: 'UA'), raising=True)


class TestDymoSearch:
    def test_missing_key_raises(self, monkeypatch):
        _patch_dymo_key(monkeypatch, None)
        with pytest.raises(MissingKey):
            dymosearch.SearchDymo('example.com')

    def test_init_sets_state(self, monkeypatch):
        _patch_dymo_key(monkeypatch, 'token-123')
        search = dymosearch.SearchDymo('example.com')
        assert search.word == 'example.com'
        assert search.key == 'token-123'
        assert search.proxy is False
        assert search.totalhosts == set()
        assert search.results == {}

    def test_headers_use_bearer(self, monkeypatch):
        _patch_dymo_key(monkeypatch, 'token-abc')
        search = dymosearch.SearchDymo('example.com')
        headers = search._headers()
        assert headers['Authorization'] == 'Bearer token-abc'
        assert headers['Content-Type'] == 'application/json'
        assert headers['User-Agent'] == 'UA'

    @pytest.mark.asyncio
    async def test_process_extracts_canonical_and_suggestion(self, monkeypatch):
        _patch_dymo_key(monkeypatch, 'token-xyz')
        captured = {}

        async def fake_post_fetch(url, headers=None, data='', params='', json=False, proxy=False):
            captured['url'] = url
            captured['headers'] = headers
            captured['data'] = data
            captured['proxy'] = proxy
            return {
                'domain': {
                    'valid': True,
                    'fraud': False,
                    'freeSubdomain': False,
                    'domain': 'exemple.com',
                    'didYouMean': 'www.exemple.com',
                },
                'url': {
                    'valid': True,
                    'domain': 'exemple.com',
                    'didYouMean': None,
                },
            }

        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, 'post_fetch', classmethod(lambda cls, *a, **kw: fake_post_fetch(*a, **kw)))

        search = dymosearch.SearchDymo('exemple.com')
        await search.process(proxy=True)

        assert captured['url'] == dymosearch.SearchDymo.VERIFY_URL
        assert captured['proxy'] is True
        assert captured['data'] == {'domain': 'exemple.com', 'url': 'https://exemple.com'}
        assert captured['headers']['Authorization'] == 'Bearer token-xyz'

        hosts = await search.get_hostnames()
        results = await search.get_results()

        assert 'exemple.com' in hosts
        assert 'www.exemple.com' in hosts
        assert results['domain']['valid'] is True

    @pytest.mark.asyncio
    async def test_process_handles_empty_payload(self, monkeypatch):
        _patch_dymo_key(monkeypatch, 'token')

        async def fake_post_fetch(url, headers=None, data='', params='', json=False, proxy=False):
            return {}

        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, 'post_fetch', classmethod(lambda cls, *a, **kw: fake_post_fetch(*a, **kw)))

        search = dymosearch.SearchDymo('example.com')
        await search.process()
        assert await search.get_hostnames() == set()
        assert await search.get_results() == {}

    @pytest.mark.asyncio
    async def test_process_ignores_unrelated_suggestion(self, monkeypatch):
        _patch_dymo_key(monkeypatch, 'token')

        async def fake_post_fetch(url, headers=None, data='', params='', json=False, proxy=False):
            return {
                'domain': {
                    'valid': True,
                    'domain': 'totally-different.org',
                    'didYouMean': 'somewhere-else.net',
                },
            }

        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, 'post_fetch', classmethod(lambda cls, *a, **kw: fake_post_fetch(*a, **kw)))

        search = dymosearch.SearchDymo('example.com')
        await search.process()
        # Neither contains 'example.com', so neither should be added.
        assert await search.get_hostnames() == set()

    @pytest.mark.asyncio
    async def test_process_handles_non_dict_response(self, monkeypatch):
        _patch_dymo_key(monkeypatch, 'token')

        async def fake_post_fetch(url, headers=None, data='', params='', json=False, proxy=False):
            return '<html>error</html>'

        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, 'post_fetch', classmethod(lambda cls, *a, **kw: fake_post_fetch(*a, **kw)))

        search = dymosearch.SearchDymo('example.com')
        await search.process()
        assert await search.get_hostnames() == set()
        assert search.results == {}


class TestDymoIntegration:
    def test_module_exposes_class(self, monkeypatch):
        from theHarvester.discovery import dymosearch as mod

        assert hasattr(mod, 'SearchDymo')

    def test_source_catalog_lists_dymo(self):
        from theHarvester.lib.source_catalog import SOURCE_SPECS

        assert 'dymo' in SOURCE_SPECS
