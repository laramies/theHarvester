import pytest
from theHarvester.discovery import mojeek

class TestMojeekSearch:

    @pytest.mark.asyncio
    async def test_process_and_parsing(self, monkeypatch):
        called = {}

        async def fake_fetch_all(urls, headers=None, proxy=False):
            called["urls"] = urls
            called["headers"] = headers
            called["proxy"] = proxy
            return [
                "Contact admin@exemple.com sur www.exemple.com \n",
                " dev@exemple.com est présent sur api.exemple.com \n"
            ]

        import theHarvester.lib.core as core_module
        monkeypatch.setattr(core_module.AsyncFetcher, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(core_module.Core, "get_user_agent", staticmethod(lambda: "UA"), raising=True)

        search = mojeek.SearchMojeek(word="exemple.com", limit=20)
        await search.process(proxy=True)

        expected_urls = [
            "https://www.mojeek.com/search?q=%40exemple.com&s=0",
            "https://www.mojeek.com/search?q=%40exemple.com&s=10"
        ]
        
        assert any("mojeek.com" in url for url in called["urls"])
        
        emails = await search.get_emails()
        hosts = await search.get_hostnames()

        assert "admin@exemple.com" in emails
        assert "dev@exemple.com" in emails
        assert "www.exemple.com" in hosts
        assert "api.exemple.com" in hosts

    @pytest.mark.asyncio
    async def test_pagination_limit(self, monkeypatch):
        captured = {}

        async def fake_fetch_all(urls, headers=None, proxy=False):
            captured["urls"] = urls
            return [""] * len(urls)

        import theHarvester.lib.core as core_module
        monkeypatch.setattr(core_module.AsyncFetcher, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(core_module.Core, "get_user_agent", staticmethod(lambda: "UA"), raising=True)

        search = mojeek.SearchMojeek(word="exemple.com", limit=10)
        await search.process()
        
        assert len(captured["urls"]) == 1
