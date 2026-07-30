import pytest

from theHarvester.discovery import baidusearch


class TestBaiduSearch:
    @pytest.mark.asyncio
    async def test_empty_fetch_response_is_reported(self, monkeypatch):
        async def fake_fetch_all(urls, headers=None, proxy=False):
            return ['']

        monkeypatch.setattr(baidusearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        with pytest.raises(RuntimeError, match='empty response'):
            await search.process()

    @pytest.mark.asyncio
    async def test_partial_empty_fetch_response_is_ignored(self, monkeypatch):
        async def fake_fetch_all(urls, headers=None, proxy=False):
            return ['', 'a.example.com']

        monkeypatch.setattr(baidusearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = baidusearch.SearchBaidu(word='example.com', limit=20)

        await search.process()

        assert await search.get_hostnames() == ['a.example.com']

    @pytest.mark.asyncio
    async def test_security_verification_is_reported(self, monkeypatch):
        async def fake_fetch_all(urls, headers=None, proxy=False):
            return ['<html><title>百度安全验证</title></html>']

        monkeypatch.setattr(baidusearch.AsyncFetcher, 'fetch_all', fake_fetch_all)
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        with pytest.raises(RuntimeError, match='security verification'):
            await search.process()

    @pytest.mark.asyncio
    async def test_process_and_parsing(self, monkeypatch):
        called = {}

        async def fake_fetch_all(urls, headers=None, proxy=False):
            called["urls"] = urls
            called["headers"] = headers
            called["proxy"] = proxy
            return [
                "Contact foo@example.com on a.example.com \n",
                " bar@sub.example.com is here and www.example.com appears \n",
                " Visit sub.a.example.com. baz@example.com \n",
            ]

        # Patch the AsyncFetcher.fetch_all to avoid network I/O
        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, "fetch_all", fake_fetch_all)
        # Make user agent deterministic (not strictly necessary, but stable)
        monkeypatch.setattr(core_module.Core, "get_user_agent", staticmethod(lambda: "UA"), raising=True)

        search = baidusearch.SearchBaidu(word="example.com", limit=21)
        await search.process(proxy=True)

        expected_urls = [
            "https://www.baidu.com/s?wd=site%3Aexample.com&pn=0",
            "https://www.baidu.com/s?wd=site%3Aexample.com&pn=10",
            "https://www.baidu.com/s?wd=site%3Aexample.com&pn=20",
        ]
        assert called["urls"] == expected_urls
        assert called["proxy"] is True

        emails = await search.get_emails()
        hosts = await search.get_hostnames()

        # Ensure our expected values are present
        assert "foo@example.com" in emails
        assert "bar@sub.example.com" in emails
        assert "baz@example.com" in emails

        assert {"a.example.com", "www.example.com", "sub.a.example.com"} <= set(hosts)

    @pytest.mark.asyncio
    async def test_pagination_limit_exclusive(self, monkeypatch):
        captured = {}

        async def fake_fetch_all(urls, headers=None, proxy=False):
            captured["urls"] = urls
            return ["<html></html>"] * len(urls)

        import theHarvester.lib.core as core_module

        monkeypatch.setattr(core_module.AsyncFetcher, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(core_module.Core, "get_user_agent", staticmethod(lambda: "UA"), raising=True)

        search = baidusearch.SearchBaidu(word="example.com", limit=20)
        await search.process()

        # For limit=20, range(0, 20, 10) yields 0 and 10 only (20 is excluded)
        assert captured["urls"] == [
            "https://www.baidu.com/s?wd=site%3Aexample.com&pn=0",
            "https://www.baidu.com/s?wd=site%3Aexample.com&pn=10",
        ]
