import pytest

from theHarvester.discovery import baidusearch


class FakeSession:
    def __init__(self) -> None:
        self.closed = False
        self.delays: list[float] = []

    async def close(self) -> None:
        self.closed = True


def response(body: str, status: int = 200, location: str = '') -> baidusearch.FetcherResponse:
    headers = {'location': location} if location else {}
    return baidusearch.FetcherResponse(body=body, status=status, headers=headers)


def patch_requests(monkeypatch: pytest.MonkeyPatch, responses: list[object]) -> tuple[FakeSession, list[dict]]:
    session = FakeSession()
    calls: list[dict] = []
    queued_responses = iter(responses)

    async def fake_build_session(*_args: object, **_kwargs: object) -> FakeSession:
        return session

    async def fake_fetch(**kwargs: object) -> object:
        calls.append(kwargs)
        return next(queued_responses)

    async def fake_sleep(delay: float) -> None:
        session.delays.append(delay)

    def fake_resolve_proxy(_cls: type, proxy: object) -> tuple[str | None, str | None]:
        return ('http://proxy.example:8080', 'http') if proxy else (None, None)

    monkeypatch.setattr(baidusearch.AsyncFetcher, '_build_session', fake_build_session)
    monkeypatch.setattr(baidusearch.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(baidusearch.AsyncFetcher, '_resolve_proxy', classmethod(fake_resolve_proxy))
    monkeypatch.setattr(baidusearch.asyncio, 'sleep', fake_sleep)
    return session, calls


class TestBaiduSearch:
    @pytest.mark.asyncio
    async def test_process_reuses_one_session_for_sequential_pages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        session, calls = patch_requests(
            monkeypatch,
            [
                response('<html>homepage</html>'),
                response('Contact foo@example.com on a.example.com'),
                response('bar@sub.example.com is here and www.example.com appears'),
                response('Visit sub.a.example.com. baz@example.com'),
            ],
        )
        monkeypatch.setattr(baidusearch.Core, 'get_browser_user_agent', staticmethod(lambda: 'UA'))

        search = baidusearch.SearchBaidu(word='example.com', limit=21)
        await search.process(proxy=True)

        assert [call['url'] for call in calls] == [
            'https://www.baidu.com/',
            'https://www.baidu.com/s?wd=site%3Aexample.com&pn=0',
            'https://www.baidu.com/s?wd=site%3Aexample.com&pn=10',
            'https://www.baidu.com/s?wd=site%3Aexample.com&pn=20',
        ]
        assert all(call['session'] is session for call in calls)
        assert [call['follow_redirects'] for call in calls] == [False, False, False, False]
        assert all(call['proxy'] == 'http://proxy.example:8080' for call in calls)
        assert session.delays == [1.0, 1.0, 1.0]
        assert session.closed is True
        assert {'foo@example.com', 'bar@sub.example.com', 'baz@example.com'} <= await search.get_emails()
        assert {'a.example.com', 'www.example.com', 'sub.a.example.com'} <= set(await search.get_hostnames())

    @pytest.mark.asyncio
    async def test_captcha_redirect_stops_before_following_or_requesting_more_pages(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session, calls = patch_requests(
            monkeypatch,
            [
                response('<html>homepage</html>'),
                response('', status=302, location='https://wappass.baidu.com/static/captcha/tuxing_v2.html'),
                response('must not be requested'),
            ],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=20)

        await search.process()

        assert len(calls) == 2
        assert calls[-1]['follow_redirects'] is False
        assert session.delays == [1.0]
        assert search.execution_status == 'failed'
        assert search.stop_reason == 'security-verification'
        assert session.closed is True

    @pytest.mark.asyncio
    async def test_homepage_captcha_redirect_stops_before_search(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _session, calls = patch_requests(
            monkeypatch,
            [response('', status=302, location='https://wappass.baidu.com/static/captcha/tuxing_v2.html')],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        await search.process()

        assert len(calls) == 1
        assert calls[0]['follow_redirects'] is False
        assert search.execution_status == 'failed'
        assert search.stop_reason == 'security-verification'

    @pytest.mark.asyncio
    async def test_later_captcha_preserves_partial_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _session, calls = patch_requests(
            monkeypatch,
            [
                response('<html>homepage</html>'),
                response('api.example.com'),
                response('<html>百度安全验证</html>'),
                response('must not be requested'),
            ],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=30)

        await search.process()

        assert len(calls) == 3
        assert await search.get_hostnames() == ['api.example.com']
        assert search.execution_status == 'partial'
        assert search.stop_reason == 'security-verification'

    @pytest.mark.asyncio
    async def test_transport_failure_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_requests(monkeypatch, [response('<html>homepage</html>'), None])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        await search.process()

        assert search.execution_status == 'failed'
        assert search.stop_reason == 'transport-error'

    @pytest.mark.asyncio
    async def test_empty_response_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_requests(monkeypatch, [response('<html>homepage</html>'), response('')])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        await search.process()

        assert search.execution_status == 'failed'
        assert search.stop_reason == 'no-response'

    @pytest.mark.asyncio
    async def test_http_429_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_requests(monkeypatch, [response('<html>homepage</html>'), response('', status=429)])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        await search.process()

        assert search.execution_status == 'rate-limited'
        assert search.stop_reason == 'http-429'

    @pytest.mark.asyncio
    async def test_pagination_limit_is_exclusive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _session, calls = patch_requests(
            monkeypatch,
            [response('<html>homepage</html>'), response('<html></html>'), response('<html></html>')],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=20)

        await search.process()

        assert [call['url'] for call in calls[1:]] == [
            'https://www.baidu.com/s?wd=site%3Aexample.com&pn=0',
            'https://www.baidu.com/s?wd=site%3Aexample.com&pn=10',
        ]
