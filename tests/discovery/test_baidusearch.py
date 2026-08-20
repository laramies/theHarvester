import asyncio
from dataclasses import dataclass

import pytest

from theHarvester.discovery import baidusearch


@dataclass(frozen=True)
class PageResponse:
    body: str
    status: int = 200
    final_url: str | None = None
    requires_prior_navigation: bool = False


class BrowserState:
    def __init__(
        self,
        responses: list[PageResponse | BaseException | None],
        close_errors: dict[str, BaseException] | None = None,
    ) -> None:
        self.responses = iter(responses)
        self.close_errors = close_errors or {}
        self.calls: list[dict] = []
        self.delays: list[float] = []
        self.launch_kwargs: dict = {}
        self.context_kwargs: dict = {}
        self.page_closed = False
        self.context_closed = False
        self.browser_closed = False
        self.manager_exited = False


class HttpState:
    def __init__(self, responses: list[baidusearch.FetcherResponse | None]) -> None:
        self.responses = iter(responses)
        self.calls: list[dict] = []
        self.open_kwargs: dict = {}
        self.delays: list[float] = []
        self.closed = False


class FakeNavigation:
    def __init__(self, status: int) -> None:
        self.status = status


class FakePage:
    def __init__(self, state: BrowserState) -> None:
        self.state = state
        self.url = ''
        self.body = ''
        self.navigated = False

    async def goto(self, url: str, **kwargs: object) -> FakeNavigation | None:
        self.state.calls.append({'url': url, **kwargs})
        response = next(self.state.responses)
        if isinstance(response, BaseException):
            raise response
        if response is None:
            return None
        if response.requires_prior_navigation and not self.navigated:
            raise AssertionError('later page lost browser state')
        self.navigated = True
        self.url = response.final_url or url
        self.body = response.body
        return FakeNavigation(response.status)

    async def content(self) -> str:
        return self.body

    async def close(self) -> None:
        self.state.page_closed = True
        if error := self.state.close_errors.get('page'):
            raise error


class FakeContext:
    def __init__(self, state: BrowserState) -> None:
        self.state = state

    async def new_page(self) -> FakePage:
        return FakePage(self.state)

    async def close(self) -> None:
        self.state.context_closed = True
        if error := self.state.close_errors.get('context'):
            raise error


class FakeBrowser:
    def __init__(self, state: BrowserState) -> None:
        self.state = state

    async def new_context(self, **kwargs: object) -> FakeContext:
        self.state.context_kwargs = kwargs
        return FakeContext(self.state)

    async def close(self) -> None:
        self.state.browser_closed = True
        if error := self.state.close_errors.get('browser'):
            raise error


class FakeChromium:
    def __init__(self, state: BrowserState) -> None:
        self.state = state

    async def launch(self, **kwargs: object) -> FakeBrowser:
        self.state.launch_kwargs = kwargs
        return FakeBrowser(self.state)


class FakePlaywright:
    def __init__(self, state: BrowserState) -> None:
        self.chromium = FakeChromium(state)


class FakePlaywrightError(Exception):
    pass


class FakePlaywrightApi:
    Error = FakePlaywrightError

    def __init__(self, state: BrowserState) -> None:
        self.state = state

    def async_playwright(self) -> FakeManager:
        return FakeManager(self.state)


class FakeManager:
    def __init__(self, state: BrowserState) -> None:
        self.state = state

    async def __aenter__(self) -> FakePlaywright:
        return FakePlaywright(self.state)

    async def __aexit__(self, *_args: object) -> None:
        self.state.manager_exited = True
        if error := self.state.close_errors.get('manager'):
            raise error


def patch_browser(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[PageResponse | BaseException | None],
    close_errors: dict[str, BaseException] | None = None,
) -> BrowserState:
    state = BrowserState(responses, close_errors)

    async def fake_sleep(delay: float) -> None:
        state.delays.append(delay)

    def fake_resolve_proxy(_cls: type, proxy: object) -> tuple[str | None, str | None]:
        return ('http://proxy.example:8080', 'http') if proxy else (None, None)

    monkeypatch.setattr(baidusearch, 'playwright_api', FakePlaywrightApi(state))
    monkeypatch.setattr(baidusearch.AsyncFetcher, '_resolve_proxy', classmethod(fake_resolve_proxy))
    monkeypatch.setattr(baidusearch.asyncio, 'sleep', fake_sleep)
    return state


def http_response(body: str, status: int = 200, location: str = '') -> baidusearch.FetcherResponse:
    return baidusearch.FetcherResponse(body=body, status=status, headers={'location': location} if location else {})


def patch_http(monkeypatch: pytest.MonkeyPatch, responses: list[baidusearch.FetcherResponse | None]) -> HttpState:
    state = HttpState(responses)

    class SessionManager:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *_args: object) -> None:
            state.closed = True

    def fake_open_session(*_args: object, **kwargs: object) -> SessionManager:
        state.open_kwargs = kwargs
        return SessionManager()

    async def fake_fetch(*_args: object, **kwargs: object) -> baidusearch.FetcherResponse | None:
        state.calls.append(kwargs)
        return next(state.responses)

    async def fake_sleep(delay: float) -> None:
        state.delays.append(delay)

    monkeypatch.setattr(baidusearch.AsyncFetcher, 'open_session', fake_open_session)
    monkeypatch.setattr(baidusearch.AsyncFetcher, 'fetch', fake_fetch)
    monkeypatch.setattr(baidusearch.Core, 'get_browser_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(baidusearch.asyncio, 'sleep', fake_sleep)
    return state


class TestBaiduSearch:
    @pytest.mark.asyncio
    async def test_process_queries_site_first_and_reuses_one_browser(self, monkeypatch: pytest.MonkeyPatch) -> None:
        state = patch_browser(
            monkeypatch,
            [
                PageResponse('Contact foo@example.com on a.example.com'),
                PageResponse('bar@sub.example.com is here and www.example.com appears', requires_prior_navigation=True),
                PageResponse('Visit sub.a.example.com. baz@example.com'),
            ],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=21)
        report = await search.process(proxy=True)

        assert report is None
        assert [call['url'] for call in state.calls] == [
            'https://www.baidu.com/s?ie=utf-8&f=8&tn=baidu&wd=site%3Aexample.com&rqlang=en&rsv_enter=1&rsv_dl=tb_enter',
            'https://www.baidu.com/s?ie=utf-8&f=8&tn=baidu&wd=site%3Aexample.com&rqlang=en&rsv_enter=1&rsv_dl=tb_enter&pn=10',
            'https://www.baidu.com/s?ie=utf-8&f=8&tn=baidu&wd=site%3Aexample.com&rqlang=en&rsv_enter=1&rsv_dl=tb_enter&pn=20',
        ]
        assert all(call['wait_until'] == 'domcontentloaded' for call in state.calls)
        assert all(call['timeout'] == 60_000 for call in state.calls)
        assert state.launch_kwargs == {'headless': True, 'proxy': {'server': 'http://proxy.example:8080'}}
        assert state.context_kwargs == {}
        assert state.delays == [1.0, 1.0]
        assert state.page_closed
        assert state.context_closed
        assert state.browser_closed
        assert state.manager_exited
        assert {'foo@example.com', 'bar@sub.example.com', 'baz@example.com'} <= await search.get_emails()
        assert {'a.example.com', 'www.example.com', 'sub.a.example.com'} <= set(await search.get_hostnames())

    @pytest.mark.asyncio
    async def test_captcha_redirect_stops_before_requesting_more_pages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        state = patch_browser(
            monkeypatch,
            [
                PageResponse('', final_url='https://wappass.baidu.com/static/captcha/tuxing_v2.html'),
                PageResponse('must not be requested'),
            ],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=20)

        report = await search.process()

        assert len(state.calls) == 1
        assert 'wd=site%3Aexample.com' in state.calls[0]['url']
        assert state.delays == []
        assert report.status == 'failed'
        assert report.stop_reason == 'security-verification'
        assert state.page_closed
        assert state.context_closed
        assert state.browser_closed
        assert state.manager_exited

    @pytest.mark.asyncio
    async def test_later_captcha_preserves_partial_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        state = patch_browser(
            monkeypatch,
            [
                PageResponse('api.example.com'),
                PageResponse('<html>百度安全验证</html>'),
                PageResponse('must not be requested'),
            ],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=30)

        report = await search.process()

        assert len(state.calls) == 2
        assert await search.get_hostnames() == ['api.example.com']
        assert report.status == 'failed'
        assert report.stop_reason == 'security-verification'

    @pytest.mark.asyncio
    async def test_browser_transport_failure_falls_back_to_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        state = patch_browser(monkeypatch, [FakePlaywrightError('failure')])
        http = patch_http(monkeypatch, [http_response('fallback.example.com')])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        report = await search.process()

        assert report is None
        assert await search.get_hostnames() == ['fallback.example.com']
        assert state.page_closed
        assert state.context_closed
        assert state.browser_closed
        assert state.manager_exited
        assert len(http.calls) == 1
        assert http.closed

    @pytest.mark.asyncio
    async def test_winloop_playwright_startup_failure_falls_back_to_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fail_manager_startup(_manager: FakeManager) -> FakePlaywright:
            raise ValueError('startupinfo is not supported')

        monkeypatch.setattr(FakeManager, '__aenter__', fail_manager_startup)
        patch_browser(monkeypatch, [])
        http = patch_http(monkeypatch, [http_response('fallback.example.com')])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        report = await search.process()

        assert report is None
        assert await search.get_hostnames() == ['fallback.example.com']
        assert len(http.calls) == 1
        assert http.closed

    @pytest.mark.asyncio
    async def test_missing_playwright_falls_back_to_direct_http_site_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(baidusearch, 'playwright_api', None)
        http = patch_http(
            monkeypatch,
            [http_response('one.example.com'), http_response('two.example.com')],
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=20)

        report = await search.process(proxy=True)

        assert report is None
        assert [call['url'] for call in http.calls] == [
            'https://www.baidu.com/s?ie=utf-8&f=8&tn=baidu&wd=site%3Aexample.com&rqlang=en&rsv_enter=1&rsv_dl=tb_enter',
            'https://www.baidu.com/s?ie=utf-8&f=8&tn=baidu&wd=site%3Aexample.com&rqlang=en&rsv_enter=1&rsv_dl=tb_enter&pn=10',
        ]
        assert all(call['follow_redirects'] is False for call in http.calls)
        assert http.open_kwargs == {
            'headers': {'Host': 'www.baidu.com', 'User-Agent': 'UA'},
            'proxy': True,
            'request_timeout': 60,
        }
        assert http.delays == [1.0]
        assert http.closed

    @pytest.mark.asyncio
    async def test_cancellation_survives_cleanup_failures(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cancellation = asyncio.CancelledError('operator-stop')
        state = patch_browser(
            monkeypatch,
            [cancellation],
            {
                'page': RuntimeError('page close failed'),
                'context': RuntimeError('context close failed'),
                'browser': RuntimeError('browser close failed'),
                'manager': RuntimeError('manager close failed'),
            },
        )
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        with pytest.raises(asyncio.CancelledError, match='operator-stop') as raised:
            await search.process()

        assert raised.value is cancellation
        assert state.page_closed
        assert state.context_closed
        assert state.browser_closed
        assert state.manager_exited

    @pytest.mark.asyncio
    async def test_empty_response_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_browser(monkeypatch, [PageResponse('')])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        report = await search.process()

        assert report.status == 'failed'
        assert report.stop_reason == 'no-response'

    @pytest.mark.asyncio
    async def test_http_429_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_browser(monkeypatch, [PageResponse('', status=429)])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        report = await search.process()

        assert report.status == 'rate-limited'
        assert report.stop_reason == 'http-429'

    @pytest.mark.asyncio
    async def test_missing_navigation_response_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_browser(monkeypatch, [None])
        patch_http(monkeypatch, [None])
        search = baidusearch.SearchBaidu(word='example.com', limit=10)

        report = await search.process()

        assert report.status == 'failed'
        assert report.stop_reason == 'transport-error'


pytestmark = pytest.mark.provider_contract('baidu')
