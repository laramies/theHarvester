from __future__ import annotations

import asyncio
import stat
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import TYPE_CHECKING, Self
from unittest.mock import AsyncMock, MagicMock

import pytest

import theHarvester.screenshot.screenshot as screenshot_module
from theHarvester.screenshot.screenshot import ScreenShotter

if TYPE_CHECKING:
    from types import TracebackType


class _EmptyResponse(AbstractAsyncContextManager):
    def __init__(self, url: str, active_requests: list[int]) -> None:
        self.url = url
        self.status = 204
        self._active_requests = active_requests

    async def __aenter__(self) -> Self:
        self._active_requests[0] += 1
        self._active_requests[1] = max(self._active_requests)
        await asyncio.sleep(0)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._active_requests[0] -= 1


@pytest.mark.asyncio
async def test_reachable_targets_reuses_one_session_and_bounds_empty_responses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    active_requests = [0, 0]
    session = MagicMock()
    session.get.side_effect = lambda url, **_kwargs: _EmptyResponse(url, active_requests)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session_factory = MagicMock(return_value=session)
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', session_factory)
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', MagicMock())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', MagicMock())
    targets = [f'host-{index}.example.test' for index in range(25)]

    reachable = await ScreenShotter(str(tmp_path)).reachable_targets(targets)

    assert reachable == [(target, f'https://{target}') for target in targets]
    assert session_factory.call_count == 1
    assert session.get.call_count == 25
    assert active_requests == [0, 20]


@pytest.mark.asyncio
async def test_reachable_targets_cancellation_closes_session_and_leaves_no_tasks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = asyncio.Event()
    active_requests = 0

    class PendingResponse(AbstractAsyncContextManager):
        async def __aenter__(self) -> Self:
            nonlocal active_requests
            active_requests += 1
            try:
                if active_requests == 20:
                    started.set()
                await asyncio.Event().wait()
                raise AssertionError('unreachable')
            finally:
                active_requests -= 1

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            return None

    session = MagicMock()
    session.get.return_value = PendingResponse()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', MagicMock(return_value=session))
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', MagicMock())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', MagicMock())
    targets = [f'host-{index}.example.test' for index in range(25)]

    operation = asyncio.create_task(ScreenShotter(str(tmp_path)).reachable_targets(targets))
    await asyncio.wait_for(started.wait(), timeout=1)
    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation

    session.__aexit__.assert_awaited_once()
    assert active_requests == 0
    assert not [task for task in asyncio.all_tasks() if task.get_name().startswith('screenshot-reachability-')]


@pytest.mark.asyncio
async def test_capture_targets_reuses_one_browser_and_bounds_isolated_contexts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context_counts = [0, 0]
    page_close_count = 0
    context_close_count = 0
    browser_close_count = 0
    manager_exit_count = 0

    class Page:
        async def goto(self, _url: str, **kwargs: int) -> None:
            assert kwargs == {'timeout': 35000}
            await asyncio.sleep(0)

        async def screenshot(self, *, path: Path) -> None:
            assert path.parent == tmp_path

        async def close(self) -> None:
            nonlocal page_close_count
            page_close_count += 1

    class Context:
        async def new_page(self) -> Page:
            return Page()

        async def close(self) -> None:
            nonlocal context_close_count
            context_close_count += 1
            context_counts[0] -= 1

    class Browser:
        async def new_context(self) -> Context:
            context_counts[0] += 1
            context_counts[1] = max(context_counts)
            return Context()

        async def close(self) -> None:
            nonlocal browser_close_count
            browser_close_count += 1

    class Chromium:
        def __init__(self) -> None:
            self.launch_count = 0

        async def launch(self, *, headless: bool) -> Browser:
            assert headless is True
            self.launch_count += 1
            return Browser()

    class Playwright:
        def __init__(self) -> None:
            self.chromium = Chromium()

    playwright = Playwright()

    class Manager:
        async def __aenter__(self) -> Playwright:
            return playwright

        async def __aexit__(self, *_args: object) -> None:
            nonlocal manager_exit_count
            manager_exit_count += 1

    monkeypatch.setattr(screenshot_module, 'async_playwright', lambda: Manager())
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())
    captured: list[tuple[str, str, Path]] = []

    async def record(subject: str, captured_url: str, path: Path) -> None:
        captured.append((subject, captured_url, path))

    targets = [(f'host-{index}.example.test', f'https://host-{index}.example.test') for index in range(8)]
    await ScreenShotter(str(tmp_path)).capture_targets(targets, record)

    assert [item[:2] for item in captured] == targets
    assert playwright.chromium.launch_count == 1
    assert context_counts == [0, 3]
    assert page_close_count == 8
    assert context_close_count == 8
    assert browser_close_count == 1
    assert manager_exit_count == 1


@pytest.mark.parametrize(
    'failure_stage',
    [
        'launch',
        'new-context',
        'new-page',
        'goto',
        'goto-timeout',
        'screenshot',
        'record',
        'page-close',
        'context-close',
        'browser-close',
    ],
)
@pytest.mark.asyncio
async def test_capture_targets_closes_resources_after_each_failure_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_stage: str,
) -> None:
    page = MagicMock()
    goto_error: Exception | None = None
    if failure_stage == 'goto':
        goto_error = RuntimeError('goto failed')
    elif failure_stage == 'goto-timeout':
        goto_error = TimeoutError('goto timed out')
    page.goto = AsyncMock(side_effect=goto_error)
    page.screenshot = AsyncMock(side_effect=RuntimeError('screenshot failed') if failure_stage == 'screenshot' else None)
    page.close = AsyncMock(side_effect=RuntimeError('page close failed') if failure_stage == 'page-close' else None)
    context = MagicMock()
    context.new_page = AsyncMock(
        side_effect=RuntimeError('new page failed') if failure_stage == 'new-page' else None,
        return_value=page,
    )
    context.close = AsyncMock(side_effect=RuntimeError('context close failed') if failure_stage == 'context-close' else None)
    browser = MagicMock()
    browser.new_context = AsyncMock(
        side_effect=RuntimeError('new context failed') if failure_stage == 'new-context' else None,
        return_value=context,
    )
    browser.close = AsyncMock(side_effect=RuntimeError('browser close failed') if failure_stage == 'browser-close' else None)
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(
        side_effect=RuntimeError('launch failed') if failure_stage == 'launch' else None,
        return_value=browser,
    )
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(screenshot_module, 'async_playwright', MagicMock(return_value=manager))
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())

    async def record(_subject: str, _captured_url: str, _path: Path) -> None:
        if failure_stage == 'record':
            raise RuntimeError('record failed')

    operation = ScreenShotter(str(tmp_path)).capture_targets([('example.test', 'https://example.test')], record)
    if failure_stage in {'launch', 'record', 'page-close', 'context-close', 'browser-close'}:
        with pytest.raises(RuntimeError):
            await operation
    else:
        await operation

    manager.__aexit__.assert_awaited_once()
    if failure_stage == 'launch':
        browser.close.assert_not_awaited()
        return
    browser.close.assert_awaited_once()
    if failure_stage == 'new-context':
        context.close.assert_not_awaited()
        page.close.assert_not_awaited()
    elif failure_stage == 'new-page':
        context.close.assert_awaited_once()
        page.close.assert_not_awaited()
    else:
        context.close.assert_awaited_once()
        page.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_capture_targets_cancellation_closes_resources_and_leaves_no_tasks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = asyncio.Event()
    pages: list[MagicMock] = []
    contexts: list[MagicMock] = []

    async def wait_for_cancellation(*_args: object, **_kwargs: object) -> None:
        if len(pages) == 3:
            started.set()
        await asyncio.Event().wait()

    async def new_context() -> MagicMock:
        page = MagicMock()
        page.goto = AsyncMock(side_effect=wait_for_cancellation)
        page.screenshot = AsyncMock()
        page.close = AsyncMock()
        pages.append(page)
        context = MagicMock()
        context.new_page = AsyncMock(return_value=page)
        context.close = AsyncMock()
        contexts.append(context)
        return context

    browser = MagicMock()
    browser.new_context = AsyncMock(side_effect=new_context)
    browser.close = AsyncMock()
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(screenshot_module, 'async_playwright', MagicMock(return_value=manager))

    async def record(_subject: str, _captured_url: str, _path: Path) -> None:
        raise AssertionError('cancelled captures must not be recorded')

    targets = [(f'host-{index}.example.test', f'https://host-{index}.example.test') for index in range(5)]
    operation = asyncio.create_task(ScreenShotter(str(tmp_path)).capture_targets(targets, record))
    await asyncio.wait_for(started.wait(), timeout=1)
    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation

    assert len(pages) == len(contexts) == 3
    assert all(page.close.await_count == 1 for page in pages)
    assert all(context.close.await_count == 1 for context in contexts)
    browser.close.assert_awaited_once()
    manager.__aexit__.assert_awaited_once()
    assert not [task for task in asyncio.all_tasks() if task.get_name().startswith('screenshot-capture-')]


@pytest.mark.asyncio
async def test_capture_cleanup_preserves_cancellation_and_attempts_every_resource(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cancellation = asyncio.CancelledError('page-close-cancelled')
    page = MagicMock()
    page.goto = AsyncMock()
    page.screenshot = AsyncMock()
    page.close = AsyncMock(side_effect=cancellation)
    context = MagicMock()
    context.new_page = AsyncMock(return_value=page)
    context.close = AsyncMock(side_effect=BaseException('context-close-failed'))
    browser = MagicMock()
    browser.new_context = AsyncMock(return_value=context)
    browser.close = AsyncMock(side_effect=BaseException('browser-close-failed'))
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(side_effect=BaseException('playwright-close-failed'))
    monkeypatch.setattr(screenshot_module, 'async_playwright', MagicMock(return_value=manager))
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())

    async def record(_subject: str, _captured_url: str, _path: Path) -> None:
        raise AssertionError('cleanup cancellation must prevent recording')

    with pytest.raises(asyncio.CancelledError, match='page-close-cancelled') as error:
        await ScreenShotter(str(tmp_path)).capture_targets([('example.test', 'https://example.test')], record)

    assert error.value is cancellation
    page.close.assert_awaited_once()
    context.close.assert_awaited_once()
    browser.close.assert_awaited_once()
    manager.__aexit__.assert_awaited_once()
    assert not [task for task in asyncio.all_tasks() if task.get_name().startswith('screenshot-')]


@pytest.mark.parametrize(
    ('platform', 'expected_separator'),
    [('darwin', '/'), ('linux', '/'), ('win32', '\\')],
)
def test_screenshot_output_separator_matches_platform(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    expected_separator: str,
) -> None:
    monkeypatch.setattr(screenshot_module.sys, 'platform', platform)

    assert ScreenShotter('screenshots').slash == expected_separator


@pytest.mark.parametrize(
    ('target', 'filename'),
    [
        ('https://www.example.com:8443/login?next=/admin', 'www.example.com_8443.png'),
        ('2001:db8::1', '2001_db8__1.png'),
    ],
)
def test_screenshot_path_uses_the_target_host_and_port(tmp_path: Path, target: str, filename: str) -> None:
    screenshotter = ScreenShotter(str(tmp_path))

    assert screenshotter.screenshot_path(target) == tmp_path / filename


@pytest.mark.parametrize(
    ('target', 'response_url', 'request_url'),
    [
        ('www.example.com', 'https://www.example.com/landing', 'https://www.example.com'),
        ('2001:db8::1', 'https://[2001:db8::1]/', 'https://[2001:db8::1]'),
    ],
)
@pytest.mark.asyncio
async def test_visit_prefers_https_and_normalizes_the_target(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    response_url: str,
    request_url: str,
) -> None:
    response = MagicMock()
    response.url = response_url
    response.status = 200
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    response.text = AsyncMock(return_value='reachable')
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.get.return_value = response
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', MagicMock(return_value=session))
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', MagicMock())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', MagicMock())
    result = await ScreenShotter.visit(target)

    assert result == (response_url, 'reachable')
    assert session.get.call_args.args[0] == request_url


@pytest.mark.asyncio
async def test_visit_falls_back_to_http_when_https_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    response = MagicMock()
    response.url = 'http://www.example.com'
    response.status = 200
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    response.text = AsyncMock(return_value='reachable')
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.get.side_effect = [screenshot_module.aiohttp.ClientError('TLS unavailable'), response]
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', MagicMock(return_value=session))
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', MagicMock())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', MagicMock())
    result = await ScreenShotter.visit('www.example.com')

    assert result == ('http://www.example.com', 'reachable')
    assert [call.args[0] for call in session.get.call_args_list] == [
        'https://www.example.com',
        'http://www.example.com',
    ]


@pytest.mark.parametrize(
    ('target', 'normalized_url', 'filename'),
    [
        ('www.example.com', 'https://www.example.com', 'www.example.com.png'),
        ('2001:db8::1', 'https://[2001:db8::1]', '2001_db8__1.png'),
    ],
)
@pytest.mark.asyncio
async def test_take_screenshot_normalizes_the_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
    normalized_url: str,
    filename: str,
) -> None:
    page = AsyncMock()
    context = AsyncMock()
    context.new_page.return_value = page
    browser = AsyncMock()
    browser.new_context.return_value = context
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(screenshot_module, 'async_playwright', MagicMock(return_value=manager))
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())

    captured_url = await ScreenShotter(str(tmp_path)).take_screenshot(target)

    assert captured_url == normalized_url
    page.goto.assert_awaited_once_with(normalized_url, timeout=35000)
    screenshot_path = page.screenshot.await_args.kwargs['path']
    assert Path(screenshot_path) == tmp_path / filename


@pytest.mark.asyncio
async def test_take_screenshot_can_name_the_artifact_for_the_authorized_subject(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    page = AsyncMock()
    context = AsyncMock()
    context.new_page.return_value = page
    browser = AsyncMock()
    browser.new_context.return_value = context
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(screenshot_module, 'async_playwright', MagicMock(return_value=manager))
    monkeypatch.setattr(screenshot_module.os, 'chmod', MagicMock())
    output_path = tmp_path / 'authorized.example.com.png'

    captured_url = await ScreenShotter(str(tmp_path)).take_screenshot(
        'https://login.example.net/session',
        output_path=output_path,
    )

    assert captured_url == 'https://login.example.net/session'
    assert page.screenshot.await_args.kwargs['path'] == output_path


@pytest.mark.asyncio
async def test_screenshot_visit_uses_an_http_proxy(monkeypatch) -> None:
    response = MagicMock()
    response.url = 'https://example.com'
    response.status = 200
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    response.text = AsyncMock(return_value='reachable')
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.get.return_value = response
    monkeypatch.setattr(screenshot_module.aiohttp, 'ClientSession', MagicMock(return_value=session))
    monkeypatch.setattr(screenshot_module.aiohttp, 'TCPConnector', MagicMock())
    monkeypatch.setattr(screenshot_module.ssl, 'create_default_context', MagicMock())

    result = await ScreenShotter.visit('example.com', proxy='http://proxy.example:8080')

    assert result == ('https://example.com', 'reachable')
    assert session.get.call_args.kwargs == {'proxy': 'http://proxy.example:8080'}


@pytest.mark.asyncio
async def test_screenshot_capture_is_owner_only(tmp_path, monkeypatch) -> None:
    class Page:
        async def goto(self, *_args, **_kwargs):
            return None

        async def screenshot(self, *, path):
            Path(path).write_bytes(b'png')  # noqa: ASYNC240 - tiny in-memory browser fixture

        async def close(self):
            return None

    class Context:
        async def new_page(self):
            return Page()

        async def close(self):
            return None

    class Browser:
        async def new_context(self):
            return Context()

        async def close(self):
            return None

    class Playwright:
        chromium = None

        def __init__(self):
            self.chromium = self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def launch(self, **_kwargs):
            return Browser()

    monkeypatch.setattr(screenshot_module, 'async_playwright', Playwright)

    await ScreenShotter(str(tmp_path)).take_screenshot('example.com')

    assert stat.S_IMODE((tmp_path / 'example.com.png').stat().st_mode) == 0o600
