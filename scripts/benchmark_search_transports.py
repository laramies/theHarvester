#!/usr/bin/env python3
"""Compare one direct search request through aiohttp and Playwright."""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from urllib.parse import urlencode, urlsplit

import aiohttp
import certifi
from playwright.async_api import Browser, BrowserContext, Page, Response, async_playwright

from theHarvester.lib.core import Core

CHALLENGE_MARKERS = (
    '百度安全验证',
    'wappass.baidu.com/static/captcha',
    'captcha',
    'verify you are human',
    'prove you are human',
    'access denied',
    'temporarily blocked',
)
RESULT_MARKERS = {
    'baidu': ('content_left', 'c-container'),
    'yahoo': ('searchcentermiddle', 'class="algo'),
    'mojeek': ('results-standard',),
}


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    provider: str
    transport: str
    outcome: str
    status: int | None
    elapsed_ms: float
    final_host: str | None
    redirects: int
    body_bytes: int
    error_type: str | None = None


def search_url(provider: str, target: str) -> str:
    query = f'site:{target}'
    if provider == 'baidu':
        return f'https://www.baidu.com/s?{urlencode({"ie": "utf-8", "f": 8, "tn": "baidu", "wd": query, "rqlang": "en", "rsv_enter": 1, "rsv_dl": "tb_enter"})}'
    if provider == 'yahoo':
        return f'https://search.yahoo.com/search?{urlencode({"p": query, "b": 1, "pz": 10})}'
    if provider == 'mojeek':
        return f'https://www.mojeek.com/search?{urlencode({"q": query, "s": 0})}'
    raise ValueError(f'unsupported provider: {provider}')


def classify(provider: str, status: int | None, final_url: str, body: str) -> str:
    normalized = f'{final_url} {body}'.casefold()
    if any(marker in normalized for marker in CHALLENGE_MARKERS):
        return 'challenge'
    if status is None or status >= 400:
        return 'http-error'
    if not body.strip():
        return 'empty'
    if any(marker in normalized for marker in RESULT_MARKERS[provider]):
        return 'results-page'
    return 'unrecognized-page'


def positive_seconds(value: str) -> float:
    seconds = float(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError('timeout must be positive')
    return seconds


async def benchmark_aiohttp(session: aiohttp.ClientSession, provider: str, url: str) -> BenchmarkResult:
    started = time.perf_counter()
    try:
        async with session.get(url, allow_redirects=True) as response:
            body = await response.text(errors='replace')
            final_url = str(response.url)
            return BenchmarkResult(
                provider,
                'aiohttp',
                classify(provider, response.status, final_url, body),
                response.status,
                (time.perf_counter() - started) * 1000,
                urlsplit(final_url).hostname,
                len(response.history),
                len(body.encode()),
            )
    except Exception as error:
        return BenchmarkResult(
            provider,
            'aiohttp',
            'transport-error',
            None,
            (time.perf_counter() - started) * 1000,
            None,
            0,
            0,
            type(error).__name__,
        )


def redirect_count(response: Response | None) -> int:
    redirects = 0
    request = response.request if response is not None else None
    while request is not None and request.redirected_from is not None:
        redirects += 1
        request = request.redirected_from
    return redirects


async def benchmark_playwright(page: Page, provider: str, url: str, timeout_ms: float) -> BenchmarkResult:
    started = time.perf_counter()
    try:
        response = await page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)
        body = await page.content()
        final_url = page.url
        status = response.status if response is not None else None
        return BenchmarkResult(
            provider,
            'playwright',
            classify(provider, status, final_url, body),
            status,
            (time.perf_counter() - started) * 1000,
            urlsplit(final_url).hostname,
            redirect_count(response),
            len(body.encode()),
        )
    except Exception as error:
        return BenchmarkResult(
            provider,
            'playwright',
            'transport-error',
            None,
            (time.perf_counter() - started) * 1000,
            urlsplit(page.url).hostname,
            0,
            0,
            type(error).__name__,
        )


async def benchmark_baidu_ui(page: Page, target: str, timeout_ms: float) -> BenchmarkResult:
    started = time.perf_counter()
    phase = 'homepage'
    try:
        response = await page.goto('https://www.baidu.com/', wait_until='commit', timeout=timeout_ms)
        search_box = page.locator('#kw')
        await search_box.wait_for(state='visible', timeout=min(timeout_ms, 10_000))
        homepage = await page.content()
        status = response.status if response is not None else None
        if classify('baidu', status, page.url, homepage) == 'challenge':
            return BenchmarkResult(
                'baidu',
                'playwright-ui-headed',
                'challenge',
                status,
                (time.perf_counter() - started) * 1000,
                urlsplit(page.url).hostname,
                redirect_count(response),
                len(homepage.encode()),
            )

        phase = 'search-box'
        await search_box.click(timeout=5_000)
        await search_box.fill(f'site:{target}', timeout=5_000)
        phase = 'submit'
        async with page.expect_navigation(wait_until='commit', timeout=timeout_ms) as navigation:
            await search_box.press('Enter', timeout=5_000)
        response = await navigation.value
        await page.wait_for_timeout(1_000)
        body = await page.content()
        status = response.status if response is not None else None
        return BenchmarkResult(
            'baidu',
            'playwright-ui-headed',
            classify('baidu', status, page.url, body),
            status,
            (time.perf_counter() - started) * 1000,
            urlsplit(page.url).hostname,
            redirect_count(response),
            len(body.encode()),
        )
    except Exception as error:
        return BenchmarkResult(
            'baidu',
            'playwright-ui-headed',
            'transport-error',
            None,
            (time.perf_counter() - started) * 1000,
            urlsplit(page.url).hostname,
            0,
            0,
            f'{type(error).__name__}:{phase}',
        )


async def run(providers: list[str], target: str, timeout_seconds: float) -> None:
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    connector = aiohttp.TCPConnector(ssl=ssl.create_default_context(cafile=certifi.where()))
    headers = {'User-Agent': Core.get_browser_user_agent()}
    async with (
        aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector) as session,
        async_playwright() as playwright,
    ):
        browser = await playwright.chromium.launch(headless=True)
        try:
            context: BrowserContext = await browser.new_context()
            try:
                page = await context.new_page()
                for provider in providers:
                    url = search_url(provider, target)
                    for result in (
                        await benchmark_aiohttp(session, provider, url),
                        await benchmark_playwright(page, provider, url, timeout_seconds * 1000),
                    ):
                        sys.stdout.write(f'{json.dumps(asdict(result), sort_keys=True)}\n')
                        sys.stdout.flush()
            finally:
                await context.close()
        finally:
            await browser.close()


async def run_baidu_ui(target: str, timeout_seconds: float) -> None:
    async with async_playwright() as playwright:
        browser: Browser = await playwright.chromium.launch(headless=False)
        try:
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                locale='en-US',
                timezone_id='America/New_York',
            )
            try:
                page = await context.new_page()
                result = await benchmark_baidu_ui(page, target, timeout_seconds * 1000)
                sys.stdout.write(f'{json.dumps(asdict(result), sort_keys=True)}\n')
                sys.stdout.flush()
            finally:
                await context.close()
        finally:
            await browser.close()


def self_check() -> None:
    assert classify('baidu', 200, 'https://www.baidu.com/s', '<div id="content_left">ok</div>') == 'results-page'
    assert classify('baidu', 302, 'https://wappass.baidu.com/static/captcha', '') == 'challenge'
    assert classify('mojeek', 403, 'https://www.mojeek.com/search', 'denied') == 'http-error'
    baidu_url = search_url('baidu', 'example.com')
    assert 'wd=site%3Aexample.com' in baidu_url
    assert 'rsv_pq=' not in baidu_url
    assert 'rsv_t=' not in baidu_url


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default='mozilla.org')
    parser.add_argument('--providers', nargs='+', choices=sorted(RESULT_MARKERS), default=sorted(RESULT_MARKERS))
    parser.add_argument('--timeout-seconds', type=positive_seconds, default=30)
    parser.add_argument('--baidu-ui-headed', action='store_true')
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if args.baidu_ui_headed:
        asyncio.run(run_baidu_ui(args.target, args.timeout_seconds))
        return
    asyncio.run(run(args.providers, args.target, args.timeout_seconds))


if __name__ == '__main__':
    main()
