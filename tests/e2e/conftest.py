from __future__ import annotations

import os
import subprocess
import sys
import time
from collections import Counter
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, TextIO
from urllib.parse import urlsplit

import httpx
import pytest

if TYPE_CHECKING:
    from playwright.sync_api import Page, Response, Route

CDNJS_TABULATOR_ASSETS = {
    'https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/css/tabulator.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/js/tabulator.min.js',
}


class HarvestViewServer:
    def __init__(self, repo_root: Path, port: int, environment: dict[str, str], server_log: Path) -> None:
        self.repo_root = repo_root
        self.port = port
        self.environment = environment
        self.server_log = server_log
        self.url = f'http://127.0.0.1:{port}'
        self._output: TextIO | None = None
        self._process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        self.server_log.parent.mkdir(parents=True, exist_ok=True)
        self._output = self.server_log.open('a', encoding='utf-8')
        self._process = subprocess.Popen(
            [
                sys.executable,
                '-m',
                'uvicorn',
                'theHarvester.lib.api.api:app',
                '--host',
                '127.0.0.1',
                '--port',
                str(self.port),
                '--log-level',
                'warning',
            ],
            cwd=self.repo_root,
            env=self.environment,
            stdout=self._output,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                self.stop()
                pytest.fail(f'theHarvester test server exited during startup; see {self.server_log}')
            try:
                if httpx.get(f'{self.url}/openapi.json', timeout=0.25).status_code == 200:
                    return
            except httpx.HTTPError:
                time.sleep(0.05)
        self.stop()
        pytest.fail(f'theHarvester test server did not become ready; see {self.server_log}')

    def stop(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
        self._process = None
        if self._output is not None:
            self._output.close()
            self._output = None

    def restart(self) -> None:
        self.stop()
        self.start()


class BrowserFailures:
    def __init__(self, page: Page) -> None:
        self.console_errors: Counter[str] = Counter()
        self.local_failures: Counter[tuple[str, int, str]] = Counter()
        self.external_requests: list[str] = []
        self.allowed_console_errors: Counter[str] = Counter()
        self.allowed_responses: Counter[tuple[str, int, str]] = Counter()
        page.on('console', self._record_console_message)
        page.on('response', self._record_response)
        page.route('**/*', self._guard_request)

    def _record_console_message(self, message) -> None:
        if message.type == 'error':
            self.console_errors[message.text] += 1

    def _guard_request(self, route: Route) -> None:
        request = route.request
        parsed = urlsplit(request.url)
        if request.url in CDNJS_TABULATOR_ASSETS:
            route.continue_()
            return
        if parsed.scheme not in {'http', 'https'} or parsed.hostname == 'localhost':
            route.continue_()
            return
        try:
            is_loopback = parsed.hostname is not None and ip_address(parsed.hostname).is_loopback
        except ValueError:
            is_loopback = False
        if is_loopback:
            route.continue_()
            return
        self.external_requests.append(f'{request.method} {request.url}')
        route.abort('blockedbyclient')

    def _record_response(self, response: Response) -> None:
        path = urlsplit(response.url).path
        if response.status >= 500 or (path.startswith('/api/v1/') and response.status == 401):
            self.local_failures[(response.request.method, response.status, path)] += 1

    def allow_response(self, method: str, status_code: int, path: str) -> None:
        self.allowed_responses[(method, status_code, path)] += 1

    def allow_console_error(self, message: str) -> None:
        self.allowed_console_errors[message] += 1

    def assert_clean(self) -> None:
        assert self.console_errors == self.allowed_console_errors
        assert self.local_failures == self.allowed_responses
        assert self.external_requests == []


@pytest.fixture(autouse=True)
def browser_failures(page: Page) -> BrowserFailures:
    failures = BrowserFailures(page)
    yield failures
    failures.assert_clean()


@pytest.fixture
def harvestview_server(tmp_path: Path, unused_tcp_port: int) -> HarvestViewServer:
    repo_root = Path(__file__).parents[2]
    artifact_dir = repo_root / 'test-results'
    artifact_dir.mkdir(exist_ok=True)
    server_log = artifact_dir / f'harvestview-server-{unused_tcp_port}.log'
    environment = os.environ.copy()
    environment.update(
        {
            'THEHARVESTER_API_KEY': 'harvestview-e2e-key',
            'THEHARVESTER_RUN_ARTIFACTS': str(tmp_path / 'artifacts'),
            'THEHARVESTER_RUN_DB': str(tmp_path / 'runs.sqlite'),
            'THEHARVESTER_RUN_WORKER': 'disabled',
            'ALL_PROXY': 'http://127.0.0.1:9',
            'HTTPS_PROXY': 'http://127.0.0.1:9',
            'HTTP_PROXY': 'http://127.0.0.1:9',
            'NO_PROXY': '127.0.0.1,localhost',
            'all_proxy': 'http://127.0.0.1:9',
            'https_proxy': 'http://127.0.0.1:9',
            'http_proxy': 'http://127.0.0.1:9',
            'no_proxy': '127.0.0.1,localhost',
        }
    )
    server = HarvestViewServer(repo_root, unused_tcp_port, environment, server_log)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def harvestview_server_url(harvestview_server: HarvestViewServer) -> str:
    return harvestview_server.url
