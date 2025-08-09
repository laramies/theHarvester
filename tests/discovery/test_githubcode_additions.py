from unittest.mock import MagicMock, AsyncMock
import asyncio
import pytest
from _pytest.mark.structures import MarkDecorator
from theHarvester.discovery import githubcode
from theHarvester.lib.core import Core

pytestmark: MarkDecorator = pytest.mark.asyncio


class TestSearchGithubCodeProcess:
    async def test_process_stops_after_max_retries(self, monkeypatch):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        inst = githubcode.SearchGithubCode(word="test", limit=10)

        # Speed up by avoiding actual sleeps
        monkeypatch.setattr(githubcode, "get_delay", lambda: 0, raising=False)
        monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

        # Force RetryResult every time
        monkeypatch.setattr(
            inst,
            "handle_response",
            AsyncMock(return_value=githubcode.RetryResult(0)),
        )
        monkeypatch.setattr(
            inst,
            "do_search",
            AsyncMock(return_value=("", {}, 403, {})),
        )

        inst.max_retries = 2
        await inst.process()
        assert inst.page == 0, "Process should stop after exceeding max retries"
        assert inst.retry_count == 3, "Retry count should exceed max_retries before stopping"

    async def test_process_stops_on_error_result(self, monkeypatch):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        inst = githubcode.SearchGithubCode(word="test", limit=10)

        monkeypatch.setattr(githubcode, "get_delay", lambda: 0, raising=False)
        monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

        # Force ErrorResult
        monkeypatch.setattr(
            inst,
            "handle_response",
            AsyncMock(return_value=githubcode.ErrorResult(500, "err")),
        )
        monkeypatch.setattr(
            inst,
            "do_search",
            AsyncMock(return_value=("", {}, 500, {})),
        )

        await inst.process()
        assert inst.page == 0, "Process should stop on error result to avoid infinite loop"

    async def test_process_breaks_on_same_page_pagination(self, monkeypatch):
        Core.github_key = MagicMock(return_value="test_key")  # type: ignore[method-assign]
        inst = githubcode.SearchGithubCode(word="test", limit=10)

        monkeypatch.setattr(githubcode, "get_delay", lambda: 0, raising=False)
        monkeypatch.setattr(asyncio, "sleep", AsyncMock(return_value=None))

        # Force SuccessResult that does not advance the page
        monkeypatch.setattr(
            inst,
            "handle_response",
            AsyncMock(return_value=githubcode.SuccessResult([], next_page=1, last_page=0)),
        )
        monkeypatch.setattr(
            inst,
            "do_search",
            AsyncMock(return_value=("", {"items": []}, 200, {})),
        )

        await inst.process()
        assert inst.page == 0, "Process should stop when pagination does not advance"
