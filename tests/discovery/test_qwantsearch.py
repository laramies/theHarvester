#!/usr/bin/env python3
# coding=utf-8
from theHarvester.discovery import qwantsearch
import os
import pytest
from _pytest.mark.structures import MarkDecorator
from typing import Optional

pytestmark: MarkDecorator = pytest.mark.asyncio
github_ci: Optional[str] = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestSearchQwant(object):

    @staticmethod
    def domain() -> str:
        return 'example.com'

    async def test_get_start_offset_return_0(self) -> None:
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 0, 200)
        assert search.get_start_offset() == 0

    async def test_get_start_offset_return_50(self) -> None:
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 55, 200)
        assert search.get_start_offset() == 50

    async def test_get_start_offset_return_100(self) -> None:
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 100, 200)
        assert search.get_start_offset() == 100

    async def test_get_emails(self) -> None:
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 0, 200)
        await search.process()
        assert isinstance(await search.get_emails(), set)

    async def test_get_hostnames(self) -> None:
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 0, 200)
        await search.process()
        assert isinstance(await search.get_hostnames(), list)
