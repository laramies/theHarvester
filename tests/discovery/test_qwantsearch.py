#!/usr/bin/env python3
# coding=utf-8
from theHarvester.discovery import qwantsearch
import os
import pytest

pytestmark = pytest.mark.asyncio
github_ci = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestSearchQwant(object):

    @staticmethod
    def domain() -> str:
        return 'example.com'

    def test_get_start_offset_return_0(self):
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 0, 200)
        assert search.get_start_offset() == 0

    def test_get_start_offset_return_50(self):
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 55, 200)
        assert search.get_start_offset() == 50

    def test_get_start_offset_return_100(self):
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 100, 200)
        assert search.get_start_offset() == 100

    async def test_get_emails(self):
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 0, 200)
        await search.process()
        assert isinstance(await search.get_emails(), set)

    async def test_get_hostnames(self):
        search = qwantsearch.SearchQwant(TestSearchQwant.domain(), 0, 200)
        await search.process()
        assert isinstance(await search.get_hostnames(), list)
