#!/usr/bin/env python3
# coding=utf-8
import os
from typing import Optional
import httpx
import pytest

from theHarvester.discovery import otxsearch
from theHarvester.lib.core import *

github_ci: Optional[str] = os.getenv(
    "GITHUB_ACTIONS"
)  # Github set this to be the following: true instead of True


class TestOtx(object):
    @staticmethod
    def domain() -> str:
        return "apple.com"

    @pytest.mark.asyncio
    async def test_search(self) -> None:
        search = otxsearch.SearchOtx(TestOtx.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip("Skipping OTX search due to network error")
        assert isinstance(await search.get_hostnames(), set)
        assert isinstance(await search.get_ips(), set)


if __name__ == "__main__":
    pytest.main()
