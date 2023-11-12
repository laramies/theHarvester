#!/usr/bin/env python3
# coding=utf-8
import os
from typing import Optional

import pytest
import requests
from _pytest.mark.structures import MarkDecorator

from theHarvester.discovery import otxsearch
from theHarvester.lib.core import *

pytestmark: MarkDecorator = pytest.mark.asyncio
github_ci: Optional[str] = os.getenv(
    "GITHUB_ACTIONS"
)  # Github set this to be the following: true instead of True


class TestOtx(object):
    @staticmethod
    def domain() -> str:
        return "cybermon.uk"

    async def test_api(self) -> None:
        base_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{TestOtx.domain()}/passive_dns"
        headers = {"User-Agent": Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_search(self) -> None:
        search = otxsearch.SearchOtx(TestOtx.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)
        assert isinstance(await search.get_ips(), set)


if __name__ == "__main__":
    pytest.main()
