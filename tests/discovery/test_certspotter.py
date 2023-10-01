#!/usr/bin/env python3
# coding=utf-8
import os
from typing import Optional

import pytest
import requests
from _pytest.mark.structures import MarkDecorator

from theHarvester.discovery import certspottersearch
from theHarvester.lib.core import *

pytestmark: MarkDecorator = pytest.mark.asyncio
github_ci: Optional[str] = os.getenv(
    "GITHUB_ACTIONS"
)  # Github set this to be the following: true instead of True


class TestCertspotter(object):
    @staticmethod
    def domain() -> str:
        return "metasploit.com"

    async def test_api(self) -> None:
        base_url = f"https://api.certspotter.com/v1/issuances?domain={TestCertspotter.domain()}&expand=dns_names"
        headers = {"User-Agent": Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_search(self) -> None:
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)


if __name__ == "__main__":
    pytest.main()
