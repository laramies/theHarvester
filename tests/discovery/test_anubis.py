#!/usr/bin/env python3
# coding=utf-8
import requests
from theHarvester.lib.core import *
from theHarvester.discovery import anubis
import os
import pytest
from _pytest.mark.structures import MarkDecorator
from typing import Optional

pytestmark: MarkDecorator = pytest.mark.asyncio
github_ci: Optional[str] = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestAnubis:
    @staticmethod
    def domain() -> str:
        return 'apple.com'

    async def test_api(self) -> None:
        base_url = f'https://jldc.me/anubis/subdomains/{TestAnubis.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_do_search(self):
        search = anubis.SearchAnubis(word=TestAnubis.domain())
        await search.do_search()
        return await search.get_hostnames()

    async def test_process(self) -> None:
        await self.test_do_search()
        assert len(await self.test_do_search()) > 0
