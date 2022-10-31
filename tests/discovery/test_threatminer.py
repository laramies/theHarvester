#!/usr/bin/env python3
# coding=utf-8
import requests
from theHarvester.lib.core import *
from theHarvester.discovery import threatminer
import os
import pytest
from _pytest.mark.structures import MarkDecorator
from typing import Optional

pytestmark: MarkDecorator = pytest.mark.asyncio
github_ci: Optional[str] = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestThreatminer(object):
    @staticmethod
    def domain() -> str:
        return 'target.com'

    async def test_api(self) -> None:
        base_url = f'https://api.threatminer.org/v2/domain.php?q={TestThreatminer.domain()}&rt=5'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_search(self) -> None:
        search = threatminer.SearchThreatminer(TestThreatminer.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)
        assert isinstance(await search.get_ips(), set)


if __name__ == '__main__':
    pytest.main()
