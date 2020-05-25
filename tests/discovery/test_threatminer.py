#!/usr/bin/env python3
# coding=utf-8
import requests
from theHarvester.lib.core import *
from theHarvester.discovery import threatminer
import pytest

pytestmark = pytest.mark.asyncio


class TestThreatminer(object):
    @staticmethod
    def domain() -> str:
        return 'target.com'

    async def test_api(self):
        base_url = f'https://api.sublist3r.com/search.php?domain={TestThreatminer.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_search(self):
        search = threatminer.SearchThreatminer(TestThreatminer.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)


if __name__ == '__main__':
    pytest.main()
