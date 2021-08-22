#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import otxsearch
import os
import requests
import pytest

pytestmark = pytest.mark.asyncio
github_ci = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestOtx(object):
    @staticmethod
    def domain() -> str:
        return 'metasploit.com'

    async def test_api(self):
        base_url = f'https://otx.alienvault.com/api/v1/indicators/domain/{TestOtx.domain()}/passive_dns'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_search(self):
        search = otxsearch.SearchOtx(TestOtx.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)
        assert isinstance(await search.get_ips(), set)

    async def test_search_no_results(self):
        search = otxsearch.SearchOtx('radiant.eu')
        await search.process()
        assert len(await search.get_hostnames()) == 0
        assert len(await search.get_ips()) == 0


if __name__ == '__main__':
    pytest.main()
