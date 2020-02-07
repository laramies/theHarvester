#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import otxsearch
import requests
import pytest

pytestmark = pytest.mark.asyncio


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

    async def test_search_no_results(self):
        search = otxsearch.SearchOtx('radiant.eu')
        await search.process()
        assert len(await search.get_hostnames()) == 0


if __name__ == '__main__':
    pytest.main()
