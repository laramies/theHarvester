#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import bufferoverun
import os
import requests
import pytest

pytestmark = pytest.mark.asyncio
github_ci = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestBufferover(object):
    @staticmethod
    def domain() -> str:
        return 'uber.com'

    async def test_api(self):
        base_url = f'https://dns.bufferover.run/dns?q={TestBufferover.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_do_search(self):
        search = bufferoverun.SearchBufferover(TestBufferover.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)
        assert isinstance(await search.get_ips(), set)


if __name__ == '__main__':
    pytest.main()
