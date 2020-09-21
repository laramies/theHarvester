#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import omnisint
import requests
import pytest

pytestmark = pytest.mark.asyncio


class TestOmnisint(object):
    @staticmethod
    def domain() -> str:
        return 'uber.com'

    async def test_api(self):
        base_url = f'https://sonar.omnisint.io/all/{TestOmnisint.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_search(self):
        search = omnisint.SearchOmnisint(TestOmnisint.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)
        assert isinstance(await search.get_ips(), set)


if __name__ == '__main__':
    pytest.main()
