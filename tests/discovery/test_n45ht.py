#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import n45htsearch
import os
import requests
import pytest

pytestmark = pytest.mark.asyncio
github_ci = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestN45ht(object):
    @staticmethod
    def domain() -> str:
        return 'uber.com'

    async def test_api(self):
        base_url = f'https://api.n45ht.or.id/v1/subdomain-enumeration?domain={TestN45ht.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_do_search(self):
        search = n45htsearch.SearchN45ht(TestN45ht.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)


if __name__ == '__main__':
    pytest.main()
