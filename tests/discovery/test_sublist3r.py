#!/usr/bin/env python3
# coding=utf-8
import requests
from theHarvester.lib.core import *
from theHarvester.discovery import sublist3r
import os
import pytest

pytestmark = pytest.mark.asyncio
github_ci = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestSublist3r(object):
    @staticmethod
    def domain() -> str:
        return 'target.com'

    async def test_api(self):
        base_url = f'https://api.sublist3r.com/search.php?domain={TestSublist3r.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_do_search(self):
        search = sublist3r.SearchSublist3r(TestSublist3r.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), list)


if __name__ == '__main__':
    pytest.main()
