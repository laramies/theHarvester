#!/usr/bin/env python3
# coding=utf-8
import requests
from theHarvester.lib.core import *
from theHarvester.discovery import sublist3r
import os
import pytest
from _pytest.mark.structures import MarkDecorator
from typing import Optional

pytestmark: MarkDecorator = pytest.mark.asyncio
github_ci: Optional[str] = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestSublist3r(object):
    @staticmethod
    def domain() -> str:
        return 'google.com'

    async def test_api(self) -> None:
        base_url = f'https://api.sublist3r.com/search.php?domain={TestSublist3r.domain()}'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    @pytest.mark.skipif(github_ci == 'true', reason='Skipping on Github CI due unstable site')
    async def test_do_search(self) -> None:
        search = sublist3r.SearchSublist3r(TestSublist3r.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), list)


if __name__ == '__main__':
    pytest.main()
