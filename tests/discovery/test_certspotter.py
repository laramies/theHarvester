#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import certspottersearch
import os
import requests
import pytest
from _pytest.mark.structures import MarkDecorator
from typing import Optional

pytestmark: MarkDecorator = pytest.mark.asyncio
github_ci: Optional[str] = os.getenv('GITHUB_ACTIONS')  # Github set this to be the following: true instead of True


class TestCertspotter(object):
    @staticmethod
    def domain() -> str:
        return 'metasploit.com'

    async def test_api(self) -> None:
        base_url = f'https://api.certspotter.com/v1/issuances?domain={TestCertspotter.domain()}&expand=dns_names'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    async def test_search(self) -> None:
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        await search.process()
        assert isinstance(await search.get_hostnames(), set)

    async def test_search_no_results(self) -> None:
        search = certspottersearch.SearchCertspoter('radiant.eu')
        await search.process()
        assert len(await search.get_hostnames()) == 0


if __name__ == '__main__':
    pytest.main()
