#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import otxsearch
import requests
import pytest


class TestOtx(object):
    @staticmethod
    def domain() -> str:
        return 'metasploit.com'

    def test_api(self):
        base_url = f'https://otx.alienvault.com/api/v1/indicators/domain/{TestOtx.domain()}/passive_dns'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    def test_search(self):
        search = otxsearch.SearchOtx(TestOtx.domain())
        search.process()
        assert isinstance(search.get_hostnames(), set)

    def test_search_no_results(self):
        search = otxsearch.SearchOtx('radiant.eu')
        search.process()
        assert len(search.get_hostnames()) == 0


if __name__ == '__main__':
    pytest.main()
