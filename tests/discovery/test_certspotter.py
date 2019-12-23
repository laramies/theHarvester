#!/usr/bin/env python3
# coding=utf-8
from theHarvester.lib.core import *
from theHarvester.discovery import certspottersearch
import requests
import pytest


class TestCertspotter(object):
    @staticmethod
    def domain() -> str:
        return 'metasploit.com'

    def test_api(self):
        base_url = f'https://api.certspotter.com/v1/issuances?domain={TestCertspotter.domain()}&expand=dns_names'
        headers = {'User-Agent': Core.get_user_agent()}
        request = requests.get(base_url, headers=headers)
        assert request.status_code == 200

    def test_search(self):
        search = certspottersearch.SearchCertspoter(TestCertspotter.domain())
        search.process()
        assert isinstance(search.get_hostnames(), set)

    def test_search_no_results(self):
        search = certspottersearch.SearchCertspoter('radiant.eu')
        search.process()
        assert len(search.get_hostnames()) == 0


if __name__ == '__main__':
    pytest.main()
