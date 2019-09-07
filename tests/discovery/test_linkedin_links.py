#!/usr/bin/env python3
# coding=utf-8
import sys
sys.path.append("../../")
from theHarvester.parsers import myparser
from theHarvester.discovery import linkedinsearch
import pytest
from theHarvester.lib import stash


class TestGetLinks(object):

    def test_get_links(self):
        search = linkedinsearch.SearchLinkedin("facebook.com", '100')
        search.process()
        links = search.get_links()
        for link in links:
            print(link)

if __name__ == '__main__':
    pytest.main()
