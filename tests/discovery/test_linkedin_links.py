#!/usr/bin/env python3
# coding=utf-8
from theHarvester.discovery import linkedinsearch
from theHarvester.discovery.constants import splitter
import pytest
import os
import re


class TestGetLinks(object):

    def test_splitter(self):
        results = [
            'https://www.linkedin.com/in/don-draper-b1045618',
            'https://www.linkedin.com/in/don-draper-b59210a',
            'https://www.linkedin.com/in/don-draper-b5bb50b3',
            'https://www.linkedin.com/in/don-draper-b83ba26',
            'https://www.linkedin.com/in/don-draper-b854a51'
        ]
        filtered_results = splitter(results)
        assert len(filtered_results) == 1

    def test_get_links(self):
        search = linkedinsearch.SearchLinkedin("facebook.com", '100')
        search.process()
        links = search.get_links()
        assert type(links) == list

    def test_links_linkedin(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        mock_response = open(dir_path + "/test_linkedin_links.txt")
        mock_response_content = mock_response.read()
        mock_response.close()
        reg_links = re.compile(r"url=https:\/\/www\.linkedin.com(.*?)&")
        temp = reg_links.findall(mock_response_content)
        resul = []
        for regex_item in temp:
            stripped_url = regex_item.replace("url=", "")
            resul.append("https://www.linkedin.com" + stripped_url)
        assert set(resul)


if __name__ == '__main__':
    pytest.main()
