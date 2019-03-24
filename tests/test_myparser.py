#!/usr/bin/env python3
# coding=utf-8

from theHarvester.parsers import myparser
import pytest


class TestMyParser(object):

    def test_emails(self):
        word = 'domain.com'
        results = '@domain.com***a@domain***banotherdomain.com***c@domain.com***d@sub.domain.com***'
        parse = myparser.Parser(results, word)
        emails = sorted(parse.emails())
        assert emails, ['c@domain.com', 'd@sub.domain.com']


if __name__ == '__main__':
    pytest.main()

