#!/usr/bin/env python3
# coding=utf-8

import pytest

from theHarvester.parsers import myparser


class TestMyParser(object):
    @pytest.mark.asyncio
    async def test_emails_respect_target_label_boundaries(self) -> None:
        word = "Example.COM."
        results = "Admin@Example.COM***admin@notexample.com***.Lead@Sub.Example.COM.***other@outside.test"
        parse = myparser.Parser(results, word)
        assert await parse.emails() == {"admin@example.com", "lead@sub.example.com"}

    @pytest.mark.asyncio
    async def test_hostnames_respect_target_label_boundaries(self) -> None:
        word = "Example.COM."
        results = "API.Example.COM. badexample.com outside.test sub.example.com"
        parse = myparser.Parser(results, word)
        assert set(await parse.hostnames()) == {"api.example.com", "sub.example.com"}


if __name__ == "__main__":
    pytest.main()
