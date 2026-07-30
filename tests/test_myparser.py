#!/usr/bin/env python3
# coding=utf-8

import pytest

from theHarvester.parsers import myparser


class TestMyParser(object):
    @pytest.mark.asyncio
    @pytest.mark.parametrize('word', ['Example.COM.', 'WWW.Example.COM.'])
    async def test_emails_respect_target_label_boundaries(self, word: str) -> None:
        results = "Admin@Example.COM***admin@notexample.com***.Lead@Sub.Example.COM.***other@outside.test"
        parse = myparser.Parser(results, word)
        assert await parse.emails() == {"admin@example.com", "lead@sub.example.com"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize('word', ['Example.COM.', 'WWW.Example.COM.'])
    async def test_hostnames_respect_target_label_boundaries(self, word: str) -> None:
        results = "Example.COM. API.Example.COM. badexample.com outside.test sub.example.com"
        parse = myparser.Parser(results, word)
        assert set(await parse.hostnames()) == {"api.example.com", "example.com", "sub.example.com"}

    @pytest.mark.asyncio
    async def test_hostnames_remove_uppercase_encoded_slash(self) -> None:
        parse = myparser.Parser('%2Fencrypted.google.com', 'google.com')

        assert await parse.hostnames() == ['encrypted.google.com']

    @pytest.mark.asyncio
    async def test_empty_target_fails_closed(self) -> None:
        parse = myparser.Parser('admin@example.com api.example.com', '')

        assert await parse.emails() == set()
        assert await parse.hostnames() == []


if __name__ == "__main__":
    pytest.main()
