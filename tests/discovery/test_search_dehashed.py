import logging

import pytest

from theHarvester.discovery import search_dehashed
from theHarvester.discovery.search_dehashed import SearchDehashed


@pytest.mark.asyncio
async def test_process_does_not_output_credentials(monkeypatch, capsys) -> None:
    search = SearchDehashed.__new__(SearchDehashed)
    search.data = [{'email': 'user@example.com', 'password': 'secret-password'}]

    async def do_search() -> None:
        return None

    monkeypatch.setattr(search, 'do_search', do_search)
    await search.process()

    assert 'secret-password' not in capsys.readouterr().out
    assert await search.get_emails() == {'user@example.com'}


@pytest.mark.asyncio
async def test_non_json_response_body_is_not_logged(monkeypatch, caplog) -> None:
    class Response:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def json(self):
            raise ValueError

        async def text(self):
            return 'provider-secret-payload'

    class Session:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def post(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(search_dehashed.aiohttp, 'ClientSession', Session)
    caplog.set_level(logging.INFO, logger=search_dehashed.__name__)
    search = SearchDehashed.__new__(SearchDehashed)
    search.word = 'example.com'
    search.api = 'https://provider.example'
    search.headers = {}
    search.proxy = False
    search.data = []

    await search.do_search()

    assert 'provider-secret-payload' not in caplog.text
