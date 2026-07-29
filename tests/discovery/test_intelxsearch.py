import pytest

from theHarvester.discovery import intelxsearch
from theHarvester.discovery.constants import MissingKey


class _Response:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    async def json(self) -> object:
        return self.payload


class _Session:
    def __init__(self, result: object, search_result: object | None = None) -> None:
        self.result = result
        self.search_result = {'success': True, 'id': 'search-id'} if search_result is None else search_result

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def post(self, *_args, **_kwargs) -> _Response:
        return _Response(self.search_result)

    def get(self, *_args, **_kwargs) -> _Response:
        return _Response(self.result)


def test_blank_key_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: '  '))

    with pytest.raises(MissingKey):
        intelxsearch.SearchIntelx('example.com')


@pytest.mark.asyncio
async def test_process_exposes_flat_normalized_in_scope_results(monkeypatch: pytest.MonkeyPatch) -> None:
    result = {
        'selectors': [
            {'selectorvalue': 'ADMIN@Example.COM'},
            {'selectorvalue': 'outsider@notexample.com'},
            {'selectorvalue': 'not@an@email@example.com'},
            {'selectorvalue': 'https://portal.example.com/path'},
            {'selectorvalue': 'api.example.com.'},
            {'selectorvalue': 'foo.example.com.evil'},
            {'selectorvalue': 'http://['},
            {'selectorvalue': None},
            None,
        ]
    }
    session = _Session(result)

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(intelxsearch.aiohttp, 'ClientSession', lambda: session)
    monkeypatch.setattr(intelxsearch.asyncio, 'sleep', no_sleep)

    search = intelxsearch.SearchIntelx('example.com')
    await search.process()

    assert await search.get_emails() == ['admin@example.com']
    assert await search.get_hostnames() == ['api.example.com', 'portal.example.com']
    assert await search.get_interestingurls() == [
        'api.example.com.',
        'foo.example.com.evil',
        'https://portal.example.com/path',
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('search_result', 'result'),
    [
        ({'success': False, 'message': 'denied'}, {}),
        ({}, {}),
        ({'success': True, 'id': 'search-id'}, None),
        ({'success': True, 'id': 'search-id'}, {'selectors': 'invalid'}),
    ],
)
async def test_process_treats_denied_and_malformed_responses_as_empty(
    monkeypatch: pytest.MonkeyPatch,
    search_result: object,
    result: object,
) -> None:
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(intelxsearch.Core, 'intelx_key', staticmethod(lambda: 'test-key'))
    monkeypatch.setattr(intelxsearch.aiohttp, 'ClientSession', lambda: _Session(result, search_result))
    monkeypatch.setattr(intelxsearch.asyncio, 'sleep', no_sleep)

    search = intelxsearch.SearchIntelx('example.com')
    await search.process()

    assert await search.get_emails() == []
    assert await search.get_hostnames() == []
    assert await search.get_interestingurls() == []
