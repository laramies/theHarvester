from typing import Any

import pytest

from theHarvester.discovery import mojeek


def _patch_mojeek(
    monkeypatch: pytest.MonkeyPatch,
    *,
    api_key: str,
    api_responses: list[Any] | None = None,
    scrape_responses: list[Any] | None = None,
) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []

    async def fake_fetch_all(
        urls: list[str] | set[str],
        headers: dict[str, str] | None = None,
        proxy: bool = False,
        json: bool = False,
    ) -> list[Any]:
        requests.append(
            {
                'urls': list(urls),
                'headers': headers,
                'proxy': proxy,
                'json': json,
            }
        )
        responses = api_responses if json else scrape_responses
        return responses if responses is not None else []

    monkeypatch.setattr(mojeek.Core, 'mojeek_key', staticmethod(lambda: api_key))
    monkeypatch.setattr(mojeek.Core, 'get_user_agent', staticmethod(lambda: 'UA'))
    monkeypatch.setattr(mojeek.AsyncFetcher, 'fetch_all', fake_fetch_all)
    return requests


class TestMojeekSearch:
    @pytest.mark.asyncio
    async def test_keyless_mode_uses_scraping_without_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        requests = _patch_mojeek(
            monkeypatch,
            api_key='',
            scrape_responses=['Contact security@example.com at docs.example.com'],
        )

        search = mojeek.SearchMojeek(word='example.com', limit=10)
        await search.process()

        assert requests == [
            {
                'urls': ['https://www.mojeek.com/search?q=example.com&s=0'],
                'headers': {'User-Agent': 'UA'},
                'proxy': False,
                'json': False,
            }
        ]
        assert await search.get_emails() == {'security@example.com'}
        assert set(await search.get_hostnames()) - {'example.com'} == {'docs.example.com'}

    @pytest.mark.asyncio
    async def test_keyed_api_success_parses_results_without_scraping(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        requests = _patch_mojeek(
            monkeypatch,
            api_key='test-key',
            api_responses=[
                {
                    'response': {
                        'results': [
                            {
                                'url': 'https:\\/\\/blog.example.com\\/contact',
                                'title': 'Contact admin@example.com',
                                'desc': 'API docs at api.example.com',
                            }
                        ]
                    }
                }
            ],
        )

        search = mojeek.SearchMojeek(word='example.com', limit=20)
        await search.process(proxy=True)

        assert requests == [
            {
                'urls': [
                    'https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=1',
                    'https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=11',
                ],
                'headers': {'User-Agent': 'UA'},
                'proxy': True,
                'json': True,
            }
        ]
        assert await search.get_emails() == {'admin@example.com'}
        assert set(await search.get_hostnames()) - {'example.com'} == {
            'api.example.com',
            'blog.example.com',
        }

    @pytest.mark.parametrize(
        'api_responses',
        [
            [],
            [''],
            [{'results': ['not-an-object']}],
            [{'results': [{}]}],
            [{'status': 'Access denied'}],
            [
                {'results': [{'url': 'https://api-only.example.com', 'title': 'api-only@example.com'}]},
                '',
            ],
            [
                {'results': [{'url': 'https://api-only.example.com', 'title': 'api-only@example.com'}]},
                {'status': 'Access denied'},
            ],
            [
                {'results': [{'url': 'https://api-only.example.com', 'title': 'api-only@example.com'}]},
                {'status': None},
            ],
        ],
        ids=[
            'empty',
            'non-mapping-response',
            'malformed-results',
            'empty-result',
            'denied',
            'partial-then-malformed',
            'partial-then-denied',
            'partial-then-malformed-status',
        ],
    )
    @pytest.mark.asyncio
    async def test_unusable_api_response_falls_back_to_scraping(
        self,
        monkeypatch: pytest.MonkeyPatch,
        api_responses: list[Any],
    ) -> None:
        requests = _patch_mojeek(
            monkeypatch,
            api_key='test-key',
            api_responses=api_responses,
            scrape_responses=['Contact admin@example.com at search.example.com'],
        )

        search = mojeek.SearchMojeek(word='example.com', limit=20)
        await search.process(proxy=True)

        assert requests == [
            {
                'urls': [
                    'https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=1',
                    'https://api.mojeek.com/search?api_key=test-key&q=example.com&fmt=json&s=11',
                ],
                'headers': {'User-Agent': 'UA'},
                'proxy': True,
                'json': True,
            },
            {
                'urls': [
                    'https://www.mojeek.com/search?q=example.com&s=0',
                    'https://www.mojeek.com/search?q=example.com&s=10',
                ],
                'headers': {'User-Agent': 'UA'},
                'proxy': True,
                'json': False,
            },
        ]
        assert await search.get_emails() == {'admin@example.com'}
        assert set(await search.get_hostnames()) - {'example.com'} == {'search.example.com'}
