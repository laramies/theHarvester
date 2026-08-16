import asyncio
from typing import Any

import pytest

from theHarvester.discovery import apisguru
from theHarvester.lib.core import FetcherResponse, ResponseStreamError


@pytest.mark.asyncio
async def test_preferred_openapi_three_spec_returns_only_target_scoped_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/api.example.com/payments/1.0.0/openapi.json'
    responses = [
        FetcherResponse(
            body={
                'apis': {
                    'example.com:payments': {
                        'info': {'title': 'Payments', 'x-providerName': 'example.com'},
                        'swaggerUrl': spec_url,
                        'openapiVer': '3.0.3',
                    },
                    'notexample.com': {
                        'info': {'title': 'Example Brand API', 'x-providerName': 'notexample.com'},
                        'swaggerUrl': 'https://api.apis.guru/v2/specs/notexample.com/1.0.0/openapi.json',
                        'openapiVer': '3.0.3',
                    },
                    'example.com.evil': {
                        'info': {'x-providerName': 'example.com.evil'},
                        'swaggerUrl': 'https://api.apis.guru/v2/specs/example.com.evil/1.0.0/openapi.json',
                        'openapiVer': '3.0.3',
                    },
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={
                'openapi': '3.0.3',
                'servers': [
                    {'url': 'https://api.example.com/v1'},
                    {'url': 'https://{tenant}.example.com/v1'},
                    {'url': 'https://api.example.com/{version}'},
                    {'url': 'https://auth.vendor.test/oauth'},
                    {'url': 'https://example.com.evil/v1'},
                ],
                'info': {
                    'contact': {
                        'email': 'Security@Example.COM',
                        'url': 'https://developers.example.com/support',
                    },
                    'termsOfService': 'https://legal.example.com/terms',
                },
                'externalDocs': {'url': 'https://docs.example.com/reference'},
            },
            status=200,
            headers={},
        ),
    ]
    calls: list[dict[str, Any]] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        calls.append(kwargs)
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process(proxy=True)

    assert await search.get_hostnames() == {
        'api.example.com',
        'developers.example.com',
        'docs.example.com',
        'legal.example.com',
    }
    assert await search.get_emails() == {'security@example.com'}
    assert await search.get_urls() == {
        'https://api.example.com/v1',
        'https://developers.example.com/support',
        'https://docs.example.com/reference',
        'https://legal.example.com/terms',
    }
    assert [call['url'] for call in calls] == [
        'https://api.apis.guru/v2/example.com.json',
        spec_url,
    ]
    assert all(call['proxy'] is True for call in calls)
    assert all(call['request_timeout'] == 60 for call in calls)
    assert all(set(call) == {'url', 'proxy', 'request_timeout'} for call in calls)
    assert report is None


@pytest.mark.asyncio
async def test_templated_server_path_retains_its_concrete_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/templated/1.0/openapi.json'
    responses = [
        FetcherResponse(
            body={
                'apis': {
                    'example.com:templated': {
                        'info': {'x-providerName': 'example.com'},
                        'swaggerUrl': spec_url,
                        'openapiVer': '3.0.3',
                    }
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://api.example.com/{version}'}]},
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=500)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_urls() == set()
    assert report is None


@pytest.mark.asyncio
async def test_unwrapped_directory_and_openapi_two_spec_are_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/2.0/swagger.json'
    responses = [
        FetcherResponse(
            body={
                'example.com': {
                    'preferred': '2.0',
                    'versions': {
                        '2.0': {
                            'info': {'x-providerName': 'example.com'},
                            'swaggerUrl': spec_url,
                        }
                    },
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={
                'swagger': '2.0',
                'host': 'API.Example.COM',
                'basePath': '/v2',
                'schemes': ['https', 'http', 'ftp'],
                'info': {
                    'contact': {
                        'email': 'Ops@example.com',
                        'url': 'https://support.example.com/help?token=discarded#fragment',
                    },
                },
            },
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('EXAMPLE.com.', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com', 'support.example.com'}
    assert await search.get_emails() == {'ops@example.com'}
    assert await search.get_urls() == {
        'http://api.example.com/v2',
        'https://api.example.com/v2',
        'https://support.example.com/help',
    }
    assert report is None


@pytest.mark.asyncio
async def test_external_spec_url_is_not_fetched_and_valid_results_remain_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_spec_url = 'https://api.apis.guru/v2/specs/example.com/good/1.0/openapi.json'
    responses = [
        FetcherResponse(
            body={
                'apis': {
                    'example.com:bad': {
                        'preferred': '1.0',
                        'versions': {
                            '1.0': {
                                'info': {'x-providerName': 'example.com'},
                                'swaggerUrl': 'https://attacker.test/spec.json',
                            }
                        },
                    },
                    'example.com:good': {
                        'preferred': '1.0',
                        'versions': {
                            '1.0': {
                                'info': {'x-providerName': 'example.com'},
                                'swaggerUrl': valid_spec_url,
                            }
                        },
                    },
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://api.example.com/v1'}]},
            status=200,
            headers={},
        ),
    ]
    requested_urls: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requested_urls.append(kwargs['url'])
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert requested_urls == ['https://api.apis.guru/v2/example.com.json', valid_spec_url]
    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_preferred_spec_requests_are_not_artificially_capped_at_five(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_urls = [f'https://api.apis.guru/v2/specs/example.com/service-{index}/1.0/openapi.json' for index in range(6)]
    directory = {
        f'example.com:service-{index}': {
            'info': {'x-providerName': 'example.com'},
            'swaggerUrl': spec_url,
            'openapiVer': '3.0.3',
        }
        for index, spec_url in enumerate(spec_urls)
    }
    requested_urls: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requested_urls.append(kwargs['url'])
        if kwargs['url'] == 'https://api.apis.guru/v2/example.com.json':
            return FetcherResponse(body={'apis': directory}, status=200, headers={})
        index = spec_urls.index(kwargs['url'])
        return FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': f'https://api-{index}.example.com'}]},
            status=200,
            headers={},
        )

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=500)

    report = await search.process()

    assert requested_urls == ['https://api.apis.guru/v2/example.com.json', *spec_urls]
    assert await search.get_hostnames() == {f'api-{index}.example.com' for index in range(6)}
    assert report is None


@pytest.mark.asyncio
async def test_oversized_preferred_spec_does_not_discard_later_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_urls = [
        'https://api.apis.guru/v2/specs/example.com/oversized/1.0/openapi.json',
        'https://api.apis.guru/v2/specs/example.com/usable/1.0/openapi.json',
    ]
    directory = {
        f'example.com:service-{index}': {
            'info': {'x-providerName': 'example.com'},
            'swaggerUrl': spec_url,
            'openapiVer': '3.0.3',
        }
        for index, spec_url in enumerate(spec_urls)
    }
    requested_urls: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requested_urls.append(kwargs['url'])
        if kwargs['url'] == 'https://api.apis.guru/v2/example.com.json':
            return FetcherResponse(body={'apis': directory}, status=200, headers={})
        if kwargs['url'] == spec_urls[0]:
            raise ResponseStreamError('response-limit')
        return FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://api.example.com'}]},
            status=200,
            headers={},
        )

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=500)

    report = await search.process()

    assert requested_urls == ['https://api.apis.guru/v2/example.com.json', *spec_urls]
    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'response-limit'


@pytest.mark.asyncio
async def test_missing_preferred_spec_does_not_discard_later_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_urls = [
        'https://api.apis.guru/v2/specs/example.com/missing/1.0/openapi.json',
        'https://api.apis.guru/v2/specs/example.com/usable/1.0/openapi.json',
    ]
    directory = {
        f'example.com:service-{index}': {
            'info': {'x-providerName': 'example.com'},
            'swaggerUrl': spec_url,
            'openapiVer': '3.0.3',
        }
        for index, spec_url in enumerate(spec_urls)
    }
    requested_urls: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requested_urls.append(kwargs['url'])
        if kwargs['url'] == 'https://api.apis.guru/v2/example.com.json':
            return FetcherResponse(body={'apis': directory}, status=200, headers={})
        if kwargs['url'] == spec_urls[0]:
            return FetcherResponse(body=None, status=404, headers={})
        return FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://api.example.com'}]},
            status=200,
            headers={},
        )

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=500)

    report = await search.process()

    assert requested_urls == ['https://api.apis.guru/v2/example.com.json', *spec_urls]
    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'http-404'


@pytest.mark.asyncio
async def test_access_denied_preferred_spec_stops_before_later_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_urls = [
        'https://api.apis.guru/v2/specs/example.com/forbidden/1.0/openapi.json',
        'https://api.apis.guru/v2/specs/example.com/later/1.0/openapi.json',
    ]
    directory = {
        f'example.com:service-{index}': {
            'info': {'x-providerName': 'example.com'},
            'swaggerUrl': spec_url,
            'openapiVer': '3.0.3',
        }
        for index, spec_url in enumerate(spec_urls)
    }
    requested_urls: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requested_urls.append(kwargs['url'])
        if kwargs['url'] == 'https://api.apis.guru/v2/example.com.json':
            return FetcherResponse(body={'apis': directory}, status=200, headers={})
        return FetcherResponse(body=None, status=403, headers={})

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=500)

    report = await search.process()

    assert requested_urls == ['https://api.apis.guru/v2/example.com.json', spec_urls[0]]
    assert report.status == 'failed'
    assert report.stop_reason == 'access-denied'


@pytest.mark.asyncio
async def test_result_limit_does_not_truncate_preferred_spec_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    spec_urls = [f'https://api.apis.guru/v2/specs/example.com/service-{index}/1.0/openapi.json' for index in range(3)]
    directory = {
        f'example.com:service-{index}': {
            'preferred': '1.0',
            'versions': {
                '1.0': {
                    'info': {'x-providerName': 'example.com'},
                    'swaggerUrl': spec_url,
                }
            },
        }
        for index, spec_url in enumerate(spec_urls)
    }
    responses = [
        FetcherResponse(body={'apis': directory}, status=200, headers={}),
        FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://one.example.com'}]},
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://two.example.com'}]},
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://three.example.com'}]},
            status=200,
            headers={},
        ),
    ]
    requested_urls: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requested_urls.append(kwargs['url'])
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=2)

    report = await search.process()

    assert requested_urls == ['https://api.apis.guru/v2/example.com.json', *spec_urls]
    assert await search.get_hostnames() == {'one.example.com', 'two.example.com'}
    assert await search.get_urls() == {'https://one.example.com', 'https://two.example.com'}
    assert report.status == 'completed'
    assert report.stop_reason == 'result-limit'


@pytest.mark.asyncio
async def test_malformed_preferred_spec_does_not_discard_later_valid_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_urls = [
        'https://api.apis.guru/v2/specs/example.com/a/1.0/openapi.json',
        'https://api.apis.guru/v2/specs/example.com/b/1.0/openapi.json',
    ]
    directory = {
        f'example.com:{service}': {
            'preferred': '1.0',
            'versions': {
                '1.0': {
                    'info': {'x-providerName': 'example.com'},
                    'swaggerUrl': spec_url,
                }
            },
        }
        for service, spec_url in zip(('a', 'b'), spec_urls, strict=True)
    }
    responses = [
        FetcherResponse(body={'apis': directory}, status=200, headers={}),
        FetcherResponse(body=['not-an-openapi-object'], status=200, headers={}),
        FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://api.example.com/v2'}]},
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_malformed_spec_fields_preserve_scoped_results_as_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/1.0/openapi.json'
    responses = [
        FetcherResponse(
            body={
                'example.com': {
                    'preferred': '1.0',
                    'versions': {
                        '1.0': {
                            'info': {'x-providerName': 'example.com'},
                            'swaggerUrl': spec_url,
                        }
                    },
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={
                'openapi': '3.0.3',
                'servers': [{'url': 'https://api.example.com/v1'}, None, {'url': 7}],
                'info': {'contact': {'email': 7}},
            },
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_emails() == set()
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_malformed_matching_directory_entry_is_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(
            body={
                'apis': {
                    'example.com:broken': {'preferred': '1.0', 'versions': {}},
                    'notexample.com:ignored': None,
                }
            },
            status=200,
            headers={},
        )

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_directory_entry_scan_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    spec_urls = [f'https://api.apis.guru/v2/specs/example.com/service-{index}/1.0/openapi.json' for index in range(2)]
    directory = {
        f'example.com:service-{index}': {
            'preferred': '1.0',
            'versions': {
                '1.0': {
                    'info': {'x-providerName': 'example.com'},
                    'swaggerUrl': spec_url,
                }
            },
        }
        for index, spec_url in enumerate(spec_urls)
    }
    responses = [
        FetcherResponse(body={'apis': directory}, status=200, headers={}),
        FetcherResponse(
            body={'openapi': '3.0.3', 'servers': [{'url': 'https://api.example.com'}]},
            status=200,
            headers={},
        ),
    ]
    requested_urls: list[str] = []

    async def fake_fetch(**kwargs: Any) -> FetcherResponse:
        requested_urls.append(kwargs['url'])
        return responses.pop(0)

    monkeypatch.setattr(apisguru.SearchApisGuru, 'MAX_DIRECTORY_ENTRIES', 1)
    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert requested_urls == ['https://api.apis.guru/v2/example.com.json', spec_urls[0]]
    assert await search.get_hostnames() == {'api.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'directory-entry-limit'


@pytest.mark.asyncio
async def test_openapi_two_host_is_retained_without_inventing_a_server_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/1.0/swagger.json'
    responses = [
        FetcherResponse(
            body={
                'example.com': {
                    'preferred': '1.0',
                    'versions': {
                        '1.0': {
                            'info': {'x-providerName': 'example.com'},
                            'swaggerUrl': spec_url,
                        }
                    },
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'swagger': '2.0', 'host': 'api.example.com', 'basePath': '/v1'},
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == {'api.example.com'}
    assert await search.get_urls() == set()
    assert report is None


@pytest.mark.parametrize(
    ('response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=401, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=503, headers={}), 'failed', 'http-503'),
        (FetcherResponse(body=[], status=200, headers={}), 'failed', 'invalid-response'),
        (FetcherResponse(body={'apis': []}, status=200, headers={}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_directory_failures_are_attributed(
    monkeypatch: pytest.MonkeyPatch,
    response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return response

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert report.status == execution_status
    assert report.stop_reason == stop_reason


@pytest.mark.asyncio
async def test_missing_provider_is_completed_with_no_results(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return FetcherResponse(body={}, status=404, headers={})

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert report is None


@pytest.mark.parametrize('target', ['example.com/path', 'localhost', '192.0.2.1', 'straße.de'])
@pytest.mark.asyncio
async def test_invalid_target_is_rejected_before_provider_request(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise AssertionError('provider must not be contacted')

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru(target, limit=5)

    report = await search.process()

    assert report.status == 'failed'
    assert report.stop_reason == 'invalid-target'


@pytest.mark.asyncio
async def test_malformed_contact_email_is_not_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/1.0/openapi.json'
    responses = [
        FetcherResponse(
            body={
                'example.com': {
                    'preferred': '1.0',
                    'versions': {
                        '1.0': {
                            'info': {'x-providerName': 'example.com'},
                            'swaggerUrl': spec_url,
                        }
                    },
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={'openapi': '3.0.3', 'info': {'contact': {'email': '<x>@example.com'}}},
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_emails() == set()
    assert report is None


@pytest.mark.parametrize(
    'url',
    [
        'https://api.apis.guru/v2/specs/../../admin.json',
        'https://api.apis.guru/v2/specs/%2e%2e/%2e%2e/admin.json',
        'https://api.apis.guru/v2/specs/example.com/%5c..%5cadmin.json',
        'https://api.apis.guru/v2/specs/example.com/\x1b.json',
        f'https://api.apis.guru/v2/specs/example.com/{"x" * 4096}.json',
    ],
)
def test_spec_url_rejects_noncanonical_paths(url: str) -> None:
    assert apisguru.SearchApisGuru._spec_url(url) is None


@pytest.mark.parametrize(
    'url',
    [
        'https://api.example.com/path with space',
        'https://api.example.com/\x1b[31m',
        'https://api.example.com/\ud800',
        f'https://api.example.com/{"x" * 4096}',
    ],
)
def test_url_projection_rejects_unsafe_or_oversized_text(url: str) -> None:
    search = apisguru.SearchApisGuru('example.com', limit=5)

    search._add_url(url)

    assert search.totalhosts == set()
    assert search.urls == set()


def test_quoted_contact_email_is_reconstructed_without_losing_required_quotes() -> None:
    search = apisguru.SearchApisGuru('example.com', limit=5)

    search._add_email('"A B"@Example.com')

    assert search.totalemails == {'"a b"@example.com'}


def test_oversized_contact_email_is_not_retained() -> None:
    search = apisguru.SearchApisGuru('example.com', limit=5)

    search._add_email(f'{"a" * 65}@example.com')

    assert search.totalemails == set()


@pytest.mark.asyncio
async def test_directory_response_byte_limit_is_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise ResponseStreamError('response-limit')

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert report.status == 'failed'
    assert report.stop_reason == 'response-limit'


@pytest.mark.asyncio
async def test_apex_only_hostname_is_not_counted_as_a_retained_result(monkeypatch: pytest.MonkeyPatch) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/1.0/swagger.json'
    responses = [
        FetcherResponse(
            body={
                'apis': {
                    'example.com': {
                        'info': {'x-providerName': 'example.com'},
                        'swaggerUrl': spec_url,
                        'openapiVer': '2.0',
                    }
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(body={'swagger': '2.0', 'host': 'example.com'}, status=200, headers={}),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == set()
    assert report is None


@pytest.mark.asyncio
async def test_scalar_results_are_hard_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/1.0/openapi.json'
    responses = [
        FetcherResponse(
            body={
                'apis': {
                    'example.com': {
                        'info': {'x-providerName': 'example.com'},
                        'swaggerUrl': spec_url,
                        'openapiVer': '3.0.3',
                    }
                }
            },
            status=200,
            headers={},
        ),
        FetcherResponse(
            body={
                'openapi': '3.0.3',
                'servers': [
                    {'url': 'https://one.example.com'},
                    {'url': 'https://two.example.com'},
                ],
            },
            status=200,
            headers={},
        ),
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.SearchApisGuru, 'MAX_RESULTS_PER_ROUTE', 1)
    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert await search.get_hostnames() == {'one.example.com'}
    assert await search.get_urls() == {'https://one.example.com'}
    assert report.status == 'failed'
    assert report.stop_reason == 'result-cap'


@pytest.mark.asyncio
async def test_cancellation_is_attributed_and_propagated(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        raise asyncio.CancelledError

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    with pytest.raises(asyncio.CancelledError):
        await search.process()


@pytest.mark.asyncio
async def test_runtime_limit_is_attributed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(**_kwargs: Any) -> FetcherResponse:
        await asyncio.Event().wait()
        raise AssertionError('unreachable')

    monkeypatch.setattr(apisguru.SearchApisGuru, 'MAX_RUNTIME_SECONDS', 0.01)
    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=500)

    report = await search.process()

    assert report.status == 'failed'
    assert report.stop_reason == 'runtime-limit'


@pytest.mark.parametrize(
    ('spec_response', 'execution_status', 'stop_reason'),
    [
        (None, 'failed', 'transport-error'),
        (FetcherResponse(body={}, status=401, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=403, headers={}), 'failed', 'access-denied'),
        (FetcherResponse(body={}, status=429, headers={}), 'rate-limited', 'http-429'),
        (FetcherResponse(body={}, status=502, headers={}), 'failed', 'http-502'),
        (FetcherResponse(body='not-json', status=200, headers={}), 'failed', 'invalid-response'),
    ],
)
@pytest.mark.asyncio
async def test_preferred_spec_failures_are_attributed(
    monkeypatch: pytest.MonkeyPatch,
    spec_response: FetcherResponse | None,
    execution_status: str,
    stop_reason: str,
) -> None:
    spec_url = 'https://api.apis.guru/v2/specs/example.com/1.0/openapi.json'
    responses = [
        FetcherResponse(
            body={
                'example.com': {
                    'preferred': '1.0',
                    'versions': {
                        '1.0': {
                            'info': {'x-providerName': 'example.com'},
                            'swaggerUrl': spec_url,
                        }
                    },
                }
            },
            status=200,
            headers={},
        ),
        spec_response,
    ]

    async def fake_fetch(**_kwargs: Any) -> FetcherResponse | None:
        return responses.pop(0)

    monkeypatch.setattr(apisguru.AsyncFetcher, 'fetch_json', fake_fetch)
    search = apisguru.SearchApisGuru('example.com', limit=5)

    report = await search.process()

    assert report.status == execution_status
    assert report.stop_reason == stop_reason


pytestmark = pytest.mark.provider_contract('apis-guru')
