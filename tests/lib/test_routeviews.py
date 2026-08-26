from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import theHarvester.lib.routeviews as routeviews_module
from theHarvester.lib.core import FetcherResponse, ResponseStreamError
from theHarvester.lib.network_evidence import (
    BgpRouteObservation,
    PrefixOriginObservation,
    RpkiValidationObservation,
)
from theHarvester.lib.routeviews import RouteViewsCancelled, enrich_routeviews


def install_runtime(
    monkeypatch,
    responses: list[FetcherResponse | BaseException],
    *,
    sessions: list[object] | None = None,
):
    calls: list[tuple[str, dict[str, Any]]] = []
    elapsed = [0.0]
    collected_at = datetime(2026, 8, 11, 12, tzinfo=UTC)
    shared_session = object()

    async def fetch_json(url: str, **kwargs: Any) -> FetcherResponse:
        session = kwargs.pop('session', None)
        if sessions is not None:
            sessions.append(session)
        calls.append((url, kwargs))
        response = responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    @asynccontextmanager
    async def open_session(**_kwargs: Any):
        yield shared_session

    async def sleep(seconds: float) -> None:
        elapsed[0] += seconds

    monkeypatch.setattr(routeviews_module, '_fetch_json', fetch_json)
    monkeypatch.setattr(routeviews_module.AsyncFetcher, 'open_session', staticmethod(open_session))
    monkeypatch.setattr(routeviews_module, '_sleep', sleep)
    monkeypatch.setattr(routeviews_module, '_monotonic', lambda: elapsed[0])
    monkeypatch.setattr(routeviews_module, '_now', lambda: collected_at + timedelta(seconds=elapsed[0]))
    return calls, elapsed


def response(body: object, status: int = 200, headers: dict[str, str] | None = None) -> FetcherResponse:
    return FetcherResponse(body=body, status=status, headers=headers or {})


@pytest.mark.asyncio
async def test_routeviews_collects_asn_prefixes_and_rpki_without_prefix_fanout(monkeypatch) -> None:
    calls, elapsed = install_runtime(
        monkeypatch,
        [
            response(['192.0.2.0/24', '2001:db8::/32', '192.0.2.0/24']),
            response(
                {
                    '64500': {
                        'prefix': [
                            {'192.0.2.0/24': 'valid'},
                            {'2001:db8::/32': 'notfound'},
                        ],
                        'timestamp': '2026-08-11T12:00:00+00:00',
                    }
                }
            ),
        ],
    )

    result = await enrich_routeviews(['64500'], [])

    assert result.status == 'completed'
    assert result.stop_reason is None
    assert result.request_count == 2
    assert result.prefixes == ('192.0.2.0/24', '2001:db8::/32')
    assert result.origin_asns == ('AS64500',)
    assert sum(isinstance(item, PrefixOriginObservation) for item in result.observations) == 2
    assert {(item.prefix, item.state) for item in result.observations if isinstance(item, RpkiValidationObservation)} == {
        ('192.0.2.0/24', 'valid'),
        ('2001:db8::/32', 'not-found'),
    }
    assert [url for url, _kwargs in calls] == [
        'https://api.routeviews.org/guest/asn/64500',
        'https://api.routeviews.org/guest/rpki',
    ]
    assert calls[1][1]['params'] == {'asn': '64500'}
    assert elapsed[0] == 1.0


@pytest.mark.asyncio
async def test_routeviews_uses_configured_key_for_authenticated_access(monkeypatch) -> None:
    calls, elapsed = install_runtime(
        monkeypatch,
        [
            response(['192.0.2.0/24']),
            response({'64500': None}),
        ],
    )

    result = await enrich_routeviews(['AS64500'], [], api_key='routeviews-key')

    assert result.status == 'completed'
    assert [url for url, _kwargs in calls] == [
        'https://api.routeviews.org/asn/64500',
        'https://api.routeviews.org/rpki',
    ]
    assert [kwargs['headers'] for _url, kwargs in calls] == [
        {'Api-Key': 'routeviews-key'},
        {'Api-Key': 'routeviews-key'},
    ]
    assert elapsed[0] == 0.1


@pytest.mark.asyncio
async def test_routeviews_reuses_one_session_for_every_request(monkeypatch) -> None:
    sessions: list[object] = []
    _calls, _elapsed = install_runtime(
        monkeypatch,
        [
            response(['192.0.2.0/24']),
            response({'64500': None}),
        ],
        sessions=sessions,
    )

    result = await enrich_routeviews(['AS64500'], [], proxy=True)

    assert result.status == 'completed'
    assert len(sessions) == 2
    assert sessions[0] is not None
    assert sessions[0] is sessions[1]


@pytest.mark.asyncio
async def test_routeviews_reports_session_construction_failure(monkeypatch) -> None:
    @asynccontextmanager
    async def failed_open_session(**_kwargs: Any):
        raise ResponseStreamError('transport-error')
        yield

    monkeypatch.setattr(routeviews_module.AsyncFetcher, 'open_session', failed_open_session)

    result = await enrich_routeviews(['AS64500'], [], proxy=True)

    assert result.status == 'failed'
    assert result.error_type == 'ResponseStreamError'
    assert result.stop_reason == 'transport-error'


@pytest.mark.asyncio
async def test_routeviews_invalid_configured_key_fails_without_guest_downgrade(monkeypatch) -> None:
    calls, _elapsed = install_runtime(monkeypatch, [response(None, status=401)])

    result = await enrich_routeviews(['AS64500'], [], api_key='invalid-key')

    assert result.status == 'failed'
    assert result.stop_reason == 'http-401'
    assert calls == [
        (
            'https://api.routeviews.org/asn/64500',
            {
                'params': '',
                'headers': {'Api-Key': 'invalid-key'},
                'request_timeout': 30,
            },
        )
    ]


@pytest.mark.asyncio
async def test_routeviews_uses_authenticated_access_for_prefix_seeds(monkeypatch) -> None:
    calls, elapsed = install_runtime(monkeypatch, [response([]), response([])])

    result = await enrich_routeviews(
        [],
        ['192.0.2.0/24', '198.51.100.0/24'],
        api_key='routeviews-key',
    )

    assert result.status == 'completed'
    assert calls == [
        (
            'https://api.routeviews.org/prefix/192.0.2.0%2F24',
            {
                'params': {'strict-match': 'yes'},
                'headers': {'Api-Key': 'routeviews-key'},
                'request_timeout': 30,
            },
        ),
        (
            'https://api.routeviews.org/prefix/198.51.100.0%2F24',
            {
                'params': {'strict-match': 'yes'},
                'headers': {'Api-Key': 'routeviews-key'},
                'request_timeout': 30,
            },
        ),
    ]
    assert elapsed[0] == 0.1


@pytest.mark.asyncio
async def test_routeviews_collects_moas_routes_and_strict_prefix_evidence(monkeypatch) -> None:
    calls, _elapsed = install_runtime(
        monkeypatch,
        [
            response(
                [
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64500,
                        'rpki_state': 'valid',
                        'rpki_roas': None,
                        'reporting_peers': [
                            {
                                'peer_asn': 64496,
                                'peer_addr': '198.51.100.1',
                                'collector': 'route-views.example',
                                'as_path': ' 64496 64500 ',
                                'communities': '',
                                'timestamp': '2026-08-11T11:59:00Z',
                            }
                        ],
                    },
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64501,
                        'rpki_state': 'not-found',
                        'rpki_roas': None,
                        'reporting_peers': [],
                    },
                ]
            )
        ],
    )

    result = await enrich_routeviews([], ['192.0.2.7/24'])

    assert result.status == 'completed'
    assert result.prefixes == ('192.0.2.0/24',)
    assert result.origin_asns == ('AS64500', 'AS64501')
    route = next(item for item in result.observations if isinstance(item, BgpRouteObservation))
    assert route.as_path == ' 64496 64500 '
    assert route.communities == ''
    assert {item.state for item in result.observations if isinstance(item, RpkiValidationObservation)} == {'valid', 'not-found'}
    assert calls == [
        (
            'https://api.routeviews.org/guest/prefix/192.0.2.0%2F24',
            {
                'params': {'strict-match': 'yes'},
                'request_timeout': 30,
            },
        )
    ]


@pytest.mark.asyncio
async def test_routeviews_uses_longest_match_for_known_ip(monkeypatch) -> None:
    calls, _elapsed = install_runtime(
        monkeypatch,
        [
            response(
                [
                    {
                        'prefix': '0.0.0.0/0',
                        'origin_asn': 64500,
                        'rpki_state': 'not-found',
                        'reporting_peers': [],
                    },
                    {
                        'prefix': '192.0.0.0/16',
                        'origin_asn': 64501,
                        'rpki_state': 'valid',
                        'reporting_peers': [],
                    },
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64502,
                        'rpki_state': 'valid',
                        'reporting_peers': [],
                    },
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64503,
                        'rpki_state': 'not-found',
                        'reporting_peers': [],
                    },
                ]
            )
        ],
    )

    result = await enrich_routeviews([], ['192.0.2.7'])

    assert result.status == 'completed'
    assert result.stop_reason is None
    assert result.prefixes == ('192.0.2.0/24',)
    assert result.origin_asns == ('AS64502', 'AS64503')
    assert calls[0][0] == 'https://api.routeviews.org/guest/prefix/192.0.2.7%2F32'
    assert calls[0][1]['params'] == ''


@pytest.mark.asyncio
async def test_routeviews_deduplicates_shared_prefix_evidence_across_ip_seeds(monkeypatch) -> None:
    shared_prefix = [
        {
            'prefix': '192.0.2.0/24',
            'origin_asn': 64500,
            'rpki_state': 'valid',
            'reporting_peers': [
                {
                    'peer_asn': 64496,
                    'peer_addr': '198.51.100.1',
                    'collector': 'route-views.example',
                    'as_path': '64496 64500',
                    'communities': '64500:1',
                    'timestamp': '2026-08-11T11:59:00Z',
                }
            ],
        }
    ]
    install_runtime(monkeypatch, [response(shared_prefix), response(shared_prefix)])

    result = await enrich_routeviews([], ['192.0.2.7', '192.0.2.8'])

    assert result.request_count == 2
    assert result.prefixes == ('192.0.2.0/24',)
    assert sum(isinstance(item, PrefixOriginObservation) for item in result.observations) == 1
    assert sum(isinstance(item, BgpRouteObservation) for item in result.observations) == 1
    assert sum(isinstance(item, RpkiValidationObservation) for item in result.observations) == 1


@pytest.mark.asyncio
async def test_routeviews_records_each_response_collection_time(monkeypatch) -> None:
    install_runtime(
        monkeypatch,
        [
            response([]),
            response(
                [
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64500,
                        'rpki_state': 'valid',
                        'reporting_peers': [
                            {
                                'peer_asn': 64496,
                                'peer_addr': '198.51.100.1',
                                'collector': 'route-views.example',
                                'as_path': '64496 64500',
                                'communities': '',
                                'timestamp': '2026-08-11T12:00:00.500Z',
                            }
                        ],
                    }
                ]
            ),
        ],
    )

    result = await enrich_routeviews([], ['192.0.2.7', '192.0.2.8'])

    route = next(item for item in result.observations if isinstance(item, BgpRouteObservation))
    assert route.collected_at == datetime(2026, 8, 11, 12, 0, 1, tzinfo=UTC)


@pytest.mark.asyncio
async def test_routeviews_accepts_null_rpki_as_no_data(monkeypatch) -> None:
    install_runtime(monkeypatch, [response([]), response({'64500': None})])

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'completed'
    assert result.stop_reason == 'no-results'
    assert result.observations == ()


@pytest.mark.asyncio
async def test_routeviews_reports_rate_limit_without_parsing_error_body(monkeypatch) -> None:
    install_runtime(monkeypatch, [response(None, status=429, headers={'retry-after': '60'})])

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'rate-limited'
    assert result.error_type == 'HTTPStatusError'
    assert result.stop_reason == 'http-429'
    assert result.request_count == 1


@pytest.mark.asyncio
async def test_routeviews_reports_terminal_rate_limit_after_recoverable_error(monkeypatch) -> None:
    install_runtime(monkeypatch, [response(None, status=503), response(None, status=429)])

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'rate-limited'
    assert result.error_count == 2
    assert result.error_type == 'HTTPStatusError'
    assert result.stop_reason == 'http-429'


@pytest.mark.asyncio
async def test_routeviews_preserves_valid_prefixes_before_malformed_response(monkeypatch) -> None:
    install_runtime(monkeypatch, [response(['192.0.2.0/24']), response({'64500': {'prefix': 'bad'}})])

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'partial'
    assert result.prefixes == ('192.0.2.0/24',)
    assert result.error_type == 'ValueError'
    assert result.stop_reason == 'invalid-response'
    assert result.error_count == 1


@pytest.mark.asyncio
async def test_routeviews_continues_after_one_seed_fails(monkeypatch) -> None:
    install_runtime(
        monkeypatch,
        [
            response(None, status=503),
            response({'64500': None}),
            response(['198.51.100.0/24']),
            response({'64501': None}),
        ],
    )

    result = await enrich_routeviews(['AS64500', 'AS64501'], [])

    assert result.status == 'partial'
    assert result.prefixes == ('198.51.100.0/24',)
    assert result.origin_asns == ('AS64501',)
    assert result.request_count == 4
    assert result.error_count == 1
    assert result.error_type == 'HTTPStatusError'
    assert result.stop_reason == 'http-503'


@pytest.mark.asyncio
async def test_routeviews_rejects_prefix_evidence_unrelated_to_requested_seed(monkeypatch) -> None:
    install_runtime(
        monkeypatch,
        [
            response(
                [
                    {
                        'prefix': '203.0.113.0/24',
                        'origin_asn': 64500,
                        'rpki_state': 'not-found',
                        'rpki_roas': None,
                        'reporting_peers': [],
                    },
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64501,
                        'rpki_state': 'valid',
                        'rpki_roas': None,
                        'reporting_peers': [],
                    },
                ]
            )
        ],
    )

    result = await enrich_routeviews([], ['192.0.2.7'])

    assert result.status == 'partial'
    assert result.prefixes == ('192.0.2.0/24',)
    assert result.origin_asns == ('AS64501',)
    assert result.error_count == 1
    assert result.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_routeviews_keeps_routes_when_rpki_or_a_sibling_peer_is_invalid(monkeypatch) -> None:
    install_runtime(
        monkeypatch,
        [
            response(
                [
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64500,
                        'rpki_state': None,
                        'rpki_roas': None,
                        'reporting_peers': [
                            {'peer_asn': 'bad'},
                            {
                                'peer_asn': 64496,
                                'peer_addr': '198.51.100.1',
                                'collector': 'route-views.example',
                                'as_path': '64496 64500',
                                'communities': '',
                                'timestamp': '2026-08-11T11:59:00Z',
                            },
                        ],
                    }
                ]
            )
        ],
    )

    result = await enrich_routeviews([], ['192.0.2.0/24'])

    assert result.status == 'partial'
    assert result.prefixes == ('192.0.2.0/24',)
    assert sum(isinstance(item, BgpRouteObservation) for item in result.observations) == 1
    assert not any(isinstance(item, RpkiValidationObservation) for item in result.observations)
    assert result.error_count == 2
    assert result.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_routeviews_cancellation_carries_completed_prefix_evidence(monkeypatch) -> None:
    cancelled = asyncio.CancelledError()
    install_runtime(monkeypatch, [response(['192.0.2.0/24']), cancelled])

    with pytest.raises(RouteViewsCancelled) as raised:
        await enrich_routeviews(['AS64500'], [])

    assert raised.value.result.status == 'partial'
    assert raised.value.result.prefixes == ('192.0.2.0/24',)
    assert raised.value.result.error_type == 'CancelledError'
    assert raised.value.result.stop_reason == 'cancelled'


@pytest.mark.asyncio
async def test_routeviews_cancellation_overrides_an_earlier_recoverable_error(monkeypatch) -> None:
    install_runtime(monkeypatch, [response(None, status=503), asyncio.CancelledError()])

    with pytest.raises(RouteViewsCancelled) as raised:
        await enrich_routeviews(['AS64500'], [])

    assert raised.value.result.error_count == 2
    assert raised.value.result.error_type == 'CancelledError'
    assert raised.value.result.stop_reason == 'cancelled'


@pytest.mark.asyncio
async def test_routeviews_fixed_request_budget_preserves_prefix(monkeypatch) -> None:
    install_runtime(monkeypatch, [response(['192.0.2.0/24'])])
    monkeypatch.setattr(routeviews_module, 'MAX_ROUTEVIEWS_REQUESTS', 1)

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'partial'
    assert result.prefixes == ('192.0.2.0/24',)
    assert result.error_type == 'RouteViewsLimitError'
    assert result.stop_reason == 'request-limit'


@pytest.mark.asyncio
async def test_routeviews_runtime_budget_preserves_prefix(monkeypatch) -> None:
    install_runtime(monkeypatch, [response(['192.0.2.0/24'])])
    monkeypatch.setattr(routeviews_module, 'MAX_ROUTEVIEWS_RUNTIME_SECONDS', 0.5)

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'partial'
    assert result.prefixes == ('192.0.2.0/24',)
    assert result.stop_reason == 'runtime-limit'


@pytest.mark.asyncio
async def test_routeviews_per_prefix_evidence_limit_returns_partial(monkeypatch) -> None:
    install_runtime(
        monkeypatch,
        [
            response(
                [
                    {
                        'prefix': '192.0.2.0/24',
                        'origin_asn': 64500,
                        'rpki_state': 'valid',
                        'rpki_roas': None,
                        'reporting_peers': [],
                    }
                ]
            )
        ],
    )
    monkeypatch.setattr(routeviews_module, 'MAX_NETWORK_OBSERVATIONS_PER_PREFIX', 1)

    result = await enrich_routeviews([], ['192.0.2.0/24'])

    assert result.status == 'partial'
    assert result.prefixes == ('192.0.2.0/24',)
    assert len(result.observations) == 1
    assert result.stop_reason == 'result-limit'


@pytest.mark.asyncio
async def test_routeviews_cumulative_provider_budget_stops_before_next_request(monkeypatch) -> None:
    calls, _elapsed = install_runtime(monkeypatch, [response(['192.0.2.0/24'])])
    monkeypatch.setattr(routeviews_module, 'MAX_ROUTEVIEWS_RUN_JSON_BYTES', 1)

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'failed'
    assert result.stop_reason == 'result-limit'
    assert result.request_count == 1
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_routeviews_rejects_timestamp_that_overflows_utc_conversion(monkeypatch) -> None:
    install_runtime(
        monkeypatch,
        [
            response([]),
            response({'64500': {'prefix': [], 'timestamp': '0001-01-01T00:00:00+01:00'}}),
        ],
    )

    result = await enrich_routeviews(['AS64500'], [])

    assert result.status == 'failed'
    assert result.error_count == 1
    assert result.stop_reason == 'invalid-response'


@pytest.mark.asyncio
async def test_routeviews_skips_when_inputs_are_empty_or_invalid(monkeypatch) -> None:
    calls, _elapsed = install_runtime(monkeypatch, [])

    result = await enrich_routeviews(['not-an-asn'], ['not-an-ip'])

    assert result.status == 'skipped'
    assert result.stop_reason == 'no-input'
    assert result.request_count == 0
    assert calls == []


@pytest.mark.asyncio
async def test_routeviews_bounds_input_before_scheduling_requests(monkeypatch) -> None:
    calls, _elapsed = install_runtime(monkeypatch, [response([]), response({'64500': None})])
    monkeypatch.setattr(routeviews_module, 'MAX_ROUTEVIEWS_INPUT_ITEMS', 1)

    result = await enrich_routeviews(['AS64500', 'AS64501'], [])

    assert result.status == 'failed'
    assert result.error_count == 1
    assert result.stop_reason == 'input-limit'
    assert len(calls) == 2
