import pytest

from theHarvester.discovery.provider_response import http_status_error, provider_http_error
from theHarvester.lib.core import FetcherResponse


@pytest.mark.parametrize(
    ('status', 'expected'),
    [
        (200, None),
        (204, None),
        (401, ('failed', 'access-denied')),
        (403, ('failed', 'access-denied')),
        (429, ('rate-limited', 'http-429')),
        (302, ('failed', 'http-302')),
        (404, ('failed', 'http-404')),
        (503, ('failed', 'http-503')),
    ],
)
def test_http_status_error_classifies_shared_provider_statuses(status: int, expected: tuple[str, str] | None) -> None:
    assert http_status_error(status) == expected
    assert provider_http_error(FetcherResponse(body=None, status=status, headers={})) == expected


@pytest.mark.parametrize('response', [None, 'body-without-metadata'])
def test_provider_http_error_treats_a_missing_response_as_a_transport_error(response: object) -> None:
    assert provider_http_error(response) == ('failed', 'transport-error')
