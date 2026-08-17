from typing import TYPE_CHECKING

from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from theHarvester.lib.source_execution import SourceReportStatus


def provider_http_error(response: object) -> tuple[SourceReportStatus, str] | None:
    """Classify transport and HTTP failures shared by provider adapters."""
    if not isinstance(response, FetcherResponse):
        return 'failed', 'transport-error'
    if response.status in {401, 403}:
        return 'failed', 'access-denied'
    if response.status == 429:
        return 'rate-limited', 'http-429'
    if not 200 <= response.status < 300:
        return 'failed', f'http-{response.status}'
    return None
