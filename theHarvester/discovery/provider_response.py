from typing import TYPE_CHECKING

from theHarvester.lib.core import FetcherResponse

if TYPE_CHECKING:
    from theHarvester.lib.source_execution import SourceReportStatus


def http_status_error(status: int) -> tuple[SourceReportStatus, str] | None:
    """Classify an unsuccessful HTTP status shared by provider adapters."""
    if status in {401, 403}:
        return 'failed', 'access-denied'
    if status == 429:
        return 'rate-limited', 'http-429'
    if not 200 <= status < 300:
        return 'failed', f'http-{status}'
    return None


def provider_http_error(response: object) -> tuple[SourceReportStatus, str] | None:
    """Classify transport and HTTP failures shared by provider adapters."""
    if not isinstance(response, FetcherResponse):
        return 'failed', 'transport-error'
    return http_status_error(response.status)
