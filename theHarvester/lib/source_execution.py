from dataclasses import dataclass
from typing import Literal

SourceReportStatus = Literal['completed', 'partial', 'failed', 'rate-limited']


@dataclass(frozen=True, slots=True)
class SourceExecutionReport:
    """Provider-specific terminal details for one source execution."""

    status: SourceReportStatus
    stop_reason: str

    def __post_init__(self) -> None:
        if self.status not in {'completed', 'partial', 'failed', 'rate-limited'}:
            raise ValueError(f'adapter cannot report execution status {self.status!r}')
        if not isinstance(self.stop_reason, str) or not self.stop_reason.strip():
            raise ValueError('adapter stop reason must not be empty')
