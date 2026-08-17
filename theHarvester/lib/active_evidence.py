from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Self

from theHarvester.lib.evidence_types import EXECUTION_STATUSES, RESULT_KINDS, ExecutionStatus, ResultKind, format_utc
from theHarvester.lib.result_values import normalize_result_value

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


@dataclass(frozen=True, order=True, slots=True)
class ActionObservation:
    kind: ResultKind
    value: str

    def __post_init__(self) -> None:
        if self.kind not in RESULT_KINDS:
            raise ValueError(f'unknown action observation kind: {self.kind}')
        if self.kind == 'screenshot':
            raise ValueError('screenshots must be stored as artifacts, not results')
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError('action observation value must be a non-empty string')
        object.__setattr__(self, 'value', normalize_result_value(self.kind, self.value))


@dataclass(frozen=True, order=True, slots=True)
class ArtifactReference:
    kind: str
    subject_kind: ResultKind
    subject_value: str
    path: str
    media_type: str
    size_bytes: int
    sha256: str
    created_at: datetime

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value.strip() for value in (self.kind, self.path, self.media_type)):
            raise ValueError('artifact kind, path, and media type must not be empty')
        if (
            self.subject_kind not in RESULT_KINDS
            or self.subject_kind == 'screenshot'
            or not isinstance(self.subject_value, str)
            or not self.subject_value.strip()
        ):
            raise ValueError('artifact must reference a known non-empty result')
        if self.size_bytes < 0:
            raise ValueError('artifact size must not be negative')
        if (
            not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or any(character not in '0123456789abcdef' for character in self.sha256)
        ):
            raise ValueError('artifact sha256 must be 64 lowercase hexadecimal characters')
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError('artifact created_at must be timezone-aware')

    def to_dict(self) -> dict[str, object]:
        return {
            'kind': self.kind,
            'subject': {'kind': self.subject_kind, 'value': self.subject_value},
            'file': {
                'path': self.path,
                'media_type': self.media_type,
                'size_bytes': self.size_bytes,
                'sha256': self.sha256,
            },
            'created_at': format_utc(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class ActionExecution:
    action: str
    status: ExecutionStatus
    duration_ms: float
    observations: tuple[ActionObservation, ...] = ()
    artifacts: tuple[ArtifactReference, ...] = ()
    error_type: str | None = None
    stop_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, str) or not self.action.strip():
            raise ValueError('action must not be empty')
        if self.status not in EXECUTION_STATUSES:
            raise ValueError(f'unknown execution status: {self.status}')
        if self.duration_ms < 0:
            raise ValueError('execution duration must not be negative')
        if self.observations != tuple(sorted(set(self.observations))):
            raise ValueError('action observations must be deduplicated and sorted')
        if self.artifacts != tuple(sorted(set(self.artifacts))):
            raise ValueError('artifacts must be deduplicated and sorted')

    @classmethod
    def finish(
        cls,
        *,
        action: str,
        status: ExecutionStatus,
        duration_ms: float,
        groups: Mapping[ResultKind, Iterable[str]],
        artifacts: Iterable[ArtifactReference] = (),
        error_type: str | None = None,
        stop_reason: str | None = None,
    ) -> Self:
        observations: set[ActionObservation] = set()
        for kind, values in groups.items():
            if kind not in RESULT_KINDS:
                raise ValueError(f'unknown action observation kind: {kind}')
            if kind == 'screenshot':
                raise ValueError('screenshots must be stored as artifacts, not results')
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError('action observation value must be a non-empty string')
                observations.add(ActionObservation(kind, value.strip()))
        return cls(
            action=action.strip(),
            status=status,
            duration_ms=duration_ms,
            observations=tuple(sorted(observations)),
            artifacts=tuple(sorted(set(artifacts))),
            error_type=error_type,
            stop_reason=stop_reason,
        )

    @property
    def result_count(self) -> int:
        return len(self.observations)

    def to_dict(self) -> dict[str, str | float | int | None]:
        return {
            'action': self.action,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'error_type': self.error_type,
            'stop_reason': self.stop_reason,
        }


@dataclass(frozen=True, slots=True)
class ActiveEvidence:
    executions: tuple[ActionExecution, ...] = ()

    def __post_init__(self) -> None:
        actions = [execution.action for execution in self.executions]
        if len(actions) != len(set(actions)):
            raise ValueError('action executions must be unique')

    @property
    def observations(self) -> tuple[tuple[str, ActionObservation], ...]:
        return tuple((execution.action, observation) for execution in self.executions for observation in execution.observations)

    @property
    def artifacts(self) -> tuple[tuple[str, ArtifactReference], ...]:
        return tuple((execution.action, artifact) for execution in self.executions for artifact in execution.artifacts)


@dataclass(frozen=True, slots=True)
class ActionYield:
    action: str
    observed_result_count: int
    unique_result_count: int
    shared_result_count: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            'action': self.action,
            'observed_result_count': self.observed_result_count,
            'unique_result_count': self.unique_result_count,
            'shared_result_count': self.shared_result_count,
        }
