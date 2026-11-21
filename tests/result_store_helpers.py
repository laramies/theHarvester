"""Result-store doubles for tests that replace ``theHarvester.__main__.ResultStore``."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from theHarvester.lib.completed_result import CompletedResult


class NoopResultStore:
    """Accept every result-store call without persisting anything."""

    async def initialize(self) -> None:
        return None

    async def record_observations(self, *_args: object) -> None:
        return None

    async def save_run(self, _result: CompletedResult) -> None:
        return None


def recording_result_store(
    saved: list[CompletedResult],
    *,
    legacy_writes: list[tuple[object, ...]] | None = None,
) -> type[NoopResultStore]:
    """Return a store class that appends saved runs and, optionally, legacy observation writes."""

    class RecordingResultStore(NoopResultStore):
        async def record_observations(self, *args: object) -> None:
            if legacy_writes is not None:
                legacy_writes.append(args)

        async def save_run(self, result: CompletedResult) -> None:
            saved.append(result)

    return RecordingResultStore
