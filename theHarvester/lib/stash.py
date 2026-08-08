import datetime
import logging
import os
from collections.abc import Iterable
from typing import cast
from uuid import UUID

from sqlalchemy import func, select

from theHarvester.lib.completed_result import CompletedResult, ResultKind
from theHarvester.lib.database import (
    CompletedResultItemRecord,
    CompletedRunRecord,
    DiscoveryObservationRecord,
    initialize_stash_schema,
    sqlite_session,
)

logger = logging.getLogger(__name__)


db_path = os.path.expanduser('~/.local/share/theHarvester')

if not os.path.isdir(db_path):
    os.makedirs(db_path)


class StashManager:
    def __init__(self) -> None:
        self.db = os.path.join(db_path, 'stash.sqlite')

    async def do_init(self) -> None:
        await initialize_stash_schema(self.db)

    async def store_completed_result(self, result: CompletedResult) -> None:
        run_id = str(result.run_id)
        async with sqlite_session(self.db) as session:
            session.add(
                CompletedRunRecord(
                    run_id=run_id,
                    target=result.target,
                    started_at=result.started_at.isoformat(),
                    completed_at=result.completed_at.isoformat(),
                )
            )
            await session.flush()
            session.add_all(
                CompletedResultItemRecord(run_id=run_id, position=position, kind=kind, value=value)
                for position, (kind, value) in enumerate(result.results)
            )
            await session.commit()

    async def load_completed_result(self, run_id: UUID) -> CompletedResult:
        async with sqlite_session(self.db) as session:
            parent = await session.get(CompletedRunRecord, str(run_id))
            if parent is None:
                raise LookupError(f'completed result not found: {run_id}')
            rows = (
                await session.scalars(
                    select(CompletedResultItemRecord)
                    .where(CompletedResultItemRecord.run_id == str(run_id))
                    .order_by(CompletedResultItemRecord.position)
                )
            ).all()
        return CompletedResult(
            run_id=UUID(parent.run_id),
            target=parent.target,
            started_at=datetime.datetime.fromisoformat(parent.started_at),
            completed_at=datetime.datetime.fromisoformat(parent.completed_at),
            results=tuple((cast('ResultKind', row.kind), row.value) for row in rows),
        )

    async def list_completed_results(self, *, limit: int = 50) -> list[dict[str, object]]:
        async with sqlite_session(self.db) as session:
            rows = (
                await session.execute(
                    select(CompletedRunRecord, func.count(CompletedResultItemRecord.position))
                    .outerjoin(
                        CompletedResultItemRecord,
                        CompletedResultItemRecord.run_id == CompletedRunRecord.run_id,
                    )
                    .group_by(CompletedRunRecord.run_id)
                    .order_by(
                        func.julianday(CompletedRunRecord.completed_at).desc(),
                        CompletedRunRecord.run_id.desc(),
                    )
                    .limit(limit)
                )
            ).all()
        return [
            {
                'run_id': run.run_id,
                'target': run.target,
                'started_at': run.started_at,
                'completed_at': run.completed_at,
                'result_count': result_count,
            }
            for run, result_count in rows
        ]

    async def store(self, domain: str, resource: str, res_type: ResultKind, source: str) -> None:
        try:
            async with sqlite_session(self.db) as session:
                session.add(
                    DiscoveryObservationRecord(
                        domain=domain,
                        resource=resource,
                        kind=res_type,
                        discovered_on=datetime.date.today(),
                        source=source,
                    )
                )
                await session.commit()
        except Exception as error:
            logger.info(f'Unexpected error while storing result: {error}')

    async def store_all(self, domain: str, results: Iterable[object], res_type: ResultKind, source: str) -> None:
        try:
            async with sqlite_session(self.db) as session:
                session.add_all(
                    DiscoveryObservationRecord(
                        domain=domain,
                        resource=str(resource),
                        kind=res_type,
                        discovered_on=datetime.date.today(),
                        source=source,
                    )
                    for resource in results
                )
                await session.commit()
        except Exception as error:
            logger.info(f'Unexpected error while storing result: {error}')
