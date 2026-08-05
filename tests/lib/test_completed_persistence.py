from datetime import UTC, datetime
from uuid import UUID

import aiosqlite
import pytest

from theHarvester.lib.completed_result import CompletedResult
from theHarvester.lib.stash import StashManager


def completed_result(run_id: str = 'f047261c-0afb-4e18-89d5-28a7d977f51f') -> CompletedResult:
    return CompletedResult.finish(
        run_id=UUID(run_id),
        target='example.com',
        started_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 12, 1, tzinfo=UTC),
        groups={
            'hostname': ['api.example.com'],
            'ip-address': ['192.0.2.1'],
            'person': ['{"firstname":"Ada","lastname":"Lovelace"}'],
        },
    )


@pytest.mark.asyncio
async def test_completed_result_round_trip_preserves_legacy_results(tmp_path) -> None:
    manager = StashManager()
    manager.db = str(tmp_path / 'stash.sqlite')
    await manager.do_init()
    await manager.store('example.com', 'legacy.example.com', 'host', 'legacy-source')
    result = completed_result()

    await manager.store_completed_result(result)

    assert await manager.load_completed_result(result.run_id) == result
    async with aiosqlite.connect(manager.db) as db:
        legacy = await db.execute_fetchall('SELECT domain, resource, type, source FROM results')
    assert legacy == [('example.com', 'legacy.example.com', 'host', 'legacy-source')]


@pytest.mark.asyncio
async def test_completed_result_write_is_atomic_and_rejects_duplicate_run_id(tmp_path) -> None:
    manager = StashManager()
    manager.db = str(tmp_path / 'stash.sqlite')
    await manager.do_init()
    result = completed_result()
    await manager.store_completed_result(result)

    with pytest.raises(aiosqlite.IntegrityError):
        await manager.store_completed_result(result)

    failing = completed_result('f9b33a33-e6d6-4a48-b04f-1a4a3012bc1f')
    async with aiosqlite.connect(manager.db) as db:
        await db.execute(
            '''
            CREATE TRIGGER fail_completed_item
            BEFORE INSERT ON completed_result_items
            WHEN NEW.run_id = 'f9b33a33-e6d6-4a48-b04f-1a4a3012bc1f'
            BEGIN
                SELECT RAISE(ABORT, 'forced failure');
            END
            '''
        )
        await db.commit()

    with pytest.raises(aiosqlite.IntegrityError, match='forced failure'):
        await manager.store_completed_result(failing)

    async with aiosqlite.connect(manager.db) as db:
        parent_count = (await db.execute_fetchall('SELECT COUNT(*) FROM completed_results'))[0][0]
        item_count = (await db.execute_fetchall('SELECT COUNT(*) FROM completed_result_items'))[0][0]
    assert (parent_count, item_count) == (1, 3)
