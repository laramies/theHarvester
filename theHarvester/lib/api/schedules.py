from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from . import run_worker
from .auth import get_api_key
from .runs import canonical_run_sources
from .schedule_models import (
    ScheduleCreate,
    ScheduleDispatchRecord,
    ScheduleDispatchResponse,
    ScheduleHealthResponse,
    ScheduleResponse,
)
from .schedule_service import (
    dispatch_schedule_now,
    refresh_schedule_dispatches,
    scheduler_available,
    scheduler_enabled,
    wake_scheduler,
)
from .schedule_store import ScheduleStore, ScheduleStoreError

router = APIRouter(prefix='/api/v1/schedules', tags=['Schedules'])


def _canonicalize_schedule(request: ScheduleCreate) -> ScheduleCreate:
    data = request.model_dump()
    data['run']['sources'] = canonical_run_sources(request.run.sources)
    return ScheduleCreate.model_validate(data)


def _store_error(error: ScheduleStoreError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(error))


@router.get('')
async def list_schedules(
    _api_key: Annotated[str, Depends(get_api_key)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ScheduleResponse]:
    try:
        return await ScheduleStore().list_schedules(limit=limit, offset=offset)
    except ScheduleStoreError as error:
        raise _store_error(error) from error


@router.get('/health')
async def schedule_health(
    _api_key: Annotated[str, Depends(get_api_key)],
) -> ScheduleHealthResponse:
    return ScheduleHealthResponse(
        scheduler_enabled=scheduler_enabled(),
        scheduler_available=scheduler_available(),
        worker_enabled=run_worker.worker_enabled(),
        worker_available=run_worker.worker_available(),
    )


@router.post('', status_code=status.HTTP_201_CREATED)
async def create_schedule(
    request: ScheduleCreate,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> ScheduleResponse:
    try:
        created = await ScheduleStore().create(_canonicalize_schedule(request))
    except ScheduleStoreError as error:
        raise _store_error(error) from error
    wake_scheduler()
    return created


@router.get('/{schedule_id}')
async def get_schedule(
    schedule_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> ScheduleResponse:
    try:
        schedule = await ScheduleStore().get(schedule_id)
    except ScheduleStoreError as error:
        raise _store_error(error) from error
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Schedule not found')
    return schedule


@router.put('/{schedule_id}')
async def replace_schedule(
    schedule_id: str,
    request: ScheduleCreate,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> ScheduleResponse:
    try:
        schedule = await ScheduleStore().replace(schedule_id, _canonicalize_schedule(request))
    except ScheduleStoreError as error:
        raise _store_error(error) from error
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Schedule not found')
    wake_scheduler()
    return schedule


@router.delete('/{schedule_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> Response:
    try:
        deleted = await ScheduleStore().delete(schedule_id)
    except ScheduleStoreError as error:
        raise _store_error(error) from error
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Schedule not found')
    wake_scheduler()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post('/{schedule_id}/pause')
async def pause_schedule(
    schedule_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> ScheduleResponse:
    try:
        schedule = await ScheduleStore().set_enabled(schedule_id, False)
    except ScheduleStoreError as error:
        raise _store_error(error) from error
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Schedule not found')
    wake_scheduler()
    return schedule


@router.post('/{schedule_id}/resume')
async def resume_schedule(
    schedule_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> ScheduleResponse:
    try:
        schedule = await ScheduleStore().set_enabled(schedule_id, True)
    except ScheduleStoreError as error:
        raise _store_error(error) from error
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Schedule not found')
    wake_scheduler()
    return schedule


@router.post('/{schedule_id}/run-now', status_code=status.HTTP_202_ACCEPTED)
async def run_schedule_now(
    schedule_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> ScheduleDispatchResponse:
    if not run_worker.worker_enabled() or not run_worker.worker_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='theHarvester execution worker is unavailable',
        )
    try:
        dispatch = await dispatch_schedule_now(schedule_id)
    except (RuntimeError, ScheduleStoreError) as error:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)) from error
    if dispatch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Schedule not found')
    return dispatch


@router.get('/{schedule_id}/dispatches')
async def list_schedule_dispatches(
    schedule_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ScheduleDispatchRecord]:
    store = ScheduleStore()
    try:
        if await store.get(schedule_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Schedule not found')
        await refresh_schedule_dispatches(schedule_id)
        return await store.list_dispatches(schedule_id, limit=limit, offset=offset)
    except ScheduleStoreError as error:
        raise _store_error(error) from error
