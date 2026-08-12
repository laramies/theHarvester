from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated

import anyio
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import ValidationError

from theHarvester.lib.api.auth import get_api_key
from theHarvester.lib.source_catalog import ACTION_ACTIVITIES, SOURCE_SPECS, SourceSpec, get_source_spec, resolve_sources

from . import run_worker
from .run_evidence import parse_jsonl_import
from .run_models import (
    DATABASE_IMPORT_REQUEST_OPENAPI,
    EXPORT_RESPONSES,
    IMPORT_REQUEST_OPENAPI,
    RUN_REQUEST_OPENAPI,
    ActionResponse,
    DatabaseImportResponse,
    RunDetail,
    RunRequest,
    RunSummary,
    SourceCatalogResponse,
    SourceResponse,
)
from .run_projection import source_spec
from .run_store import RunStore

router = APIRouter(prefix='/api/v1', tags=['Runs'])
MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_RUN_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_DATABASE_IMPORT_BYTES = 1024 * 1024 * 1024


async def _read_limited_body(request: Request, limit: int, detail: str) -> bytes:
    content_length = request.headers.get('content-length')
    if content_length and content_length.isdigit() and int(content_length) > limit:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=detail)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=detail)
        body.extend(chunk)
    return bytes(body)


async def _stream_limited_body(request: Request, path: Path, limit: int, detail: str) -> None:
    content_length = request.headers.get('content-length')
    if content_length and content_length.isdigit() and int(content_length) > limit:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=detail)
    size = 0
    async with await anyio.open_file(path, 'wb') as file:
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=detail)
            await file.write(chunk)


@router.get('/runs')
async def list_runs(
    _api_key: Annotated[str, Depends(get_api_key)],
    limit: Annotated[int, Query(ge=1, le=500, description='Maximum run summaries to return.')] = 100,
    offset: Annotated[int, Query(ge=0, description='Number of newer run summaries to skip.')] = 0,
) -> list[RunSummary]:
    return [RunSummary.model_validate(run) for run in await RunStore().list_runs(limit=limit, offset=offset)]


@router.get('/sources')
async def list_sources(_api_key: Annotated[str, Depends(get_api_key)]) -> SourceCatalogResponse:
    from theHarvester.lib.core import Core

    provider_aliases = {'github-code': 'github', 'pentesttools': 'pentestTools'}
    api_key_fields = Core.api_key_fields()
    provider_names = {provider.casefold(): provider for provider in api_key_fields}

    def credentials(source: SourceSpec) -> list[str]:
        provider = provider_aliases.get(source.name, provider_names.get(source.name.casefold()))
        if provider is None:
            return []
        return [f'api-{field}' for field in api_key_fields.get(provider, ())]

    return SourceCatalogResponse(
        sources=[
            SourceResponse(
                name=source.name,
                activity=source.activity,
                credentials=credentials(source),
                capabilities=sorted(source.capabilities),
            )
            for source in sorted(SOURCE_SPECS.values(), key=lambda item: item.name)
        ],
        actions=[ActionResponse(name=name, activity=activity) for name, activity in sorted(ACTION_ACTIVITIES.items())],
    )


@router.post(
    '/runs',
    status_code=status.HTTP_201_CREATED,
    response_model_exclude_unset=True,
    openapi_extra=RUN_REQUEST_OPENAPI,
)
async def create_run(
    request: Request,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> RunDetail:
    body = await _read_limited_body(request, MAX_RUN_REQUEST_BYTES, 'Run request exceeds the 64 KiB limit')
    try:
        run_request = RunRequest.model_validate_json(body)
    except ValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=error.errors(include_url=False, include_context=False),
        ) from error
    selected_sources = resolve_sources(run_request.sources)
    unsupported_sources = [source for source in selected_sources if source_spec(source) is None]
    if unsupported_sources:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'Unsupported sources: {", ".join(sorted(unsupported_sources))}',
        )
    run_request.sources = [get_source_spec(source).name for source in selected_sources]
    if not run_worker.worker_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='theHarvester execution worker is disabled',
        )
    if not run_worker.worker_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='theHarvester execution worker is unavailable',
        )
    run = await RunStore().create(run_request)
    run_worker.wake_worker()
    return RunDetail.model_validate(run)


@router.post(
    '/runs/import',
    status_code=status.HTTP_201_CREATED,
    response_model_exclude_unset=True,
    openapi_extra=IMPORT_REQUEST_OPENAPI,
)
async def import_run(
    request: Request,
    _api_key: Annotated[str, Depends(get_api_key)],
    filename: Annotated[
        str,
        Query(
            min_length=1,
            max_length=255,
            description='Original .jsonl file name.',
        ),
    ],
) -> RunDetail:
    safe_filename = Path(filename).name
    if Path(safe_filename).suffix.casefold() != '.jsonl':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Choose a .jsonl result file')
    body = await _read_limited_body(request, MAX_IMPORT_BYTES, 'Result file exceeds the 10 MiB limit')
    evidence = parse_jsonl_import(body)
    return RunDetail.model_validate(await RunStore().import_evidence(evidence, safe_filename))


@router.post(
    '/runs/import-database',
    status_code=status.HTTP_201_CREATED,
    openapi_extra=DATABASE_IMPORT_REQUEST_OPENAPI,
)
async def import_database(
    request: Request,
    _api_key: Annotated[str, Depends(get_api_key)],
    filename: Annotated[
        str,
        Query(
            min_length=1,
            max_length=255,
            description='Original .sqlite, .sqlite3, or .db file name.',
        ),
    ],
) -> DatabaseImportResponse:
    safe_filename = Path(filename).name
    if Path(safe_filename).suffix.casefold() not in {'.sqlite', '.sqlite3', '.db'}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Choose a SQLite database file')
    try:
        maximum_size = int(os.getenv('THEHARVESTER_MAX_DATABASE_IMPORT_BYTES', DEFAULT_MAX_DATABASE_IMPORT_BYTES))
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='THEHARVESTER_MAX_DATABASE_IMPORT_BYTES must be an integer',
        ) from error
    descriptor, temporary_name = tempfile.mkstemp(prefix='theharvester-import-', suffix='.sqlite')
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    await anyio.Path(temporary_path).chmod(0o600)
    try:
        await _stream_limited_body(
            request,
            temporary_path,
            maximum_size,
            'SQLite database exceeds the configured import limit',
        )
        async with await anyio.open_file(temporary_path, 'rb') as file:
            header = await file.read(16)
        if header != b'SQLite format 3\x00':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Uploaded file is not a SQLite database')
        return DatabaseImportResponse.model_validate(await RunStore().import_database(temporary_path, safe_filename))
    finally:
        await anyio.Path(temporary_path).unlink(missing_ok=True)


@router.get('/runs/{run_id}', response_model_exclude_unset=True)
async def get_run(run_id: str, _api_key: Annotated[str, Depends(get_api_key)]) -> RunDetail:
    run = await RunStore().get(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='theHarvester run not found')
    return RunDetail.model_validate(run)


@router.post('/runs/{run_id}/cancel', response_model_exclude_unset=True)
async def cancel_run(
    run_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> RunDetail:
    run = await RunStore().cancel(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='theHarvester run not found')
    return RunDetail.model_validate(run)


@router.get('/runs/{run_id}/export', response_class=Response, responses=EXPORT_RESPONSES)
async def export_run(
    run_id: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> Response:
    store = RunStore()
    try:
        completed = await store.load_completed_result(run_id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='theHarvester run not found')
    if completed is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='No run evidence is available to export',
        )
    return Response(
        completed.jsonl(),
        media_type='application/x-ndjson',
        headers={'Content-Disposition': f'attachment; filename="{completed.target}-{run_id}.jsonl"'},
    )


@router.get('/runs/{run_id}/screenshots/{name}')
async def get_screenshot(
    run_id: str,
    name: str,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> FileResponse:
    store = RunStore()
    run = await store.get(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Screenshot not found')
    screenshot = next((item for item in run['screenshots'] if item['name'] == name), None)
    if screenshot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Screenshot not found')
    artifact_dir = store.artifact_directory(str(run['run_id']))
    screenshot_dir = artifact_dir / 'screenshots'
    path = screenshot_dir / screenshot['name']
    if artifact_dir.is_symlink() or screenshot_dir.is_symlink() or path.is_symlink() or not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Screenshot not found')
    return FileResponse(path, media_type='image/png', filename=screenshot['name'])
