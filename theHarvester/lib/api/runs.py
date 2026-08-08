from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import ValidationError

from theHarvester.lib.api.auth import get_api_key
from theHarvester.lib.completed_result import encode_result_jsonl
from theHarvester.lib.source_catalog import ACTION_ACTIVITIES, SOURCE_SPECS, SourceSpec, get_source_spec, resolve_sources

from . import run_worker
from .run_evidence import parse_jsonl_import
from .run_models import (
    EXPORT_RESPONSES,
    IMPORT_REQUEST_OPENAPI,
    RUN_REQUEST_OPENAPI,
    ActionResponse,
    RunDetail,
    RunRequest,
    RunSummary,
    SourceCatalogResponse,
    SourceResponse,
)
from .run_projection import JSONL_RESULT_TYPE_ALIASES, source_spec
from .run_store import RunStore

router = APIRouter(prefix='/api/v1', tags=['Runs'])
MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_RUN_REQUEST_BYTES = 64 * 1024


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


@router.get('/runs')
async def list_runs(_api_key: Annotated[str, Depends(get_api_key)]) -> list[RunSummary]:
    return [RunSummary.model_validate(run) for run in await RunStore().list_runs()]


@router.get('/sources')
async def list_sources(_api_key: Annotated[str, Depends(get_api_key)]) -> SourceCatalogResponse:
    from theHarvester.lib.core import Core

    provider_aliases = {'chaos': 'projectDiscovery', 'github-code': 'github', 'pentesttools': 'pentestTools'}
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
    run = await RunStore().get(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='theHarvester run not found')
    if run['evidence'] is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='No run evidence is available to export',
        )
    results = [{**result, 'type': JSONL_RESULT_TYPE_ALIASES.get(result['type'], result['type'])} for result in run['results']]
    counts = Counter(result['type'] for result in results)
    started_at = run['evidence'].get('started_at') or run['started_at']
    completed_at = run['evidence'].get('completed_at') or run['completed_at']
    if started_at is None or completed_at is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail='Run evidence does not have complete timestamps',
        )
    payload = encode_result_jsonl(
        {
            'completed_at': completed_at,
            'counts': dict(sorted(counts.items())),
            'evidence_status': run['evidence_status'],
            'result_count': len(results),
            'run_id': run['evidence']['run_id'],
            'started_at': started_at,
            'source_executions': run['source_executions'],
            'target': run['target'],
        },
        results,
    )
    return Response(
        payload,
        media_type='application/x-ndjson',
        headers={'Content-Disposition': f'attachment; filename="{run["target"]}-{run_id}.jsonl"'},
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
