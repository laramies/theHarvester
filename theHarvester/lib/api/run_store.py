from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

from fastapi import HTTPException, status

from theHarvester.lib.active_evidence import ActionExecution, ActiveEvidence, ArtifactReference
from theHarvester.lib.asn_attribution import AsnAttributionObservation, parse_asn_attribution_details
from theHarvester.lib.completed_result import (
    CompletedResult,
    ResultObservation,
    SourceExecution,
    parse_virtual_host_details,
)
from theHarvester.lib.database import DuplicateRunError, ResultStore, ResultStoreError, RunLifecycleStore
from theHarvester.lib.evidence_types import EXECUTION_STATUSES, EvidenceStatus, ExecutionStatus, ResultKind
from theHarvester.lib.hostname_tracking import canonical_target, hostname_tracking_projection
from theHarvester.lib.network_evidence import NetworkObservation, parse_network_observation_details
from theHarvester.lib.shodan_evidence import ShodanHostObservation
from theHarvester.lib.takeover_evidence import TakeoverCandidateOutcome, parse_takeover_details

from .run_artifacts import RunPaths, read_child_evidence
from .run_models import RunRequest, _normalize_target, utc_now
from .run_projection import activities_for_evidence, activities_for_request, normalized_results, screenshots, source_executions

if TYPE_CHECKING:
    from pathlib import Path

    from theHarvester.lib.virtual_host import VirtualHostObservation

WORKER_LEASE_TIMEOUT_SECONDS = 30
DATABASE_IMPORT_BATCH_SIZE = 100


def _execution_status(value: object) -> ExecutionStatus:
    normalized = str(value)
    if normalized not in EXECUTION_STATUSES:
        raise ValueError(f'unknown execution status: {normalized}')
    return cast('ExecutionStatus', normalized)


def _completed_result(
    evidence: dict[str, Any],
    *,
    run_id: UUID,
    fallback_started_at: str,
    fallback_completed_at: str,
) -> CompletedResult:
    results = [item for item in evidence.get('results', []) if isinstance(item, dict)]
    groups: dict[ResultKind, set[str]] = defaultdict(set)
    source_origins: set[ResultObservation] = set()
    source_counts: Counter[str] = Counter()
    action_groups: dict[str, dict[ResultKind, set[str]]] = defaultdict(lambda: defaultdict(set))
    virtual_hosts: list[VirtualHostObservation] = []
    network_observations: list[NetworkObservation] = []
    asn_attributions: list[AsnAttributionObservation] = []
    shodan_hosts: list[ShodanHostObservation] = []
    takeover_outcomes: list[TakeoverCandidateOutcome] = []
    for item in results:
        kind = cast('ResultKind', str(item['type']))
        value = str(item['value'])
        groups[kind].add(value)
        if kind == 'hostname' and item.get('observations'):
            virtual_hosts.extend(parse_virtual_host_details(value, item.get('observations')))
        elif kind == 'prefix' and item.get('observations'):
            network_observations.extend(parse_network_observation_details(value, item.get('observations')))
        elif kind == 'asn' and item.get('observations'):
            asn_attributions.extend(parse_asn_attribution_details(value, item.get('observations')))
        elif kind == 'shodan-host':
            shodan_hosts.append(ShodanHostObservation.from_record(value, item.get('details')))
        elif kind == 'takeover':
            takeover_outcomes.append(parse_takeover_details(value, item.get('details')))
        for source in set(item.get('sources', [])):
            source_name = str(source)
            source_origins.add(ResultObservation(source_name, kind, value))
            source_counts[source_name] += 1
        for action in set(item.get('actions', [])):
            action_groups[str(action)][kind].add(value)

    source_details = {
        str(item['source']): item
        for item in evidence.get('source_executions', [])
        if isinstance(item, dict) and item.get('source')
    }
    if len(source_details) != len(evidence.get('source_executions', [])):
        raise ValueError('source executions must have unique non-empty names')
    if missing_sources := set(source_counts) - set(source_details):
        raise ValueError(f'missing source execution: {min(missing_sources)}')
    source_names = sorted(source_details)
    completed_sources = tuple(
        SourceExecution(
            source=name,
            status=_execution_status(source_details.get(name, {}).get('status', 'completed')),
            duration_ms=float(source_details.get(name, {}).get('duration_ms', 0)),
            result_count=source_counts[name],
            error_type=source_details.get(name, {}).get('error_type'),
            stop_reason=source_details[name].get('stop_reason'),
        )
        for name in source_names
    )

    artifacts_by_action: dict[str, list[ArtifactReference]] = defaultdict(list)
    for item in evidence.get('artifacts', []):
        if not isinstance(item, dict) or not item.get('action'):
            continue
        subject = item.get('subject')
        file = item.get('file')
        if not isinstance(subject, dict) or not isinstance(file, dict):
            continue
        artifacts_by_action[str(item['action'])].append(
            ArtifactReference(
                kind=str(item['kind']),
                subject_kind=cast('ResultKind', str(subject['kind'])),
                subject_value=str(subject['value']),
                path=str(file['path']),
                media_type=str(file['media_type']),
                size_bytes=int(file['size_bytes']),
                sha256=str(file['sha256']),
                created_at=datetime.fromisoformat(str(item.get('created_at') or fallback_completed_at)),
            )
        )
    action_details = {
        str(item['action']): item
        for item in evidence.get('action_executions', [])
        if isinstance(item, dict) and item.get('action')
    }
    if len(action_details) != len(evidence.get('action_executions', [])):
        raise ValueError('action executions must have unique non-empty names')
    missing_actions = (set(action_groups) | set(artifacts_by_action)) - set(action_details)
    if missing_actions:
        raise ValueError(f'missing action execution: {min(missing_actions)}')
    action_names = sorted(action_details)
    active_evidence = ActiveEvidence(
        executions=tuple(
            ActionExecution.finish(
                action=name,
                status=_execution_status(action_details.get(name, {}).get('status', 'completed')),
                duration_ms=float(action_details.get(name, {}).get('duration_ms', 0)),
                groups=action_groups[name],
                artifacts=artifacts_by_action[name],
                error_type=action_details.get(name, {}).get('error_type'),
                stop_reason=action_details.get(name, {}).get('stop_reason'),
            )
            for name in action_names
        )
    )
    execution_status_is_authoritative = bool(completed_sources or action_names)
    return CompletedResult.finish(
        run_id=run_id,
        target=str(evidence['target']),
        started_at=datetime.fromisoformat(str(evidence.get('started_at') or fallback_started_at)),
        completed_at=datetime.fromisoformat(str(evidence.get('completed_at') or fallback_completed_at)),
        groups=groups,
        source_executions=completed_sources,
        observations=sorted(source_origins),
        active_evidence=active_evidence,
        virtual_hosts=virtual_hosts,
        network_observations=network_observations,
        asn_attributions=asn_attributions,
        shodan_hosts=shodan_hosts,
        takeover_outcomes=takeover_outcomes,
        evidence_status=(
            cast('EvidenceStatus', str(evidence['status']))
            if evidence.get('status') is not None and not execution_status_is_authoritative
            else None
        ),
    )


def _imported_request(completed: CompletedResult, filename: str, source_run_id: str) -> dict[str, object]:
    evidence = completed.evidence_dict()
    executions = source_executions(evidence)
    raw_action_executions = evidence.get('action_executions', [])
    action_executions = (
        [dict(execution) for execution in raw_action_executions if isinstance(execution, dict)]
        if isinstance(raw_action_executions, list)
        else []
    )
    return {
        'filename': filename,
        'source_run_id': source_run_id,
        'sources': sorted(
            {
                str(execution.get('source') or execution.get('name'))
                for execution in executions
                if execution.get('source') or execution.get('name')
            }
        ),
        'activities': activities_for_evidence(executions, action_executions),
    }


class RunStore:
    """Join API lifecycle state with the canonical SQLAlchemy result store."""

    def __init__(self, database: str | Path | None = None) -> None:
        self.paths = RunPaths.configured(database)
        self.database = self.paths.database
        self.lifecycle = RunLifecycleStore(self.database)
        self.results = ResultStore(self.database)

    def artifact_directory(self, run_id: str) -> Path:
        return self.paths.artifact_directory(run_id)

    async def initialize(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        await self.lifecycle.initialize()
        self.database.chmod(0o600)

    async def _row(self, record: dict[str, object], *, detail: bool = False) -> dict[str, Any]:
        request = json.loads(str(record['request_json']))
        evidence = None
        if detail and record['evidence_run_id'] is not None:
            evidence = (await self.results.load_run(UUID(str(record['evidence_run_id'])))).evidence_dict()
        summary_result_count = record.get('result_count')
        result = {
            'run_id': record['run_id'],
            'target': record['target'],
            'status': record['status'],
            'origin': record['origin'],
            'created_at': record['created_at'],
            'started_at': record['started_at'],
            'completed_at': record['completed_at'],
            'cancellation_requested_at': record['cancellation_requested_at'],
            'error': record['error'],
            'sources': request.get('sources', []),
            'activities': activities_for_request(request),
            'evidence_status': record['evidence_status'] or (evidence.get('status') if evidence else None),
            'result_count': (
                len(normalized_results(evidence))
                if evidence
                else summary_result_count
                if isinstance(summary_result_count, int)
                else 0
            ),
        }
        if detail:
            source_yields = (
                [
                    item.to_dict()
                    for item in await self.results.source_yields(
                        UUID(str(record['evidence_run_id'])),
                        kind='hostname',
                    )
                ]
                if evidence
                else []
            )
            result.update(
                request=request,
                evidence=evidence,
                results=normalized_results(evidence),
                source_executions=source_executions(evidence),
                source_yields=source_yields,
                hostname_tracking=(
                    await hostname_tracking_projection(
                        self.results,
                        run_id=UUID(str(record['evidence_run_id'])),
                        include_persisting=True,
                    )
                    if evidence
                    else {
                        'target': canonical_target(record['target']),
                        'comparison_count': 0,
                        'comparisons': [],
                        'hostname_changes': [],
                    }
                ),
                action_executions=evidence.get('action_executions', []) if evidence else [],
                artifacts=evidence.get('artifacts', []) if evidence else [],
                screenshots=screenshots(evidence, str(record['run_id']), self.artifact_directory(str(record['run_id']))),
                log=record['log'],
            )
        return result

    async def create(self, request: RunRequest, *, run_id: str | None = None) -> dict[str, Any]:
        await self.initialize()
        run_id = run_id or str(uuid4())
        await self.lifecycle.create(
            run_id=run_id,
            target=request.target,
            status='queued',
            origin='local',
            created_at=utc_now(),
            request_json=request.model_dump_json(),
        )
        run = await self.get(run_id)
        assert run is not None
        return run

    async def import_evidence(self, evidence: dict[str, Any], filename: str) -> dict[str, Any]:
        await self.initialize()
        created_at = utc_now()
        target = _normalize_target(str(evidence['target']))
        source_run_id = str(evidence['run_id'])
        run_id = str(uuid4())
        try:
            completed = _completed_result(
                evidence,
                run_id=UUID(run_id),
                fallback_started_at=created_at,
                fallback_completed_at=created_at,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'Invalid run evidence: {error}',
            ) from error
        if evidence['status'] != completed.status:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Evidence status does not match its execution outcomes',
            )
        await self._persist_completed(completed)
        request = _imported_request(completed, filename, source_run_id)
        await self.lifecycle.create(
            run_id=run_id,
            target=target,
            status='completed',
            origin='imported',
            created_at=created_at,
            started_at=completed.started_at.isoformat(),
            completed_at=completed.completed_at.isoformat(),
            request_json=json.dumps(request),
            evidence_run_id=run_id,
            evidence_status=completed.status,
        )
        run = await self.get(run_id)
        assert run is not None
        return run

    async def import_database(self, source_path: Path, filename: str) -> dict[str, object]:
        await self.initialize()
        source = ResultStore(source_path)
        imported_run_ids: list[str] = []
        skipped_run_ids: set[str] = set()
        reuse_evidence_ids: set[str] = set()

        async def source_summaries():
            offset = 0
            while batch := await source.list_runs(limit=DATABASE_IMPORT_BATCH_SIZE, offset=offset):
                for summary in batch:
                    yield summary
                offset += len(batch)

        try:
            await source.validate_import_database()
            await source.initialize()
            async for summary in source_summaries():
                completed = await source.load_run(UUID(str(summary['run_id'])))
                run_id = str(completed.run_id)
                record = await self.lifecycle.get(run_id)
                existing = None
                try:
                    existing = await self.results.load_run(completed.run_id)
                except LookupError, ResultStoreError:
                    pass
                if record is not None or existing is not None:
                    if record is not None and existing == completed:
                        skipped_run_ids.add(run_id)
                        continue
                    if existing != completed:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=f'Run ID conflicts with different evidence: {run_id}',
                        )
                    reuse_evidence_ids.add(run_id)

            async for summary in source_summaries():
                completed = await source.load_run(UUID(str(summary['run_id'])))
                run_id = str(completed.run_id)
                if run_id in skipped_run_ids:
                    continue
                if run_id not in reuse_evidence_ids:
                    await self.results.save_run(completed)
                await self.lifecycle.create(
                    run_id=run_id,
                    target=completed.target,
                    status='completed',
                    origin='imported',
                    created_at=completed.completed_at.isoformat(),
                    started_at=completed.started_at.isoformat(),
                    completed_at=completed.completed_at.isoformat(),
                    request_json=json.dumps(_imported_request(completed, filename, run_id)),
                    evidence_run_id=run_id,
                    evidence_status=completed.status,
                )
                imported_run_ids.append(run_id)
        except (ResultStoreError, RuntimeError, ValueError) as error:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
        finally:
            await source.dispose()
        return {
            'filename': filename,
            'imported_run_ids': sorted(imported_run_ids),
            'skipped_run_ids': sorted(skipped_run_ids),
        }

    async def export_database(self, destination: Path) -> None:
        await self.initialize()
        await self.results.export_database(destination)

    async def list_runs(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        await self.initialize()
        return [await self._row(record) for record in await self.lifecycle.list_records(limit=limit, offset=offset)]

    async def get(self, run_id: str) -> dict[str, Any] | None:
        await self.initialize()
        record = await self.lifecycle.get(run_id)
        return await self._row(record, detail=True) if record else None

    async def load_completed_result(self, run_id: str) -> CompletedResult | None:
        """Load the canonical evidence attached to an API run."""
        await self.initialize()
        record = await self.lifecycle.get(run_id)
        if record is None:
            raise LookupError(run_id)
        if record['evidence_run_id'] is None:
            return None
        try:
            completed = await self.results.load_run(UUID(str(record['evidence_run_id'])))
        except (LookupError, ValueError) as error:
            raise ResultStoreError('Attached run evidence does not exist') from error
        if completed.target != str(record['target']):
            raise ResultStoreError('Attached run evidence target does not match its lifecycle run')
        return completed

    async def cancel(self, run_id: str) -> dict[str, Any] | None:
        await self.initialize()
        try:
            record = await self.lifecycle.cancel(run_id, utc_now())
        except ValueError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f'Run is already {error.args[0]}') from error
        return await self._row(record, detail=True) if record else None

    async def recover_orphans(self) -> None:
        await self.initialize()
        recovered_at = utc_now()
        for record in await self.lifecycle.running():
            run_id = str(record['run_id'])
            target = str(record['target'])
            evidence, evidence_error = read_child_evidence(self.artifact_directory(run_id), target)
            error = 'theHarvester restarted before child completion'
            if evidence_error:
                error += f'; {evidence_error}'
            evidence_run_id, evidence_status = await self._terminal_evidence_reference(
                record,
                evidence,
                recovered_at,
            )
            await self.lifecycle.fail(
                run_id,
                status='failed',
                completed_at=recovered_at,
                error=error,
                log=str(record['log']),
                evidence_run_id=evidence_run_id,
                evidence_status=evidence_status,
            )

    async def acquire_worker_lease(self, owner_id: str) -> bool:
        await self.initialize()
        return await self.lifecycle.acquire_lease(owner_id, utc_now(), WORKER_LEASE_TIMEOUT_SECONDS)

    async def heartbeat_worker_lease(self, owner_id: str) -> bool:
        return await self.lifecycle.heartbeat_lease(owner_id, utc_now())

    async def release_worker_lease(self, owner_id: str) -> None:
        return await self.lifecycle.release_lease(owner_id)

    async def claim_next(self) -> dict[str, Any] | None:
        await self.initialize()
        record = await self.lifecycle.claim_next(utc_now())
        return await self._row(record, detail=True) if record else None

    async def finish(self, run_id: str, evidence: dict[str, Any] | None, log: str) -> None:
        record = await self.lifecycle.get(run_id)
        if record is None:
            return
        completed_at = utc_now()
        evidence_run_id, evidence_status = await self._terminal_evidence_reference(record, evidence, completed_at)
        await self.lifecycle.finish(
            run_id,
            completed_at=completed_at,
            evidence_run_id=evidence_run_id,
            evidence_status=evidence_status,
            log=log[-200_000:],
        )

    async def fail(
        self,
        run_id: str,
        error: str,
        log: str,
        *,
        cancelled: bool = False,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        record = await self.lifecycle.get(run_id)
        if record is None:
            return
        completed_at = utc_now()
        evidence_run_id, evidence_status = await self._terminal_evidence_reference(record, evidence, completed_at)
        await self.lifecycle.fail(
            run_id,
            status='cancelled' if cancelled else 'failed',
            completed_at=completed_at,
            error=error,
            log=log[-200_000:],
            evidence_run_id=evidence_run_id,
            evidence_status=evidence_status,
        )

    async def _terminal_evidence_reference(
        self,
        record: dict[str, object],
        evidence: dict[str, Any] | None,
        completed_at: str,
    ) -> tuple[str | None, str | None]:
        """Return the immutable evidence reference for a terminal lifecycle update."""
        run_id = str(record['run_id'])
        target = str(record['target'])
        completed = (
            await self._save_evidence(
                evidence,
                str(record['started_at'] or record['created_at']),
                completed_at,
                run_id=UUID(run_id),
                expected_target=target,
            )
            if evidence
            else await self._existing_evidence(run_id, target)
        )
        return (str(completed.run_id), completed.status) if completed is not None else (None, None)

    async def _existing_evidence(self, run_id: str, target: str) -> CompletedResult | None:
        try:
            completed = await self.results.load_run(UUID(run_id))
        except LookupError, ResultStoreError, ValueError:
            return None
        return completed if completed.target == target else None

    async def _save_evidence(
        self,
        evidence: dict[str, Any],
        fallback_started_at: str,
        fallback_completed_at: str,
        *,
        run_id: UUID,
        expected_target: str,
    ) -> CompletedResult:
        if str(evidence.get('target', '')) != expected_target:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Evidence target does not match run target',
            )
        existing = await self._existing_evidence(str(run_id), expected_target)
        if existing is not None:
            return existing
        try:
            completed = _completed_result(
                evidence,
                run_id=run_id,
                fallback_started_at=fallback_started_at,
                fallback_completed_at=fallback_completed_at,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'Invalid run evidence: {error}',
            ) from error
        if completed.target != expected_target:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Evidence target does not match run target',
            )
        await self._persist_completed(completed)
        return completed

    async def _persist_completed(self, completed: CompletedResult) -> None:
        try:
            await self.results.save_run(completed)
        except DuplicateRunError:
            existing = await self.results.load_run(completed.run_id)
            if existing != completed:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f'Run evidence already exists with different contents: {completed.run_id}',
                ) from None
