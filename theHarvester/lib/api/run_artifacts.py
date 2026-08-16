from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from theHarvester.lib.database import ResultStore

from .run_evidence import validate_evidence


@dataclass(frozen=True, slots=True)
class RunPaths:
    database: Path
    artifacts: Path

    @classmethod
    def configured(cls, database: str | Path | None = None) -> RunPaths:
        database_path = Path(database or os.getenv('THEHARVESTER_RUN_DB') or ResultStore().database)
        database_path = database_path.expanduser()
        configured_artifacts = os.getenv('THEHARVESTER_RUN_ARTIFACTS')
        artifact_root = (
            Path(configured_artifacts).expanduser() if configured_artifacts else database_path.parent / 'run-artifacts'
        )
        return cls(database=database_path, artifacts=artifact_root)

    def artifact_directory(self, run_id: str) -> Path:
        return self.artifacts / run_id


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise OSError(f'Refusing symlinked theHarvester directory: {path}')
    path.chmod(0o700)


def read_child_evidence(
    artifact_dir: Path,
    expected_target: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    evidence_path = artifact_dir / 'evidence.json'
    if not evidence_path.is_file():
        return None, None
    try:
        evidence = validate_evidence(json.loads(evidence_path.read_text(encoding='utf-8')))
        if expected_target is not None and evidence.get('target') != expected_target:
            return None, 'Child evidence target does not match run target'
        return evidence, None
    except (OSError, json.JSONDecodeError, HTTPException) as error:
        return None, f'Child evidence is invalid: {error}'


def write_child_evidence(artifact_dir: Path, evidence: Any, *, partial: bool) -> None:
    payload = evidence.evidence_dict()
    if partial:
        payload['status'] = 'partial'
    temporary = artifact_dir / 'evidence.json.tmp'
    temporary.write_text(json.dumps(payload), encoding='utf-8')
    temporary.chmod(0o600)
    evidence_path = artifact_dir / 'evidence.json'
    temporary.replace(evidence_path)
    evidence_path.chmod(0o600)
