from __future__ import annotations

import subprocess
from pathlib import Path


def test_release_check_help_describes_repeatable_safe_and_live_lanes() -> None:
    repo_root = Path(__file__).parents[1]

    result = subprocess.run(
        [repo_root / 'scripts' / 'release-check.sh', '--help'],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert 'Usage: scripts/release-check.sh [--live-domain DOMAIN]...' in result.stdout
    assert 'offline contracts, HarvestView browser E2E, package build, and container smoke' in result.stdout
    assert 'Live domains run bounded P0 passive-provider checks only.' in result.stdout


def test_release_check_validates_live_sources_against_the_catalog() -> None:
    repo_root = Path(__file__).parents[1]

    result = subprocess.run(
        [repo_root / 'scripts' / 'release-check.sh', '--check-live-contract'],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert 'Validated 9 P0 passive sources.' in result.stdout
