from __future__ import annotations

import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_release_artifacts_include_the_canonical_license(tmp_path: Path) -> None:
    license_path = REPO_ROOT / 'LICENSE'
    assert license_path.is_file()

    license_text = license_path.read_bytes()
    metadata = tomllib.loads((REPO_ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    assert metadata['project']['license'] == 'GPL-2.0-only'
    assert b'GNU GENERAL PUBLIC LICENSE' in license_text
    assert b'Version 2, June 1991' in license_text
    assert b'How to Apply These Terms to Your New Programs' in license_text
    assert b'Yoyodyne, Inc.' in license_text
    subprocess.run(
        ('uv', 'build', '--offline', '--out-dir', str(tmp_path)),
        cwd=REPO_ROOT,
        check=True,
    )

    wheel_path = next(tmp_path.glob('*.whl'))
    with zipfile.ZipFile(wheel_path) as wheel:
        package_metadata = wheel.read(next(name for name in wheel.namelist() if name.endswith('.dist-info/METADATA')))
        assert b'License-Expression: GPL-2.0-only' in package_metadata
        assert b'License-File: LICENSE' in package_metadata
        wheel_license = next(name for name in wheel.namelist() if name.endswith('.dist-info/licenses/LICENSE'))
        assert wheel.read(wheel_license) == license_text

    sdist_path = next(tmp_path.glob('*.tar.gz'))
    with tarfile.open(sdist_path) as sdist:
        sdist_license = next(name for name in sdist.getnames() if name.endswith('/LICENSE'))
        extracted = sdist.extractfile(sdist_license)
        assert extracted is not None
        assert extracted.read() == license_text
