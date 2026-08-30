from __future__ import annotations

import hashlib
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HARVESTVIEW_ASSETS = (
    'theHarvester/lib/api/static/harvestview/tabulator.min.css',
    'theHarvester/lib/api/static/harvestview/tabulator.min.js',
    'theHarvester/lib/api/static/harvestview/TABULATOR-LICENSE',
)
HARVESTVIEW_ASSET_SHA256 = {
    'theHarvester/lib/api/static/harvestview/tabulator.min.css': 'b55e204b2f968cecc4d3663d37858093b31dd22d20f01d76f590726ee18f7e1f',
    'theHarvester/lib/api/static/harvestview/tabulator.min.js': '04802e757fa4189342c666d0f970a01d761c312798f31ffc664c24cbccc7ce3e',
    'theHarvester/lib/api/static/harvestview/TABULATOR-LICENSE': '191a2ee554684e1064c897b432f0e1bc6dfa714ca045d3f6ea2cf692cbd398b7',
}


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
    for asset, expected_hash in HARVESTVIEW_ASSET_SHA256.items():
        assert hashlib.sha256((REPO_ROOT / asset).read_bytes()).hexdigest() == expected_hash

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
        for asset in HARVESTVIEW_ASSETS:
            assert wheel.read(asset) == (REPO_ROOT / asset).read_bytes()

    sdist_path = next(tmp_path.glob('*.tar.gz'))
    with tarfile.open(sdist_path) as sdist:
        sdist_license = next(name for name in sdist.getnames() if name.endswith('/LICENSE'))
        extracted = sdist.extractfile(sdist_license)
        assert extracted is not None
        assert extracted.read() == license_text
        for asset in HARVESTVIEW_ASSETS:
            member = next(name for name in sdist.getnames() if name.endswith(f'/{asset}'))
            extracted = sdist.extractfile(member)
            assert extracted is not None
            assert extracted.read() == (REPO_ROOT / asset).read_bytes()
