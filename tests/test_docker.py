from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parents[1]


def test_container_starts_and_checks_harvestview_on_port_8000() -> None:
    dockerfile = (REPO_ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert 'EXPOSE 8000' in dockerfile
    assert 'from theHarvester.lib.api.auth import _configured_api_key' in dockerfile
    assert 'key = _configured_api_key(); assert key' in dockerfile
    assert 'http://127.0.0.1:8000/api/v1/runs' in dockerfile
    assert "headers={'X-API-Key': key}" in dockerfile
    assert 'CMD ["-H", "0.0.0.0", "-p", "8000"]' in dockerfile
    assert '127.0.0.1:8000/app' not in dockerfile
    assert 'COPY --chown=10001:10001 theHarvester ./theHarvester' not in dockerfile


def test_container_rebuilds_the_local_package_when_source_changes() -> None:
    dockerfile = (REPO_ROOT / 'Dockerfile').read_text(encoding='utf-8')

    assert '--reinstall-package theharvester' in dockerfile


def test_container_smoke_uses_the_unversioned_jsonl_contract() -> None:
    workflow = (REPO_ROOT / '.github/workflows/harvestview-container.yml').read_text(encoding='utf-8')

    assert '"evidence_status":"complete"' in workflow
    assert '"type":"ip"' in workflow
    assert 'ip-address' not in workflow
    assert 'schema_version' not in workflow


def test_compose_keeps_harvestview_local_and_persists_private_run_data() -> None:
    compose = yaml.safe_load((REPO_ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))
    service = compose['services']['theharvester.svc.local']

    assert service['ports'] == ['127.0.0.1:${THEHARVESTER_PORT:-5000}:8000']
    assert service['environment']['THEHARVESTER_API_KEY_FILE'] == '/run/secrets/operator-api-key'
    assert service['environment']['THEHARVESTER_HARVESTVIEW_LOCAL_PROXY'] == 'enabled'
    assert service['read_only'] is True
    assert service['cap_drop'] == ['ALL']
    assert 'theharvester-data:/var/lib/theharvester' in service['volumes']
    assert compose['secrets']['operator-api-key']['file'] == '${THEHARVESTER_API_KEY_FILE:-./.secrets/operator-api-key}'


def test_container_build_context_excludes_local_secrets_and_run_data() -> None:
    ignored = set((REPO_ROOT / '.dockerignore').read_text(encoding='utf-8').splitlines())

    assert {
        '.git',
        '.env',
        '.env.*',
        '.secrets/',
        '.venv/',
        'test-results/',
        '*.sqlite*',
        'theHarvester/data/api-keys.yaml',
        'theHarvester/data/proxies.yaml',
    } <= ignored
