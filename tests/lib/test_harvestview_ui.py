from __future__ import annotations

import ipaddress

from fastapi.testclient import TestClient


def test_harvestview_owns_root_and_issues_an_http_only_session(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api
    from theHarvester.lib.resolver_selection import DEFAULT_DNS_RESOLVERS

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        legacy = client.get('/app')
        runs = client.get('/api/v1/runs')

    assert root.status_code == 200
    assert '<title>HarvestView</title>' in root.text
    assert '<summary>Advanced safety controls</summary>' in root.text
    assert f'value="{",".join(DEFAULT_DNS_RESOLVERS)}"' in root.text
    assert 'Resolve with the configured resolver addresses.' in root.text
    assert legacy.status_code == 404
    cookie = root.headers['set-cookie']
    assert 'theharvester-api-key=' in cookie
    assert 'test-key' not in cookie
    assert 'HttpOnly' in cookie
    assert 'SameSite=strict' in cookie
    assert 'Path=/api/v1' in cookie
    assert runs.status_code == 200
    assert runs.json() == []


def test_harvestview_assets_load_outside_the_repository_directory(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.chdir(tmp_path)

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        response = client.get('/static/harvestview/app.js')

    assert response.status_code == 200
    assert 'function renderResults' in response.text


def test_harvestview_offers_jsonl_and_sqlite_imports_with_jsonl_export(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        script = client.get('/static/harvestview/app.js')

    assert 'accept=".jsonl,.sqlite,.sqlite3,.db,application/x-ndjson,application/vnd.sqlite3"' in root.text
    assert 'id="export-jsonl-button"' in root.text
    assert 'id="route-csv-button"' not in root.text
    assert 'id="export-json-button"' not in root.text
    assert 'id="export-csv-button"' not in root.text
    assert '/export' in script.text
    assert "fileKind === 'jsonl' ? '/api/v1/runs/import' : '/api/v1/runs/import-database'" in script.text
    assert '/exports/' not in script.text
    assert 'text/csv' not in script.text
    assert 'versioned JSONL' not in root.text
    assert 'interesting-url' not in script.text
    assert 'api-endpoint' not in script.text
    assert 'linkedin-link' not in script.text


def test_harvestview_loads_pinned_tabulator_locally(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        theme = client.get('/static/harvestview/tabulator.min.css')
        script = client.get('/static/harvestview/tabulator.min.js')
        license_file = client.get('/static/harvestview/TABULATOR-LICENSE')
        bootstrap = client.get('/static/harvestview/bootstrap.min.css')
        old_theme = client.get('/static/harvestview/tabulator_bootstrap5.min.css')

    assert root.status_code == 200
    assert 'bootstrap.min.css' not in root.text
    assert 'tabulator_bootstrap5.min.css' not in root.text
    assert '<link rel="stylesheet" href="/static/harvestview/tabulator.min.css">' in root.text
    assert '<script src="/static/harvestview/tabulator.min.js"></script>' in root.text
    assert 'cdnjs.cloudflare.com' not in root.text
    assert 'https://unpkg.com' not in root.text
    assert theme.status_code == 200
    assert 'Tabulator v6.5.2' in script.text
    assert license_file.status_code == 200
    assert 'The MIT License (MIT)' in license_file.text
    assert bootstrap.status_code == 404
    assert old_theme.status_code == 404


def test_docker_mode_trusts_only_the_detected_gateway(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api, harvestview

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setattr(harvestview, '_docker_gateway', lambda: ipaddress.ip_address('172.18.0.1'))

    with TestClient(api.app, base_url='http://127.0.0.1', client=('172.18.0.1', 50000)) as client:
        disabled = client.get('/')

    monkeypatch.setenv('THEHARVESTER_HARVESTVIEW_LOCAL_PROXY', 'enabled')
    with TestClient(api.app, base_url='http://127.0.0.1', client=('172.18.0.1', 50000)) as client:
        gateway = client.get('/')
    with TestClient(api.app, base_url='http://127.0.0.1', client=('172.18.0.2', 50000)) as client:
        sibling = client.get('/')
    with TestClient(api.app, base_url='http://attacker.example', client=('172.18.0.1', 50000)) as client:
        rebound = client.get('/')

    assert disabled.status_code == 403
    assert gateway.status_code == 200
    assert sibling.status_code == 403
    assert rebound.status_code == 403
