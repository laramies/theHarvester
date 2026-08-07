from __future__ import annotations

import hashlib
import ipaddress

from fastapi.testclient import TestClient


def test_harvestview_owns_root_and_issues_an_http_only_session(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        legacy = client.get('/app')
        runs = client.get('/api/v1/runs')

    assert root.status_code == 200
    assert '<title>HarvestView</title>' in root.text
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


def test_harvestview_self_hosts_only_the_pinned_tabulator_theme(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        theme = client.get('/static/harvestview/tabulator.min.css')
        bootstrap = client.get('/static/harvestview/bootstrap.min.css')
        old_theme = client.get('/static/harvestview/tabulator_bootstrap5.min.css')

    assert root.status_code == 200
    assert 'bootstrap.min.css' not in root.text
    assert 'tabulator_bootstrap5.min.css' not in root.text
    assert '<link rel="stylesheet" href="/static/harvestview/tabulator.min.css?v=6.5.2">' in root.text
    assert 'https://unpkg.com' not in root.text
    assert theme.status_code == 200
    assert hashlib.sha256(theme.content).hexdigest() == 'b55e204b2f968cecc4d3663d37858093b31dd22d20f01d76f590726ee18f7e1f'
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
