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
    assert 'id="source-workers" name="source_workers" type="number" min="1"' in root.text
    assert 'id="run-limit" name="limit" type="number" min="0" value="500"' in root.text
    assert '0 means unlimited; positive values apply per selected source.' in root.text
    assert 'id="run-limit" name="limit" type="number" min="0" max="10000"' not in root.text
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
    assert "request.dns_recursive_query_limit === null ? 'Unlimited'" in response.text
    assert "request.dns_recursive_query_limit === undefined ? 'Not recorded'" in response.text
    assert "request.dns_recursive_runtime_seconds === null ? 'Unlimited'" in response.text
    assert "request.dns_recursive_runtime_seconds === undefined ? 'Not recorded'" in response.text
    assert "request.deadline_seconds === null ? 'Unlimited'" in response.text
    assert "deadline_seconds: form.get('deadline_seconds') ? Number(form.get('deadline_seconds')) : null" in response.text
    assert "source_workers: Number(form.get('source_workers'))" in response.text
    assert "request.limit === 0 ? 'Unlimited'" in response.text


def test_harvestview_explains_and_filters_persisted_hostname_changes(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        script = client.get('/static/harvestview/app.js')

    assert root.status_code == 200
    assert 'id="hostname-tracking-section"' in root.text
    assert 'id="tracking-change-filter"' in root.text
    assert 'id="tracking-source-filter"' in root.text
    assert 'id="tracking-resolution-filter"' in root.text
    assert 'id="tracking-exclusive-filter"' in root.text
    assert 'id="tracking-persisting-filter"' in root.text
    assert 'INCONCLUSIVE means a contributing source did not complete reliably' in root.text
    assert 'This view reads finalized evidence only and performs no discovery or DNS.' in root.text
    assert script.status_code == 200
    assert 'function renderHostnameTracking' in script.text
    assert 'blocking_sources' in script.text


def test_harvestview_exposes_local_schedule_page_and_assets(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        schedules = client.get('/schedules')
        stylesheet = client.get('/static/harvestview/schedules.css')
        script = client.get('/static/harvestview/schedules.js')
    with TestClient(api.app, base_url='http://attacker.example', client=('203.0.113.10', 50000)) as client:
        remote = client.get('/schedules')

    assert 'href="/schedules">Schedules</a>' in root.text
    assert schedules.status_code == 200
    assert '<h1 id="builder-title">Create a schedule</h1>' in schedules.text
    assert 'id="run-limit" type="number" min="0" value="500"' in schedules.text
    assert 'id="run-limit" type="number" min="0" max="10000"' not in schedules.text
    assert '/static/harvestview/schedules.css?v=' in schedules.text
    assert '/static/harvestview/schedules.js?v=' in schedules.text
    assert stylesheet.status_code == 200
    assert script.status_code == 200
    assert remote.status_code == 403


def test_harvestview_has_an_operator_readable_shodan_host_route(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        script = client.get('/static/harvestview/app.js')

    assert script.status_code == 200
    assert "'shodan-host'" in script.text
    assert "'Shodan hosts'" in script.text
    assert 'function shodanNetworkFormatter' in script.text
    assert 'function shodanServicesFormatter' in script.text
    assert 'details.hostnames' in script.text
    assert 'details.domains' in script.text
    assert 'service.observed_at' in script.text
    assert 'service.cpes' in script.text
    assert 'http.components' in script.text
    assert 'service.tls' in script.text
    assert 'tls.subject_alt_names' in script.text
    assert "title: 'Network'" in script.text
    assert "title: 'Services'" in script.text


def test_harvestview_offers_jsonl_and_sqlite_imports_and_exports(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        script = client.get('/static/harvestview/app.js')

    assert 'accept=".jsonl,.sqlite,.sqlite3,.db,application/x-ndjson,application/vnd.sqlite3"' in root.text
    assert 'id="export-database-button"' in root.text
    assert 'id="export-jsonl-button"' in root.text
    assert 'id="route-csv-button"' not in root.text
    assert 'id="export-json-button"' not in root.text
    assert 'id="export-csv-button"' not in root.text
    assert '/export' in script.text
    assert '/api/v1/runs/export-database' in script.text
    assert 'theharvester-completed-runs.sqlite' in script.text
    assert "fileKind === 'jsonl' ? '/api/v1/runs/import' : '/api/v1/runs/import-database'" in script.text
    assert '/exports/' not in script.text
    assert 'text/csv' not in script.text
    assert 'versioned JSONL' not in root.text
    assert 'interesting-url' not in script.text
    assert 'api-endpoint' not in script.text
    assert 'linkedin-link' not in script.text


def test_harvestview_loads_pinned_tabulator_from_cdnjs(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        root = client.get('/')
        schedules = client.get('/schedules')
        theme = client.get('/static/harvestview/tabulator.min.css')
        script = client.get('/static/harvestview/tabulator.min.js')
        license_file = client.get('/static/harvestview/TABULATOR-LICENSE')
        bootstrap = client.get('/static/harvestview/bootstrap.min.css')
        old_theme = client.get('/static/harvestview/tabulator_bootstrap5.min.css')

    assert root.status_code == 200
    assert schedules.status_code == 200
    assert 'bootstrap.min.css' not in root.text
    assert 'tabulator_bootstrap5.min.css' not in root.text
    assert (
        '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/css/tabulator.min.css" '
        'integrity="sha512-t8I/asqzdu/MRgVLxVanQ/c5bhUA1qZ/zA432a/3nUh0kkd7P8Qch35wQvTODivf9D6Xv3h7F8p7ezcUyBOQrQ==" '
        'crossorigin="anonymous" referrerpolicy="no-referrer">'
    ) in root.text
    assert (
        '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/css/tabulator.min.css" '
        'integrity="sha512-t8I/asqzdu/MRgVLxVanQ/c5bhUA1qZ/zA432a/3nUh0kkd7P8Qch35wQvTODivf9D6Xv3h7F8p7ezcUyBOQrQ==" '
        'crossorigin="anonymous" referrerpolicy="no-referrer">'
    ) in schedules.text
    assert (
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/js/tabulator.min.js" '
        'integrity="sha512-AF0YMSgc0Ui4IJPb4hJNSi16wFidZEQa6ZTCAeguF3h5glVnAPuz/JT2ai9ypKhsc9n6CEXBB+tMdxsv1q+rxg==" '
        'crossorigin="anonymous" referrerpolicy="no-referrer"></script>'
    ) in root.text
    assert (
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/js/tabulator.min.js" '
        'integrity="sha512-AF0YMSgc0Ui4IJPb4hJNSi16wFidZEQa6ZTCAeguF3h5glVnAPuz/JT2ai9ypKhsc9n6CEXBB+tMdxsv1q+rxg==" '
        'crossorigin="anonymous" referrerpolicy="no-referrer"></script>'
    ) in schedules.text
    assert 'https://unpkg.com' not in root.text
    assert theme.status_code == 404
    assert script.status_code == 404
    assert license_file.status_code == 404
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
