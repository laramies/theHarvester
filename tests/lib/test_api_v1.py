from __future__ import annotations

from fastapi.testclient import TestClient


def test_api_exposes_one_versioned_run_contract(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)) as client:
        schema = client.get('/openapi.json').json()
        paths = set(schema['paths'])
        old_responses = [
            client.get('/'),
            client.get('/query?domain=example.test&source=crtsh'),
            client.get('/sources'),
            client.get('/dnsbrute?domain=example.test'),
            client.get('/runs'),
            client.post('/additional/all', json={'domain': 'example.test'}),
        ]

    assert paths == {
        '/api/v1/sources',
        '/api/v1/runs',
        '/api/v1/runs/import',
        '/api/v1/runs/{run_id}',
        '/api/v1/runs/{run_id}/cancel',
        '/api/v1/runs/{run_id}/exports/{format}',
        '/api/v1/runs/{run_id}/screenshots/{name}',
    }
    assert all(response.status_code == 404 for response in old_responses)


def test_screenshot_route_serves_only_a_run_owned_png(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_ARTIFACTS', str(tmp_path / 'artifacts'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
    headers = {'X-API-Key': 'test-key'}

    with TestClient(api.app) as client:
        imported = client.post(
            '/api/v1/runs/import',
            params={'filename': 'smoke.json'},
            headers=headers,
            json={'cmd': 'theHarvester -d example.test -b crtsh', 'hosts': ['www.example.test']},
        )
        assert imported.status_code == 201
        run_id = imported.json()['run_id']
        screenshot_dir = tmp_path / 'artifacts' / run_id / 'screenshots'
        screenshot_dir.mkdir(parents=True)
        (screenshot_dir / 'owned.png').write_bytes(b'owned screenshot')
        outside = tmp_path / 'outside.png'
        outside.write_bytes(b'outside screenshot')
        (screenshot_dir / 'linked.png').symlink_to(outside)

        owned = client.get(f'/api/v1/runs/{run_id}/screenshots/owned.png', headers=headers)
        linked = client.get(f'/api/v1/runs/{run_id}/screenshots/linked.png', headers=headers)
        traversal = client.get(f'/api/v1/runs/{run_id}/screenshots/%2E%2E%2Foutside.png', headers=headers)

    assert owned.status_code == 200
    assert owned.content == b'owned screenshot'
    assert linked.status_code == 404
    assert traversal.status_code == 404


def test_openapi_names_the_public_response_shapes(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        schema = client.get('/openapi.json').json()

    paths = schema['paths']
    assert paths['/api/v1/sources']['get']['responses']['200']['content']['application/json']['schema']['items'] == {
        '$ref': '#/components/schemas/SourceResponse'
    }
    assert paths['/api/v1/runs']['get']['responses']['200']['content']['application/json']['schema']['items'] == {
        '$ref': '#/components/schemas/RunSummary'
    }
    for path, method in (
        ('/api/v1/runs', 'post'),
        ('/api/v1/runs/import', 'post'),
        ('/api/v1/runs/{run_id}', 'get'),
        ('/api/v1/runs/{run_id}/cancel', 'post'),
    ):
        assert paths[path][method]['responses']['201' if path in {'/api/v1/runs', '/api/v1/runs/import'} else '200']['content'][
            'application/json'
        ]['schema'] == {'$ref': '#/components/schemas/RunDetail'}


def test_openapi_explains_scope_and_execution_controls(tmp_path, monkeypatch) -> None:
    from theHarvester.lib.api import api

    monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-key')
    monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')

    with TestClient(api.app) as client:
        schema = client.get('/openapi.json').json()

    request_body = schema['paths']['/api/v1/runs']['post']['requestBody']
    properties = request_body['content']['application/json']['schema']['properties']

    assert request_body['required'] is True
    assert 'union' in properties['sources']['description']
    assert 'do not filter' in properties['sources']['description']
    assert '/24' in properties['dns_lookup']['description']
    assert 'whole run' in properties['deadline_seconds']['description']
    assert 'three resolver' in properties['dns_recursive_query_limit']['description']
    assert 'discovery sources' in properties['proxies']['description']
    assert 'configured proxies' in properties['take_over']['description']
    import_content = schema['paths']['/api/v1/runs/import']['post']['requestBody']['content']
    assert set(import_content) == {'application/json', 'application/x-ndjson'}
    export_content = schema['paths']['/api/v1/runs/{run_id}/exports/{format}']['get']['responses']['200']['content']
    assert set(export_content) == {'application/json', 'text/csv'}
    assert export_content['application/json']['schema'] == {'$ref': '#/components/schemas/RunExport'}
    assert set(schema['components']['schemas']['RunExport']['properties']) == {
        'run_id',
        'evidence_run_id',
        'target',
        'lifecycle_status',
        'evidence_status',
        'created_at',
        'started_at',
        'completed_at',
        'request',
        'source_executions',
        'results',
    }
    assert set(schema['components']['schemas']['NormalizedResult']['properties']) == {'type', 'value', 'dns_status'}
    assert export_content['text/csv']['schema']['description'] == 'UTF-8 CSV with type, value, and dns_status columns.'

    def references(value):
        if isinstance(value, dict):
            if '$ref' in value:
                yield value['$ref']
            for child in value.values():
                yield from references(child)
        elif isinstance(value, list):
            for child in value:
                yield from references(child)

    components = schema['components']['schemas']
    for reference in references(schema):
        assert reference.startswith('#/components/schemas/')
        assert reference.removeprefix('#/components/schemas/') in components
