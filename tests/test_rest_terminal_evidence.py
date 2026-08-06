from argparse import Namespace

from fastapi.testclient import TestClient

from theHarvester.lib.api import api


def test_query_requests_completed_result_persistence(monkeypatch) -> None:
    persistence_flags: list[bool] = []

    async def fake_start(args: Namespace, *, persist_completed_result: bool = False):
        persistence_flags.append(persist_completed_result)
        return ([], [], [], [], [], [], [], [], [])

    monkeypatch.setattr(api.__main__, 'start', fake_start)

    response = TestClient(api.app).get('/query?domain=example.test&source=crtsh')

    assert response.status_code == 200
    assert persistence_flags == [True]
