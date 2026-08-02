import pytest

from theHarvester.discovery import securityscorecard


@pytest.mark.asyncio
async def test_process_reports_non_200_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', lambda: 'dummy-key')

    class FakeResponse:
        status = 503

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    class FakeSession:
        def __init__(self, **_kwargs):
            pass

        def get(self, *_args, **_kwargs):
            return FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(securityscorecard.aiohttp, 'ClientSession', FakeSession)

    search = securityscorecard.SearchSecurityScorecard('example.com')
    with pytest.raises(RuntimeError, match='SecurityScorecard returned HTTP 503'):
        await search.process()
