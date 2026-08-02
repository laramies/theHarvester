import pytest

from theHarvester.discovery import securityscorecard


@pytest.mark.asyncio
async def test_process_reports_non_200_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', lambda: 'dummy-key')

    async def fake_fetch(**_kwargs):
        raise RuntimeError('HTTP 503')

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)

    search = securityscorecard.SearchSecurityScorecard('example.com')
    with pytest.raises(RuntimeError, match='SecurityScorecard returned HTTP 503'):
        await search.process()


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', ['', {'error': 'unauthorized'}])
async def test_proxy_failure_is_not_reported_as_empty(
    monkeypatch: pytest.MonkeyPatch, payload: object
) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', lambda: 'dummy-key')

    async def fake_fetch(**kwargs):
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['json'] is True
        return payload

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)

    search = securityscorecard.SearchSecurityScorecard('example.com')
    with pytest.raises(ValueError, match='SecurityScorecard returned an invalid payload'):
        await search.process(proxy=True)


@pytest.mark.asyncio
async def test_malformed_payload_is_not_reported_as_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', lambda: 'dummy-key')

    async def fake_fetch(**_kwargs):
        return []

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)

    search = securityscorecard.SearchSecurityScorecard('example.com')
    with pytest.raises(ValueError, match='SecurityScorecard returned an invalid payload'):
        await search.process()


@pytest.mark.asyncio
async def test_process_uses_shared_transport_without_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(securityscorecard.Core, 'securityscorecard_key', lambda: 'dummy-key')

    async def fake_fetch(**kwargs):
        assert kwargs['proxy'] is False
        assert kwargs['json'] is True
        assert kwargs['fail_on_http_error'] is True
        assert kwargs['follow_redirects'] is False
        return {'domains': []}

    monkeypatch.setattr(securityscorecard.AsyncFetcher, 'fetch', fake_fetch)

    search = securityscorecard.SearchSecurityScorecard('example.com')
    await search.process()

    assert await search.get_hostnames() == set()
