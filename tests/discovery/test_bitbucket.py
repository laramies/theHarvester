import logging
from unittest.mock import AsyncMock

import pytest

from theHarvester.discovery import bitbucket


@pytest.mark.asyncio
async def test_process_does_not_log_error_body(monkeypatch, caplog) -> None:
    monkeypatch.setattr(bitbucket.Core, 'bitbucket_key', lambda: 'test-key')
    search = bitbucket.SearchBitBucket('owner/repository', limit=10)
    monkeypatch.setattr(
        search,
        'do_search',
        AsyncMock(return_value=('', {'secret': 'provider-secret-payload'}, 500, {})),
    )
    caplog.set_level(logging.INFO, logger=bitbucket.__name__)

    await search.process()

    assert 'provider-secret-payload' not in caplog.text
    assert '500' in caplog.text
