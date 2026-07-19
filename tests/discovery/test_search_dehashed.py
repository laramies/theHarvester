import pytest

from theHarvester.discovery.search_dehashed import SearchDehashed


@pytest.mark.asyncio
async def test_process_does_not_output_credentials(monkeypatch, capsys) -> None:
    search = SearchDehashed.__new__(SearchDehashed)
    search.data = [{'email': 'user@example.com', 'password': 'secret-password'}]

    async def do_search() -> None:
        return None

    monkeypatch.setattr(search, 'do_search', do_search)
    await search.process()

    assert 'secret-password' not in capsys.readouterr().out
    assert await search.get_emails() == {'user@example.com'}
