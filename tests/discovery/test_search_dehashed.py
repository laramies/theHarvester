import pytest

from theHarvester.discovery.search_dehashed import SearchDehashed
from theHarvester.lib.output import configure_logging


@pytest.mark.asyncio
async def test_csv_output_redacts_password(capsys) -> None:
    configure_logging(verbose=False)
    search = SearchDehashed.__new__(SearchDehashed)
    search.data = [{'email': 'user@example.com', 'password': 'secret-password'}]

    await search.print_csv_results()

    output = capsys.readouterr().out
    assert 'secret-password' not in output
    assert '[REDACTED]' in output
