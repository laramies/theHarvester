import json
import sys
from pathlib import Path

import pytest

from theHarvester import __main__ as theharvester_main
from theHarvester.lib.completed_result import CompletedResult


@pytest.mark.asyncio
async def test_generic_people_reach_completed_result_and_jsonl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed_results: list[CompletedResult] = []

    class FakeStash:
        async def do_init(self) -> None:
            return None

        async def store_all(self, *_args) -> None:
            return None

        async def store_completed_result(self, result: CompletedResult) -> None:
            completed_results.append(result)

    class FakeVenacus:
        def __init__(self, *, word: str, limit: int, offset_doc: int) -> None:
            assert (word, limit, offset_doc) == ('example.com', 500, 0)

        async def process(self, _proxy: bool) -> None:
            return None

        async def get_people(self) -> list[dict[str, str]]:
            return [
                {'lastname': 'Lovelace', 'firstname': 'Ada'},
                {'firstname': 'Ada', 'lastname': 'Lovelace'},
            ]

        async def get_emails(self) -> set[str]:
            return set()

        async def get_ips(self) -> set[str]:
            return set()

        async def get_interestingurls(self) -> set[str]:
            return set()

    report = tmp_path / 'people-report'
    monkeypatch.setattr(theharvester_main.stash, 'StashManager', FakeStash)
    monkeypatch.setattr(theharvester_main.venacussearch, 'SearchVenacus', FakeVenacus)
    monkeypatch.setattr(
        sys,
        'argv',
        ['theHarvester', '-d', 'example.com', '-b', 'venacus', '-f', str(report)],
    )

    with pytest.raises(SystemExit) as exit_info:
        await theharvester_main.start()

    assert exit_info.value.code == 0
    person = '{"firstname":"Ada","lastname":"Lovelace"}'
    assert completed_results[0].results.count(('person', person)) == 1
    records = [json.loads(line) for line in report.with_suffix('.jsonl').read_text().splitlines()]
    assert {'type': 'person', 'value': person} in records
