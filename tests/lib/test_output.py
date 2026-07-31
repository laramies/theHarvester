from __future__ import annotations

import json
from datetime import UTC, datetime
from xml.etree import ElementTree

import pytest

from theHarvester.lib.output import (
    configure_logging,
    evidence_xml_fragment,
    format_run_terminal,
    legacy_json_result,
    print_linkedin_sections,
    run_result_jsonl,
    sorted_unique,
)
from theHarvester.lib.run import SourceFinding, execute_run


class CompletedOutputSource:
    name = 'fixture'
    family = 'fixture'

    async def collect(self, _target: str) -> list[SourceFinding]:
        return [SourceFinding('api.example.com', observed_at=datetime(2026, 7, 31, tzinfo=UTC))]


@pytest.mark.asyncio
async def test_completed_run_adapters_share_one_result() -> None:
    result = await execute_run('example.com', (CompletedOutputSource(),))

    records = [json.loads(line) for line in run_result_jsonl(result).splitlines()]
    legacy = legacy_json_result(result, {'emails': ['ops@example.com']})
    evidence_xml = ElementTree.fromstring(evidence_xml_fragment(result))
    terminal = format_run_terminal(result)

    assert records[0]['schema_version'] == 'theharvester-results-v1'
    assert records[0]['counts'] == {'hostname': 1}
    assert records[1] == {'type': 'hostname', 'value': 'api.example.com', 'status': 'needs-review'}
    assert all('run_id' not in record and 'source' not in record for record in records)
    assert legacy['emails'] == ['ops@example.com']
    assert legacy['hosts'] == ['api.example.com']
    assert evidence_xml.attrib['run_id'] == result.run_id
    assert terminal.count('api.example.com') == 1


def test_sorted_unique_sorts_and_deduplicates() -> None:
    assert sorted_unique(["b", "a", "b"]) == ["a", "b"]


def test_print_linkedin_sections_prints_links_when_present(capsys) -> None:
    # Regression coverage: the CLI previously never printed LinkedIn links when the list was non-empty.
    configure_logging(verbose=False)
    print_linkedin_sections(
        engines=["linkedin"],
        people=[],
        links=["https://b.example", "https://a.example", "https://a.example"],
    )

    out = capsys.readouterr().out
    assert "No LinkedIn users found" in out
    assert "LinkedIn Links found: 3" in out
    assert "https://a.example" in out
    assert "https://b.example" in out


def test_print_linkedin_sections_prints_people_and_links(capsys) -> None:
    configure_logging(verbose=False)
    print_linkedin_sections(
        engines=["rocketreach"],
        people=["bob", "alice", "bob"],
        links=["https://z.example", "https://z.example"],
    )

    out = capsys.readouterr().out
    assert "LinkedIn Users found: 3" in out
    assert "alice" in out
    assert "bob" in out
    assert "LinkedIn Links found: 2" in out
    assert "https://z.example" in out
