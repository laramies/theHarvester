from __future__ import annotations

from theHarvester.lib.output import configure_logging, print_linkedin_people, sorted_unique


def test_sorted_unique_sorts_and_deduplicates() -> None:
    assert sorted_unique(['b', 'a', 'b']) == ['a', 'b']


def test_print_linkedin_people_reports_no_users(capsys) -> None:
    configure_logging(verbose=False)
    print_linkedin_people(engines=['linkedin'], people=[])

    out = capsys.readouterr().out
    assert 'No LinkedIn users found' in out


def test_print_linkedin_people_prints_people(capsys) -> None:
    configure_logging(verbose=False)
    print_linkedin_people(engines=['rocketreach'], people=['bob', 'alice', 'bob'])

    out = capsys.readouterr().out
    assert 'LinkedIn Users found: 3' in out
    assert 'alice' in out
    assert 'bob' in out
