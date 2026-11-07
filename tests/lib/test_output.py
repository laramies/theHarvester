from __future__ import annotations

from theHarvester.lib.output import sorted_unique


def test_sorted_unique_sorts_and_deduplicates() -> None:
    assert sorted_unique(['b', 'a', 'b']) == ['a', 'b']
