from __future__ import annotations


from theHarvester.lib.output import print_linkedin_sections, sorted_unique


def test_sorted_unique_sorts_and_deduplicates() -> None:
    assert sorted_unique(["b", "a", "b"]) == ["a", "b"]


def test_print_linkedin_sections_prints_links_when_present(capsys) -> None:
    # Regression coverage: the CLI previously never printed LinkedIn links when the list was non-empty.
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
