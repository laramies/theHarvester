from __future__ import annotations

from collections.abc import Hashable, Iterable, Sequence
from typing import TypeVar

T = TypeVar('T', bound=Hashable)


def sorted_unique[T: Hashable](items: Iterable[T]) -> list[T]:
    # `T` is only required to be hashable, not orderable.
    # Sorting by `str` keeps output deterministic without requiring rich comparison support.
    return list(sorted(set(items), key=str))


def print_section(header: str, items: Iterable[str], separator: str) -> None:
    print(header)
    print(separator)
    for item in sorted_unique(items):
        print(item)


def print_linkedin_sections(
    engines: Sequence[str], people: Sequence[str], links: Sequence[str], separator: str = '---------------------'
) -> None:
    if len(people) == 0 and 'linkedin' in engines:
        print('\n[*] No LinkedIn users found.\n\n')
    elif len(people) >= 1:
        print('\n[*] LinkedIn Users found: ' + str(len(people)))
        print(separator)
        for usr in sorted_unique(people):
            print(usr)

    if 'linkedin' in engines or 'rocketreach' in engines:
        print(f'\n[*] LinkedIn Links found: {len(links)}')
        print(separator)
        for link in sorted_unique(links):
            print(link)
