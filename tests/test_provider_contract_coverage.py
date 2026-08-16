from collections import Counter

from theHarvester.lib.source_catalog import SOURCE_SPECS


def _provider_contract_problems(
    sources: tuple[str, ...],
    canonical_sources: set[str],
) -> list[str]:
    counts = Counter(sources)
    marked_sources = set(counts)
    problems: list[str] = []
    if unknown := sorted(marked_sources - canonical_sources):
        problems.append(f'unknown provider contracts: {", ".join(unknown)}')
    if duplicates := sorted(source for source, count in counts.items() if count > 1):
        problems.append(f'duplicate provider contracts: {", ".join(duplicates)}')
    if missing := sorted(canonical_sources - marked_sources):
        problems.append(f'missing provider contracts: {", ".join(missing)}')
    return problems


def test_every_canonical_source_has_one_offline_provider_contract(
    provider_contract_sources: tuple[str, ...],
) -> None:
    problems = _provider_contract_problems(provider_contract_sources, set(SOURCE_SPECS))
    assert not problems, '; '.join(problems)


def test_provider_contract_failures_name_unknown_duplicate_and_missing_sources() -> None:
    assert _provider_contract_problems(('known', 'known', 'unknown'), {'known', 'missing'}) == [
        'unknown provider contracts: unknown',
        'duplicate provider contracts: known',
        'missing provider contracts: missing',
    ]
