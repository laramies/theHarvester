from __future__ import annotations

import ast
from pathlib import Path

RESULT_COLUMNS = ('Hosts', 'Emails', 'IPs', 'ASNs', 'URLs / links', 'People')
STORE_RESULT_COLUMNS = {
    'store_host': {'Hosts'},
    'store_emails': {'Emails'},
    'store_ip': {'IPs'},
    'store_asns': {'ASNs'},
    'store_links': {'URLs / links'},
    'store_interestingurls': {'URLs / links'},
    'store_people': {'People'},
    'store_results': {'Hosts', 'Emails', 'URLs / links'},
}
# These enabled store() flags cannot currently produce the named report field.
UNAVAILABLE_STORE_RESULTS = {
    'haveibeenpwned': {'Emails'},  # The adapter never populates its email set.
    'netlas': {'IPs'},  # The adapter has no get_ips() method.
    'securityscorecard': {'ASNs', 'URLs / links'},  # The adapter has neither getter.
}


def _source_name(node: ast.If) -> str | None:
    test = node.test
    if (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == 'engineitem'
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and isinstance(test.comparators[0].value, str)
    ):
        return test.comparators[0].value
    return None


def _executable_source_contracts() -> dict[str, set[str]]:
    tree = ast.parse(Path('theHarvester/__main__.py').read_text())
    contracts: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or (source := _source_name(node)) is None:
            continue
        calls = [
            child
            for statement in node.body
            for child in ast.walk(statement)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == 'store'
        ]
        assert len(calls) == 1, f'{source} must have exactly one store() call'
        enabled = {
            keyword.arg
            for keyword in calls[0].keywords
            if keyword.arg in STORE_RESULT_COLUMNS and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        }
        contracts[source] = set().union(*(STORE_RESULT_COLUMNS[name] for name in enabled)) - UNAVAILABLE_STORE_RESULTS.get(
            source, set()
        )
    return contracts


def _documented_source_contracts(readme: str) -> dict[str, set[str]]:
    matrix = readme.split('<summary><strong>View the source and result matrix</strong></summary>', 1)[1].split('</details>', 1)[0]
    contracts: dict[str, set[str]] = {}
    for line in matrix.splitlines():
        if not line.startswith('| `'):
            continue
        cells = [cell.strip() for cell in line.strip('|').split('|')]
        source = cells[0].strip('`')
        markers = cells[1:7]
        assert set(markers) <= {'✓', '—'}
        contracts[source] = {column for column, marker in zip(RESULT_COLUMNS, markers, strict=True) if marker == '✓'}
    return contracts


def test_readme_matches_executable_source_contracts() -> None:
    readme = Path('README.md').read_text()
    documented = _documented_source_contracts(readme)
    executable = _executable_source_contracts()

    assert len(executable) == 55
    assert len(documented) == 55
    assert documented == executable
    assert {'securitytrails', 'shodaninternetdb'}.isdisjoint(documented)
