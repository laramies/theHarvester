from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

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
OPTIONAL_API_KEY_SOURCES = {'hackertarget', 'leakix', 'mojeek', 'windvane'}
API_KEY_SOURCE_ALIASES = {
    'github': {'github-code'},
    'pentestTools': {'pentesttools'},
    'projectDiscovery': {'chaos', 'projectdiscovery'},
}
WIKI_PAGES = {
    'Configuration-and-API-Keys.md',
    'Contributing-and-Security.md',
    'Home.md',
    'How-to-add-a-new-module.md',
    'Installation.md',
    'Operator-Workflows.md',
    'Quick-Start.md',
    'Responsible-Use-and-Scope.md',
    'Rest-API.md',
    'Results-and-Local-Data.md',
    'Roadmap.md',
    'Troubleshooting.md',
    '_Footer.md',
    '_Sidebar.md',
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


def _documented_source_rows(readme: str) -> dict[str, list[str]]:
    matrix = readme.split('<summary><strong>View the source and result matrix</strong></summary>', 1)[1].split('</details>', 1)[0]
    rows: dict[str, list[str]] = {}
    for line in matrix.splitlines():
        if line.startswith('| `'):
            cells = [cell.strip() for cell in line.strip('|').split('|')]
            rows[cells[0].strip('`')] = cells[1:]
    return rows


def _documented_source_contracts(readme: str) -> dict[str, set[str]]:
    contracts: dict[str, set[str]] = {}
    for source, cells in _documented_source_rows(readme).items():
        markers = cells[:6]
        assert set(markers) <= {'✓', '—'}
        contracts[source] = {column for column, marker in zip(RESULT_COLUMNS, markers, strict=True) if marker == '✓'}
    return contracts


def _documented_api_key_requirements(readme: str) -> dict[str, str]:
    return {source: cells[-1] for source, cells in _documented_source_rows(readme).items()}


def _configured_api_key_sources() -> set[str]:
    configured = yaml.safe_load(Path('theHarvester/data/api-keys.yaml').read_text())['apikeys']
    return set().union(*(API_KEY_SOURCE_ALIASES.get(source, {source}) for source in configured))


def test_readme_matches_executable_source_contracts() -> None:
    readme = Path('README.md').read_text()
    documented = _documented_source_contracts(readme)
    executable = _executable_source_contracts()

    assert len(executable) == 55
    assert len(documented) == 55
    assert documented == executable
    assert {'securitytrails', 'shodaninternetdb'}.isdisjoint(documented)


def test_readme_api_key_markers_match_configuration() -> None:
    requirements = _documented_api_key_requirements(Path('README.md').read_text())

    assert set(requirements.values()) <= {'✓', 'Optional', '—'}
    assert {source for source, marker in requirements.items() if marker != '—'} == _configured_api_key_sources()
    assert {source for source, marker in requirements.items() if marker == 'Optional'} == OPTIONAL_API_KEY_SOURCES


def test_wiki_navigation_and_readme_links_resolve() -> None:
    wiki_dir = Path('docs/wiki')
    assert {path.name for path in wiki_dir.glob('*.md')} == WIKI_PAGES

    for page in wiki_dir.glob('*.md'):
        local_links = {
            target.split('#', 1)[0]
            for target in re.findall(r'\]\(([^)]+)\)', page.read_text())
            if '://' not in target and not target.startswith('mailto:')
        }
        assert {f'{target}.md' for target in local_links} <= WIKI_PAGES

    readme = Path('README.md').read_text()
    readme_wiki_links = re.findall(r'\]\((docs/wiki/[^)]+)\)', readme)
    assert readme_wiki_links
    assert all(Path(target).is_file() for target in readme_wiki_links)
