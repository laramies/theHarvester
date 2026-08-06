from __future__ import annotations

import re
from pathlib import Path

import yaml

from theHarvester.lib.source_catalog import SOURCE_SPECS, ResultRoute

RESULT_COLUMNS = ('Subdomains', 'Emails', 'IPs', 'ASNs', 'URLs / links', 'People')
ROUTE_COLUMNS = {
    ResultRoute.SUBDOMAINS: 'Subdomains',
    ResultRoute.EMAILS: 'Emails',
    ResultRoute.IPS: 'IPs',
    ResultRoute.ASNS: 'ASNs',
    ResultRoute.LINKS: 'URLs / links',
    ResultRoute.INTERESTING_URLS: 'URLs / links',
    ResultRoute.PEOPLE: 'People',
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


def _declared_source_contracts() -> dict[str, set[str]]:
    return {source: {ROUTE_COLUMNS[route] for route in spec.routes} for source, spec in SOURCE_SPECS.items()}


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
        assert set(markers) <= {'✓', 'No'}
        contracts[source] = {column for column, marker in zip(RESULT_COLUMNS, markers, strict=True) if marker == '✓'}
    return contracts


def _documented_api_key_requirements(readme: str) -> dict[str, str]:
    return {source: cells[-1] for source, cells in _documented_source_rows(readme).items()}


def _configured_api_key_sources() -> set[str]:
    configured = yaml.safe_load(Path('theHarvester/data/api-keys.yaml').read_text())['apikeys']
    return set().union(*(API_KEY_SOURCE_ALIASES.get(source, {source}) for source in configured))


def test_readme_matches_declared_source_contracts() -> None:
    readme = Path('README.md').read_text()
    documented = _documented_source_contracts(readme)
    declared = _declared_source_contracts()

    assert '| Source | Subdomains | Emails | IPs | ASNs | URLs / links | People |' in readme
    assert len(declared) == 55
    assert len(documented) == 55
    assert documented == declared
    assert {'securitytrails', 'shodaninternetdb'}.isdisjoint(documented)


def test_readme_api_key_markers_match_configuration() -> None:
    requirements = _documented_api_key_requirements(Path('README.md').read_text())

    assert set(requirements.values()) <= {'✓', 'Optional', 'No'}
    assert {source for source, marker in requirements.items() if marker != 'No'} == _configured_api_key_sources()
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


def test_readme_preserves_project_social_attribution() -> None:
    readme = Path('README.md').read_text()
    profiles = {
        'Christian Martorella': 'laramies',
        'Matt Brown': 'NotoriousRebel1',
        'Jay "L1ghtn1ng" Townsend': 'jay_townsend1',
        'Lee Baird': 'discoverscripts',
    }

    for name, handle in profiles.items():
        assert name in readme
        assert f'https://twitter.com/{handle}' in readme
        assert f'@{handle}' in readme
