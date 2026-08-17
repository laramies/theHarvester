from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from theHarvester.lib.completed_result import parse_result_jsonl
from theHarvester.lib.source_catalog import ACTION_ACTIVITIES, RESULT_CAPABILITIES, SOURCE_SPECS

OPTIONAL_API_KEY_SOURCES = {'hackertarget', 'mojeek', 'windvane'}
SOURCE_ROUTE_ORDER = ('subdomains', 'emails', 'ips', 'asns', 'urls', 'people', 'breaches')
API_KEY_SOURCE_ALIASES = {
    'github': {'github-code'},
    'pentestTools': {'pentesttools'},
    'projectDiscovery': {'projectdiscovery'},
}
SOURCE_PROVIDER_LINKS = {
    'apis-guru': 'https://apis.guru/',
    'arquivo': 'https://arquivo.pt/',
    'baidu': 'https://www.baidu.com/',
    'bevigil': 'https://bevigil.com/osint-api',
    'bufferoverun': 'https://tls.bufferover.run/',
    'builtwith': 'https://builtwith.com/',
    'brave': 'https://brave.com/search/api/',
    'censys': 'https://search.censys.io/',
    'certspotter': 'https://sslmate.com/certspotter/',
    'commoncrawl': 'https://commoncrawl.org/',
    'criminalip': 'https://www.criminalip.io/',
    'crt-name': 'https://crt.name/',
    'crtsh': 'https://crt.sh/',
    'dehashed': 'https://dehashed.com/',
    'dnsdb': 'https://docs.domaintools.com/api/dnsdb/',
    'dnsdumpster': 'https://dnsdumpster.com/',
    'duckduckgo': 'https://duckduckgo.com/',
    'dymo': 'https://docs.tpeoficial.com/docs/dymo-api/private/data-verifier',
    'fofa': 'https://en.fofa.info/',
    'fullhunt': 'https://fullhunt.io/',
    'github-code': 'https://github.com/',
    'gitlab': 'https://gitlab.com/',
    'hackertarget': 'https://hackertarget.com/',
    'haveibeenpwned': 'https://haveibeenpwned.com/',
    'hibpverified': 'https://haveibeenpwned.com/API/v3#BreachedDomain',
    'hudsonrock': 'https://www.hudsonrock.com/',
    'hunter': 'https://hunter.io/',
    'hunterhow': 'https://hunter.how/',
    'intelx': 'https://intelx.io/',
    'leakix': 'https://leakix.net/',
    'leaklookup': 'https://leak-lookup.com/',
    'mojeek': 'https://www.mojeek.com/services/search/web-search-api/',
    'netlas': 'https://netlas.io/',
    'onyphe': 'https://www.onyphe.io/',
    'otx': 'https://otx.alienvault.com/',
    'pentesttools': 'https://pentest-tools.com/',
    'projectdiscovery': 'https://chaos.projectdiscovery.io/',
    'rapiddns': 'https://rapiddns.io/',
    'robtex': 'https://www.robtex.com/',
    'rocketreach': 'https://rocketreach.co/',
    'securityscorecard': 'https://securityscorecard.com/',
    'securityTrails': 'https://securitytrails.com/',
    'sherlockeye': 'https://sherlockeye.io/',
    'shodan': 'https://www.shodan.io/',
    'shodanInternetDB': 'https://internetdb.shodan.io/',
    'shodanct': 'https://ctl.shodan.io/',
    'sourcegraph': 'https://sourcegraph.com/search',
    'subdomaincenter': 'https://www.subdomain.center/',
    'subdomainfinderc99': 'https://subdomainfinder.c99.nl/',
    'thc': 'https://ip.thc.org/',
    'tomba': 'https://tomba.io/',
    'urlscan': 'https://urlscan.io/',
    'virustotal': 'https://www.virustotal.com/',
    'waybackarchive': 'https://web.archive.org/',
    'whoisxml': 'https://subdomains.whoisxmlapi.com/',
    'windvane': 'https://windvane.lichoin.com/',
    'yahoo': 'https://www.yahoo.com/',
    'zoomeye': 'https://www.zoomeye.ai/',
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
    'Virtual-Host-Discovery.md',
    '_Footer.md',
    '_Sidebar.md',
}


def _declared_source_contracts() -> dict[str, set[str]]:
    return {source: set(spec.capabilities) for source, spec in SOURCE_SPECS.items()}


def _source_matrix(readme: str) -> str:
    return readme.split('<summary><strong>View all 58 discovery sources</strong></summary>', 1)[1].split('</details>', 1)[0]


def _documented_source_rows(readme: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in _source_matrix(readme).splitlines():
        if line.startswith('| [`'):
            cells = [cell.strip() for cell in line.strip('|').split('|')]
            source = re.fullmatch(r'\[`([^`]+)`\]\((https://[^)]+)\)', cells[0])
            assert source is not None
            rows[source.group(1)] = cells[1:]
    return rows


def _documented_source_links(readme: str) -> list[tuple[str, str]]:
    return [
        (match.group(1), match.group(2))
        for line in _source_matrix(readme).splitlines()
        if (match := re.match(r'^\| \[`([^`]+)`\]\((https://[^)]+)\)', line))
    ]


def _documented_source_contracts(readme: str) -> dict[str, set[str]]:
    return {
        source: {route.strip().removesuffix(' only') for route in cells[0].split(',')}
        for source, cells in _documented_source_rows(readme).items()
    }


def _documented_source_activities(readme: str) -> dict[str, str]:
    return {source: cells[1] for source, cells in _documented_source_rows(readme).items()}


def _documented_api_key_requirements(readme: str) -> dict[str, str]:
    return {source: cells[-1] for source, cells in _documented_source_rows(readme).items()}


def _configured_api_key_sources() -> set[str]:
    configured = yaml.safe_load(Path('theHarvester/data/api-keys.yaml').read_text())['apikeys']
    return set().union(*(API_KEY_SOURCE_ALIASES.get(source, {source}) for source in configured))


def test_readme_matches_declared_source_contracts() -> None:
    readme = Path('README.md').read_text()
    documented = _documented_source_contracts(readme)
    declared = _declared_source_contracts()

    assert _source_matrix(readme).count('| Source | Returns | Activity | API key |') == 1
    assert 'Credentials |' not in _source_matrix(readme)
    assert len(declared) == 58
    assert len(documented) == 58
    assert documented == declared
    source_links = _documented_source_links(readme)
    assert len(source_links) == len(declared)
    assert dict(source_links) == SOURCE_PROVIDER_LINKS
    assert _documented_source_activities(readme) == {source: spec.activity.value for source, spec in SOURCE_SPECS.items()}
    assert {'securitytrails', 'shodaninternetdb'}.isdisjoint(documented)


def test_readme_source_matrix_is_one_table_and_ordered() -> None:
    readme = Path('README.md').read_text()
    matrix = _source_matrix(readme)
    rows = _documented_source_rows(readme)
    names = list(rows)

    assert '#### Subdomain-only sources' not in matrix
    assert '#### Sources that return other results' not in matrix
    assert names == sorted(names, key=str.casefold)

    route_rank = {route: index for index, route in enumerate(SOURCE_ROUTE_ORDER)}
    for source, (routes, *_) in rows.items():
        documented_order = [route.strip().removesuffix(' only') for route in routes.split(',')]
        assert documented_order == sorted(documented_order, key=route_rank.__getitem__)
        assert routes.endswith(' only') == (len(SOURCE_SPECS[source].capabilities) == 1)


def test_readme_api_key_markers_match_configuration() -> None:
    readme = Path('README.md').read_text()
    requirements = _documented_api_key_requirements(readme)
    configured_source_keys = _configured_api_key_sources() - {'routeviews'}

    assert set(requirements.values()) <= {'Required', 'Optional', 'No'}
    assert {source for source, marker in requirements.items() if marker != 'No'} == configured_source_keys
    assert '`routeviews.key`' in readme
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


def test_wiki_examples_use_copy_safe_operator_language() -> None:
    quick_start = Path('docs/wiki/Quick-Start.md').read_text()
    configuration = Path('docs/wiki/Configuration-and-API-Keys.md').read_text()

    assert 'inert test data' not in quick_start
    assert 'Passive providers still receive the target string.' in quick_start
    assert '${EDITOR:-vi}' not in configuration
    assert 'vi ~/.theHarvester/api-keys.yaml' in configuration


def test_readme_architecture_diagrams_are_local_and_accessible() -> None:
    readme = Path('README.md').read_text()
    diagrams = (
        (
            'theHarvester discovery routes and enrichment',
            Path('docs/images/run-evidence-architecture.svg'),
            'run-evidence-architecture',
            ('58 discovery adapters', 'CompletedResult evidence contract', 'Terminal · JSONL · SQLite · REST'),
        ),
        (
            'HarvestView run desk architecture',
            Path('docs/images/harvestview-architecture.svg'),
            'harvestview-architecture',
            ('Authenticated REST API', 'queued · running', 'Isolated run worker', 'JSONL · one run'),
        ),
    )

    for alt, svg, slug, expected_text in diagrams:
        svg_text = svg.read_text()
        assert f'[![{alt}]({svg})]({svg})' in readme
        assert 'role="img"' in svg_text
        assert f'<title id="{slug}-title">' in svg_text
        assert f'<desc id="{slug}-desc">' in svg_text
        assert 'viewBox="0 0 960 640"' in svg_text
        assert '@media (prefers-color-scheme: light)' in svg_text
        assert "font: 600 16px 'Geist'" in svg_text
        assert all(text in svg_text for text in expected_text)

    run_diagram = diagrams[0][1].read_text()
    harvestview_diagram = diagrams[1][1].read_text()
    assert all(capability in run_diagram for capability in RESULT_CAPABILITIES)
    assert all(action in run_diagram for action in ACTION_ACTIVITIES)
    assert f'{len(SOURCE_SPECS)} discovery adapters' in run_diagram
    assert f'{len(ACTION_ACTIVITIES)} explicit actions' in harvestview_diagram


def test_wiki_diagrams_are_local_accessible_and_used_deliberately() -> None:
    raw_root = 'https://raw.githubusercontent.com/laramies/theHarvester/dev/'
    diagrams = (
        (
            Path('docs/wiki/Virtual-Host-Discovery.md'),
            'Bounded virtual-host sweep',
            Path('docs/images/vhost-sweep-overview.svg'),
            'vhost-sweep-overview',
            ('exact target scope', 'Literal-IP endpoint pool', 'shared request cap', '3 shape-matched controls'),
        ),
        (
            Path('docs/wiki/Virtual-Host-Discovery.md'),
            'Virtual-host response classifier',
            Path('docs/images/vhost-classifier.svg'),
            'vhost-classifier',
            ('All responses usable', 'Candidate matches', 'Repeat candidate request', 'Retain hostname'),
        ),
        (
            Path('docs/wiki/Operator-Workflows.md'),
            'theHarvester discovery routes and enrichment',
            Path('docs/images/run-evidence-architecture.svg'),
            'run-evidence-architecture',
            (),
        ),
        (
            Path('docs/wiki/Rest-API.md'),
            'HarvestView run desk architecture',
            Path('docs/images/harvestview-architecture.svg'),
            'harvestview-architecture',
            (),
        ),
    )

    for page, alt, svg, slug, expected_text in diagrams:
        svg_text = svg.read_text()
        assert f'![{alt}]({raw_root}{svg})' in page.read_text()
        assert 'role="img"' in svg_text
        assert f'<title id="{slug}-title">' in svg_text
        assert f'<desc id="{slug}-desc">' in svg_text
        assert all(text in svg_text for text in expected_text)

    assert '```mermaid' not in Path('docs/wiki/Virtual-Host-Discovery.md').read_text()


def test_virtual_host_wiki_examples_match_the_structured_result_contract() -> None:
    page = Path('docs/wiki/Virtual-Host-Discovery.md').read_text()

    assert '-b rapiddns \\\n  --vhost' in page
    assert '"sources": ["rapiddns"]' in page
    assert '"type": "hostname"' in page
    assert '"value": "admin.authorized.example"' in page
    assert '"actions": ["vhost"]' in page
    assert '"observations": [' in page
    assert page.count('"endpoint": "https://192.0.2.') == 2
    assert '"source": "action:vhost"' not in page
    assert 'schema_version' not in page

    json_examples = re.findall(r'```json\n(.*?)\n```', page, flags=re.DOTALL)
    finding = next(
        json.loads(example) for example in json_examples if '"type": "hostname"' in example and '"observations"' in example
    )
    assert finding['value'] == 'admin.authorized.example'
    assert finding['actions'] == ['vhost']
    assert len(finding['observations']) == 2


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


def test_operator_docs_recommend_jsonl_and_assume_uv_is_available() -> None:
    readme = Path('README.md').read_text()
    installation = Path('docs/wiki/Installation.md').read_text()
    quick_start = Path('docs/wiki/Quick-Start.md').read_text()
    workflows = Path('docs/wiki/Operator-Workflows.md').read_text()

    assert '## Package versions' in readme
    assert 'https://repology.org/badge/vertical-allrepos/theharvester.svg' in readme
    assert 'https://repology.org/project/theharvester/versions' in readme
    assert 'curl -LsSf https://astral.sh/uv/install.sh' not in readme
    assert 'curl -LsSf https://astral.sh/uv/install.sh' not in installation
    assert all('`report.jsonl`' in page and 'automation' in page for page in (quick_start, workflows))


def test_operator_docs_cover_portable_database_export() -> None:
    readme = Path('README.md').read_text()
    rest_api = Path('docs/wiki/Rest-API.md').read_text()
    local_data = Path('docs/wiki/Results-and-Local-Data.md').read_text()

    assert all('/api/v1/runs/export-database' in page for page in (readme, rest_api, local_data))
    assert 'queue state, cancellation state, worker leases, and legacy observations' in rest_api
    assert 'no manual WAL handling is required' in rest_api


def test_readme_explains_jsonl_record_and_structured_evidence_parsing() -> None:
    readme = Path('README.md').read_text()
    example = re.search(r'```jsonl\n(.*?)\n```', readme, flags=re.DOTALL)
    assert example is not None
    summary, findings = parse_result_jsonl(example.group(1))

    finding_types = ('asn', 'breach', 'email', 'hostname', 'ip', 'url')
    assert summary['counts'] == {result_type: 1 for result_type in finding_types}
    assert summary['result_count'] == len(findings) == 6
    assert tuple(finding['type'] for finding in findings) == finding_types
    assert all(finding['sources'] for finding in findings)
    assert {execution['source'] for execution in summary['source_executions']} == {'haveibeenpwned', 'zoomeye'}
    for result_kind in ('hostname', 'ip', 'asn', 'email', 'url', 'person', 'breach'):
        assert f'select(.type == "{result_kind}")' in readme
    assert 'select(.type == "person") | .value | fromjson' in readme
    assert 'select(.type == "dns-recursive-finding") | .value | fromjson' in readme
    assert 'JSONL is the primary format for automation and one-run interchange.' in readme
    assert '`person`, `infostealer`' in readme
    assert 'Takeover results keep the hostname in `value`' in readme
    assert 'DNS, wildcard, HTTP, rule, status, and error evidence in `details`' in readme
    assert 'select(.type == "shodan-host") | {ip: .value, services: .details.services}' in readme
    assert 'select(.type == "hostname" and .observations) | {hostname: .value, observations}' in readme
    assert 'select(.type == "asn" and .observations) | {asn: .value, observations}' in readme
