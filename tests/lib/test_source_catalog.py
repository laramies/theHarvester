import ast
from pathlib import Path

from theHarvester.lib.core import Core
from theHarvester.lib.source_catalog import SOURCE_SPECS, ResultRoute, SourceSpec, get_source_spec


def _scheduled_source_names() -> list[str]:
    tree = ast.parse(Path('theHarvester/__main__.py').read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
            continue
        if not isinstance(node.left, ast.Name) or node.left.id != 'engineitem' or len(node.comparators) != 1:
            continue
        comparator = node.comparators[0]
        if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
            names.append(comparator.value)
    return names


def test_source_specs_cover_supported_sources() -> None:
    scheduled = _scheduled_source_names()

    assert len(scheduled) == len(set(scheduled))
    assert set(SOURCE_SPECS) == set(scheduled)
    assert set(SOURCE_SPECS) <= set(Core.get_supportedengines())


def test_source_capabilities_are_derived_from_result_routes() -> None:
    spec = SourceSpec(
        name='example',
        routes=frozenset(
            {
                ResultRoute.HOSTS,
                ResultRoute.LINKS,
                ResultRoute.INTERESTING_URLS,
            }
        ),
    )

    assert spec.capabilities == frozenset({'subdomains', 'urls'})


def test_source_specs_describe_consolidated_routes_not_getter_presence() -> None:
    assert SOURCE_SPECS['gitlab'].routes == frozenset({ResultRoute.HOSTS, ResultRoute.EMAILS})
    assert SOURCE_SPECS['haveibeenpwned'].routes == frozenset()
    assert SOURCE_SPECS['urlscan'].routes == frozenset(
        {
            ResultRoute.HOSTS,
            ResultRoute.IPS,
            ResultRoute.ASNS,
            ResultRoute.INTERESTING_URLS,
        }
    )


def test_source_specs_classify_provider_descendant_queries() -> None:
    expected = {
        'baidu',
        'bevigil',
        'brave',
        'bufferoverun',
        'certspotter',
        'chaos',
        'commoncrawl',
        'criminalip',
        'crtsh',
        'dnsdb',
        'dnsdumpster',
        'fofa',
        'fullhunt',
        'hackertarget',
        'hunterhow',
        'leakix',
        'netlas',
        'otx',
        'pentesttools',
        'projectdiscovery',
        'rapiddns',
        'robtex',
        'securityTrails',
        'subdomaincenter',
        'subdomainfinderc99',
        'thc',
        'threatcrowd',
        'urlscan',
        'virustotal',
        'waybackarchive',
        'whoisxml',
        'windvane',
        'zoomeye',
    }

    assert {spec.name for spec in SOURCE_SPECS.values() if spec.queries_provider_descendants} == expected


def test_capability_selection_preserves_every_declared_route() -> None:
    assert 'venacus' in Core.expand_source_selection('emails')
    assert get_source_spec('venacus').routes == frozenset(
        {
            ResultRoute.EMAILS,
            ResultRoute.IPS,
            ResultRoute.PEOPLE,
            ResultRoute.INTERESTING_URLS,
        }
    )


def test_source_lookup_preserves_case_insensitive_legacy_labels() -> None:
    assert get_source_spec('CRTsh') is SOURCE_SPECS['crtsh']
