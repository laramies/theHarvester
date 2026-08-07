from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum, StrEnum, auto
from typing import Final


class ActivityClass(StrEnum):
    PASSIVE = 'P0'
    DNS = 'P1'
    DIRECT = 'P2'


ACTION_ACTIVITIES: Final = {
    'dns-brute': ActivityClass.DNS,
    'dns-lookup': ActivityClass.DNS,
    'dns-resolve': ActivityClass.DNS,
    'shodan': ActivityClass.PASSIVE,
    'api-scan': ActivityClass.DIRECT,
    'screenshot': ActivityClass.DIRECT,
    'take-over': ActivityClass.DIRECT,
}


class ResultRoute(Enum):
    """Normalized result collections a source can contribute.

    ``SUBDOMAINS`` contains in-scope descendant names reported by a source. It
    does not imply DNS resolution or current addressability. Legacy adapters
    and output formats may still call these values hosts for compatibility.
    """

    SUBDOMAINS = auto()
    EMAILS = auto()
    IPS = auto()
    ASNS = auto()
    PEOPLE = auto()
    LINKS = auto()
    URLS = auto()
    INTERESTING_URLS = auto()
    BREACHES = auto()


_ROUTE_CAPABILITIES = {
    ResultRoute.SUBDOMAINS: 'subdomains',
    ResultRoute.EMAILS: 'emails',
    ResultRoute.IPS: 'ips',
    ResultRoute.ASNS: 'asns',
    ResultRoute.PEOPLE: 'people',
    ResultRoute.LINKS: 'urls',
    ResultRoute.URLS: 'urls',
    ResultRoute.INTERESTING_URLS: 'urls',
    ResultRoute.BREACHES: 'breaches',
}
RESULT_CAPABILITIES = frozenset(_ROUTE_CAPABILITIES.values())


@dataclass(frozen=True)
class SourceSpec:
    name: str
    routes: frozenset[ResultRoute]
    activity: ActivityClass = ActivityClass.PASSIVE

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(_ROUTE_CAPABILITIES[route] for route in self.routes)


def _spec(
    name: str,
    *routes: ResultRoute,
    activity: ActivityClass = ActivityClass.PASSIVE,
) -> SourceSpec:
    return SourceSpec(
        name=name,
        routes=frozenset(routes),
        activity=activity,
    )


_SPECS = (
    _spec('arquivo', ResultRoute.SUBDOMAINS),
    _spec('baidu', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('bevigil', ResultRoute.SUBDOMAINS, ResultRoute.INTERESTING_URLS),
    _spec('brave', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('bufferoverun', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('builtwith', ResultRoute.SUBDOMAINS, ResultRoute.INTERESTING_URLS),
    _spec('censys', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('certspotter', ResultRoute.SUBDOMAINS),
    _spec('chaos', ResultRoute.SUBDOMAINS),
    _spec('commoncrawl', ResultRoute.SUBDOMAINS),
    _spec(
        'criminalip',
        ResultRoute.SUBDOMAINS,
        ResultRoute.IPS,
        ResultRoute.ASNS,
        activity=ActivityClass.DIRECT,
    ),
    _spec('crtsh', ResultRoute.SUBDOMAINS),
    _spec('dehashed', ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('dnsdb', ResultRoute.SUBDOMAINS),
    _spec('dnsdumpster', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('duckduckgo', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('dymo', ResultRoute.SUBDOMAINS),
    _spec('fofa', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('fullhunt', ResultRoute.SUBDOMAINS),
    _spec('github-code', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('gitlab', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.URLS),
    _spec('hackertarget', ResultRoute.SUBDOMAINS),
    _spec('haveibeenpwned', ResultRoute.BREACHES),
    _spec('hibpverified', ResultRoute.EMAILS, ResultRoute.BREACHES),
    _spec('hudsonrock', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('hunter', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('hunterhow', ResultRoute.SUBDOMAINS),
    _spec('intelx', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.INTERESTING_URLS),
    _spec('leakix', ResultRoute.SUBDOMAINS),
    _spec('leaklookup', ResultRoute.EMAILS, ResultRoute.BREACHES),
    _spec('mojeek', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('netlas', ResultRoute.SUBDOMAINS),
    _spec('onyphe', ResultRoute.SUBDOMAINS, ResultRoute.IPS, ResultRoute.ASNS),
    _spec('otx', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('pentesttools', ResultRoute.SUBDOMAINS, ResultRoute.IPS, activity=ActivityClass.DNS),
    _spec('projectdiscovery', ResultRoute.SUBDOMAINS),
    _spec('rapiddns', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('robtex', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('rocketreach', ResultRoute.EMAILS, ResultRoute.LINKS),
    _spec('securityTrails', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('securityscorecard', ResultRoute.SUBDOMAINS, ResultRoute.IPS),
    _spec('sherlockeye', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('shodan', ResultRoute.SUBDOMAINS, activity=ActivityClass.DNS),
    _spec(
        'shodanInternetDB',
        ResultRoute.SUBDOMAINS,
        ResultRoute.IPS,
        activity=ActivityClass.DNS,
    ),
    _spec('shodanct', ResultRoute.SUBDOMAINS),
    _spec('subdomaincenter', ResultRoute.SUBDOMAINS),
    _spec('subdomainfinderc99', ResultRoute.SUBDOMAINS, activity=ActivityClass.DNS),
    _spec('thc', ResultRoute.SUBDOMAINS),
    _spec('tomba', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec('urlscan', ResultRoute.SUBDOMAINS, ResultRoute.IPS, ResultRoute.ASNS, ResultRoute.INTERESTING_URLS),
    _spec('virustotal', ResultRoute.SUBDOMAINS),
    _spec('waybackarchive', ResultRoute.SUBDOMAINS),
    _spec('whoisxml', ResultRoute.SUBDOMAINS),
    _spec(
        'windvane',
        ResultRoute.SUBDOMAINS,
        ResultRoute.EMAILS,
        ResultRoute.IPS,
        activity=ActivityClass.DNS,
    ),
    _spec('yahoo', ResultRoute.SUBDOMAINS, ResultRoute.EMAILS),
    _spec(
        'zoomeye',
        ResultRoute.SUBDOMAINS,
        ResultRoute.EMAILS,
        ResultRoute.IPS,
        ResultRoute.ASNS,
        ResultRoute.INTERESTING_URLS,
    ),
)

SOURCE_SPECS = {spec.name: spec for spec in _SPECS}
_CASEFOLDED_SOURCE_SPECS = {name.casefold(): spec for name, spec in SOURCE_SPECS.items()}


def get_source_spec(name: str) -> SourceSpec:
    return _CASEFOLDED_SOURCE_SPECS[name.casefold()]


def resolve_sources(selection: str | Iterable[str]) -> list[str]:
    """Expand source and result-capability selectors into canonical source names."""
    values = (selection,) if isinstance(selection, str) else selection
    tokens = [token for value in values for token in map(str.strip, value.split(',')) if token]
    selected: set[str] = set()
    for token in tokens:
        if token.casefold() == 'all':
            selected.update(spec.name for spec in SOURCE_SPECS.values() if spec.activity is ActivityClass.PASSIVE)
        elif token in RESULT_CAPABILITIES:
            selected.update(spec.name for spec in SOURCE_SPECS.values() if token in spec.capabilities)
        else:
            selected.add(token)
    return sorted(selected)
