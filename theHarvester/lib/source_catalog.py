from dataclasses import dataclass
from enum import Enum, auto


class ResultRoute(Enum):
    HOSTS = auto()
    EMAILS = auto()
    IPS = auto()
    ASNS = auto()
    PEOPLE = auto()
    LINKS = auto()
    INTERESTING_URLS = auto()


_ROUTE_CAPABILITIES = {
    ResultRoute.HOSTS: 'subdomains',
    ResultRoute.EMAILS: 'emails',
    ResultRoute.IPS: 'ips',
    ResultRoute.ASNS: 'asns',
    ResultRoute.PEOPLE: 'people',
    ResultRoute.LINKS: 'urls',
    ResultRoute.INTERESTING_URLS: 'urls',
}


@dataclass(frozen=True)
class SourceSpec:
    """Discovery routes and the independent evidence family for one source.

    Sources sharing an upstream dataset share a family. For example, ``shodan``
    and ``shodanInternetDB`` are separate adapters but not independent evidence.
    """

    name: str
    routes: frozenset[ResultRoute]
    family: str

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(_ROUTE_CAPABILITIES[route] for route in self.routes)


def _spec(
    name: str,
    *routes: ResultRoute,
    family: str | None = None,
) -> SourceSpec:
    return SourceSpec(
        name=name,
        routes=frozenset(routes),
        family=family if family is not None else name,
    )


_SPECS = (
    _spec('baidu', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('bevigil', ResultRoute.HOSTS, ResultRoute.INTERESTING_URLS),
    _spec('bitbucket', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('brave', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('bufferoverun', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('builtwith', ResultRoute.HOSTS, ResultRoute.INTERESTING_URLS),
    _spec('censys', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('certspotter', ResultRoute.HOSTS, family='certificate-transparency'),
    _spec('chaos', ResultRoute.HOSTS, family='projectdiscovery'),
    _spec('commoncrawl', ResultRoute.HOSTS),
    _spec('criminalip', ResultRoute.HOSTS, ResultRoute.IPS, ResultRoute.ASNS),
    _spec('crtsh', ResultRoute.HOSTS, family='certificate-transparency'),
    _spec('dehashed', ResultRoute.IPS),
    _spec('dnsdb', ResultRoute.HOSTS),
    _spec('dnsdumpster', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('duckduckgo', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('dymo', ResultRoute.HOSTS),
    _spec('fofa', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('fullhunt', ResultRoute.HOSTS),
    _spec('github-code', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('gitlab', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('hackertarget', ResultRoute.HOSTS),
    _spec('haveibeenpwned'),
    _spec('hudsonrock', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('hunter', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('hunterhow', ResultRoute.HOSTS),
    _spec('intelx', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.INTERESTING_URLS),
    _spec('leakix', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('leaklookup', ResultRoute.EMAILS),
    _spec('mojeek', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('netlas', ResultRoute.HOSTS),
    _spec('onyphe', ResultRoute.HOSTS, ResultRoute.IPS, ResultRoute.ASNS),
    _spec('otx', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('pentesttools', ResultRoute.HOSTS),
    _spec('projectdiscovery', ResultRoute.HOSTS),
    _spec('rapiddns', ResultRoute.HOSTS),
    _spec('robtex', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('rocketreach', ResultRoute.EMAILS, ResultRoute.LINKS),
    _spec('securityTrails', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('securityscorecard', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('sherlockeye', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('shodan', ResultRoute.HOSTS),
    _spec('shodanInternetDB', ResultRoute.HOSTS, ResultRoute.IPS, family='shodan'),
    _spec('subdomaincenter', ResultRoute.HOSTS),
    _spec('subdomainfinderc99', ResultRoute.HOSTS),
    _spec('thc', ResultRoute.HOSTS),
    _spec('threatcrowd', ResultRoute.HOSTS, ResultRoute.IPS),
    _spec('tomba', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec('urlscan', ResultRoute.HOSTS, ResultRoute.IPS, ResultRoute.ASNS, ResultRoute.INTERESTING_URLS),
    _spec('venacus', ResultRoute.EMAILS, ResultRoute.IPS, ResultRoute.PEOPLE, ResultRoute.INTERESTING_URLS),
    _spec('virustotal', ResultRoute.HOSTS),
    _spec('waybackarchive', ResultRoute.HOSTS),
    _spec('whoisxml', ResultRoute.HOSTS),
    _spec('windvane', ResultRoute.HOSTS, ResultRoute.EMAILS, ResultRoute.IPS),
    _spec('yahoo', ResultRoute.HOSTS, ResultRoute.EMAILS),
    _spec(
        'zoomeye',
        ResultRoute.HOSTS,
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
