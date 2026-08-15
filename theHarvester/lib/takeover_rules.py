import re
from dataclasses import dataclass

from theHarvester.lib.takeover_evidence import TakeoverClassification, TakeoverRcode

# This reviewed snapshot translates the provider-gated subset of
# can-i-take-over-xyz@5bd4e128 and compound predicates from
# nuclei-templates@9090ee10. Rules are local so network failure cannot silently
# change coverage. See CHANGELOG.md and README.md for provenance and terminology.
TAKEOVER_RULE_REVISION = 'takeover-rules-v1'


@dataclass(frozen=True, slots=True)
class TakeoverRule:
    rule_id: str
    service: str
    cname_patterns: tuple[str, ...]
    classification: TakeoverClassification = 'vulnerable-indicator'
    terminal_rcodes: tuple[TakeoverRcode, ...] = ()
    status_codes: tuple[int, ...] = ()
    body_all: tuple[str, ...] = ()
    body_any: tuple[str, ...] = ()
    body_none: tuple[str, ...] = ()
    body_regex_all: tuple[str, ...] = ()
    body_regex_any: tuple[str, ...] = ()
    body_regex_none: tuple[str, ...] = ()
    header_any: tuple[str, ...] = ()
    header_none: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.rule_id.strip() or not self.service.strip() or not self.cname_patterns:
            raise ValueError('takeover rules require an ID, service, and provider CNAME pattern')
        text_groups = (
            self.cname_patterns,
            self.body_all,
            self.body_any,
            self.body_none,
            self.body_regex_all,
            self.body_regex_any,
            self.body_regex_none,
            self.header_any,
            self.header_none,
        )
        if any(not value.strip() for group in text_groups for value in group):
            raise ValueError(f'takeover rule {self.rule_id} contains an empty matcher')
        for pattern in (*self.cname_patterns, *self.body_regex_all, *self.body_regex_any, *self.body_regex_none):
            try:
                re.compile(pattern, flags=re.IGNORECASE)
            except re.error as error:
                raise ValueError(f'takeover rule {self.rule_id} contains an invalid regular expression') from error
        if self.classification not in {'vulnerable-indicator', 'unverified-indicator', 'edge-case'}:
            raise ValueError(f'takeover rule {self.rule_id} has an unsupported classification')
        if any(rcode not in {'NOERROR', 'NXDOMAIN', 'NODATA', 'ERROR'} for rcode in self.terminal_rcodes):
            raise ValueError(f'takeover rule {self.rule_id} has an unsupported terminal RCODE')
        if any(isinstance(status, bool) or not 100 <= status <= 599 for status in self.status_codes):
            raise ValueError(f'takeover rule {self.rule_id} has an invalid HTTP status')
        http_predicates = (
            self.status_codes,
            self.body_all,
            self.body_any,
            self.body_none,
            self.body_regex_all,
            self.body_regex_any,
            self.body_regex_none,
            self.header_any,
            self.header_none,
        )
        if self.terminal_rcodes and any(http_predicates):
            raise ValueError(f'takeover rule {self.rule_id} cannot mix DNS and HTTP predicates')
        if not any(
            (
                self.terminal_rcodes,
                self.status_codes,
                self.body_all,
                self.body_any,
                self.body_regex_all,
                self.body_regex_any,
                self.header_any,
            )
        ):
            raise ValueError(f'takeover rule {self.rule_id} has no positive predicate')


def validate_takeover_rules(rules: tuple[TakeoverRule, ...]) -> tuple[TakeoverRule, ...]:
    if not rules:
        raise ValueError('takeover rules cannot be empty')
    rule_ids = [rule.rule_id for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError('takeover rule IDs must be unique')
    return rules


TAKEOVER_RULES: tuple[TakeoverRule, ...] = (
    TakeoverRule(
        'aws-elastic-beanstalk',
        'AWS/Elastic Beanstalk',
        (r'(?:^|\.)elasticbeanstalk\.com$',),
        terminal_rcodes=('NXDOMAIN',),
    ),
    TakeoverRule(
        'aws-s3',
        'AWS/S3',
        (r'(?:^|\.)s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$',),
        body_all=('The specified bucket does not exist', 'BucketName'),
        header_none=('x-guploader-uploadid', 'aliyunoss'),
    ),
    TakeoverRule(
        'airee',
        'Airee.ru',
        (r'(?:^|\.)airee\.ru$',),
        body_all=('Ошибка 402. Сервис Айри.рф не оплачен',),
    ),
    TakeoverRule(
        'anima',
        'Anima',
        (r'(?:^|\.)animaapp\.io$',),
        body_all=('The page you were looking for does not exist.',),
    ),
    TakeoverRule(
        'bitbucket',
        'Bitbucket',
        (r'(?:^|\.)bitbucket\.io$',),
        body_all=('Repository not found',),
    ),
    TakeoverRule(
        'cargo-collective',
        'Cargo Collective',
        (r'(?:^|\.)cargo\.site$',),
        classification='unverified-indicator',
        body_all=('<div class="notfound">', '404 Not Found<br>'),
    ),
    TakeoverRule(
        'discourse',
        'Discourse',
        (r'(?:^|\.)trydiscourse\.com$',),
        terminal_rcodes=('NXDOMAIN',),
    ),
    TakeoverRule(
        'hatena-blog',
        'HatenaBlog',
        (r'(?:^|\.)hatenablog\.com$',),
        body_all=('404 Blog is not found',),
    ),
    TakeoverRule(
        'help-juice',
        'Help Juice',
        (r'(?:^|\.)helpjuice\.com$',),
        body_all=("We could not find what you're looking for.",),
    ),
    TakeoverRule(
        'help-scout',
        'Help Scout',
        (r'(?:^|\.)helpscoutdocs\.com$',),
        body_all=('No settings were found for this company:',),
    ),
    TakeoverRule(
        'helprace',
        'Helprace',
        (r'(?:^|\.)helprace\.com$',),
        status_codes=(301,),
    ),
    TakeoverRule(
        'microsoft-azure',
        'Microsoft Azure',
        (
            r'(?:^|\.)cloudapp\.net$',
            r'(?:^|\.)cloudapp\.azure\.com$',
            r'(?:^|\.)azurewebsites\.net$',
            r'(?:^|\.)blob\.core\.windows\.net$',
            r'(?:^|\.)azure-api\.net$',
            r'(?:^|\.)azurehdinsight\.net$',
            r'(?:^|\.)azureedge\.net$',
            r'(?:^|\.)azurecontainer\.io$',
            r'(?:^|\.)database\.windows\.net$',
            r'(?:^|\.)azuredatalakestore\.net$',
            r'(?:^|\.)search\.windows\.net$',
            r'(?:^|\.)azurecr\.io$',
            r'(?:^|\.)redis\.cache\.windows\.net$',
            r'(?:^|\.)servicebus\.windows\.net$',
            r'(?:^|\.)visualstudio\.com$',
        ),
        terminal_rcodes=('NXDOMAIN',),
    ),
    TakeoverRule(
        'strikingly',
        'Strikingly',
        (r'(?:^|\.)s\.strikinglydns\.com$',),
        body_all=('PAGE NOT FOUND.',),
    ),
    TakeoverRule(
        'surge',
        'Surge.sh',
        (r'(?:^|\.)na-west1\.surge\.sh$',),
        body_all=('project not found',),
    ),
    TakeoverRule(
        'survey-sparrow',
        'SurveySparrow',
        (r'(?:^|\.)surveysparrow\.com$',),
        body_all=('Account not found.',),
    ),
    TakeoverRule(
        'uberflip',
        'Uberflip',
        (r'(?:^|\.)read\.uberflip\.com$',),
        body_all=("The URL you've accessed does not provide a hub.",),
    ),
    TakeoverRule(
        'wordpress',
        'Wordpress',
        (r'(?:^|\.)wordpress\.com$',),
        body_all=('Do you want to register', '.wordpress.com</em> doesn&#8217;t&nbsp;exist'),
        body_none=('cannot be registered',),
    ),
    TakeoverRule(
        'worksites',
        'Worksites',
        (r'(?:^|\.)worksites\.net$',),
        body_all=('Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.',),
    ),
    TakeoverRule(
        'ghost',
        'Ghost',
        (r'(?:^|\.)ghost\.io$',),
        status_codes=(302,),
        header_any=('error.ghost.org', 'offline.ghost.org'),
    ),
    TakeoverRule(
        'github-pages',
        'GitHub Pages',
        (r'(?:^|\.)github\.io$',),
        classification='edge-case',
        body_any=(
            "There isn't a GitHub Pages site here.",
            'For root URLs (like http://example.com/) you must provide an index.html file',
            'The site configured at this address does not contain the requested file.',
            'For root URLs (like <code>http://example.com/</code>)',
        ),
    ),
)

TAKEOVER_RULES = validate_takeover_rules(TAKEOVER_RULES)
