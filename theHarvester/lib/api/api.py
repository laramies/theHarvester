import argparse
import asyncio
import ipaddress
import logging
import os
import socket
from datetime import datetime
from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.staticfiles import StaticFiles

from theHarvester import __main__
from theHarvester.lib import stash
from theHarvester.lib.api.additional_endpoints import router as additional_router
from theHarvester.lib.api.auth import get_api_key
from theHarvester.lib.completed_result import ResultKind
from theHarvester.lib.recursive_dns import DEFAULT_RECURSIVE_DNS_QUERY_LIMIT

logger = logging.getLogger(__name__)

API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '5/minute')


async def _is_public_target(domain: str) -> bool:
    host = domain.split('/')[0].split(':')[0]
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(host, None)
    except socket.gaierror:
        return True  # unresolvable: the scan cannot reach it
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True


# Define Pydantic models for request and response validation
class QueryResponse(BaseModel):
    asns: list[str] = Field(default_factory=list, description='List of ASNs')
    interesting_urls: list[str] = Field(default_factory=list, description='List of interesting URLs')
    twitter_people: list[str] = Field(default_factory=list, description='List of Twitter people')
    linkedin_people: list[dict] = Field(default_factory=list, description='List of LinkedIn people')
    linkedin_links: list[str] = Field(default_factory=list, description='List of LinkedIn links')
    trello_urls: list[str] = Field(default_factory=list, description='List of discovered URLs (legacy field name)')
    ips: list[str] = Field(default_factory=list, description='List of IPs')
    emails: list[str] = Field(default_factory=list, description='List of emails')
    hosts: list[str] = Field(default_factory=list, description='List of hosts')
    breaches: list[str] = Field(default_factory=list, description='List of breach names')


class ErrorResponse(BaseModel):
    detail: str = Field(..., description='Error message')
    error_type: str | None = Field(None, description='Type of error')
    traceback: str | None = Field(None, description='Error traceback')


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title='Restful Harvest',
    description='Rest API for theHarvester powered by FastAPI',
    version='0.0.4',
    docs_url='/docs',
    redoc_url='/redoc',
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

# Add CORS middleware
app.add_middleware(
    cast('Any', CORSMiddleware),
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['GET', 'POST'],
    allow_headers=['*'],
)

# Include additional endpoints
app.include_router(additional_router, prefix='/additional', tags=['Additional APIs'])

# This is where we will host files that arise if the user specifies a filename
try:
    app.mount('/static', StaticFiles(directory='theHarvester/lib/api/static/'), name='static')
except RuntimeError:
    static_path = os.path.expanduser('~/.local/share/theHarvester/static/')
    if not os.path.isdir(static_path):
        os.makedirs(static_path)
        app.mount(
            '/static',
            StaticFiles(directory=static_path),
            name='static',
        )


@app.get('/', response_class=HTMLResponse)
async def root(*, user_agent: Annotated[str | None, Header()] = None) -> Response:
    """Root endpoint that displays the theHarvester logo and links to the GitHub repository.

    Also performs basic user agent filtering to redirect suspicious bots.
    """
    # Very basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    return HTMLResponse(
        """
    <!DOCTYPE html>
    <html lang="en-US">
        <head>
            <title>theHarvester API</title>
             <style>
              .img-container {
                text-align: center;
                display: block;
                }
              .api-links {
                text-align: center;
                margin-top: 20px;
                font-family: Arial, sans-serif;
              }
              .api-links a {
                margin: 0 10px;
                text-decoration: none;
                color: #0366d6;
              }
              .api-links a:hover {
                text-decoration: underline;
              }
            </style>
        </head>
        <body>
            <br/>
            <a href="https://github.com/laramies/theHarvester" target="_blank">
            <span class="img-container">
                <img src="https://raw.githubusercontent.com/laramies/theHarvester/master/theHarvester-logo.webp" alt="theHarvester logo"/>
            </span>
            </a>
            <div class="api-links">
                <a href="/docs">API Documentation</a> | 
                <a href="/redoc">ReDoc Documentation</a> | 
                <a href="/sources">Available Sources</a>
            </div>
        </body>
    </html>
    """
    )


# Define Pydantic model for bot response
class BotResponse(BaseModel):
    bot: str = Field(..., description='Bot message')


@app.get('/nicebot', response_model=BotResponse)
async def bot() -> Response:
    """Easter egg endpoint for bots.

    Returns a Star Wars reference when accessed.
    """
    return JSONResponse({'bot': 'These are not the droids you are looking for'})


# Define Pydantic model for sources response
class SourcesResponse(BaseModel):
    sources: list[str] = Field(..., description='List of supported data sources')


class CompletedRunSummary(BaseModel):
    run_id: UUID
    target: str
    started_at: datetime
    completed_at: datetime
    result_count: int


class CompletedResultItem(BaseModel):
    type: ResultKind
    value: str


class CompletedRunDetail(CompletedRunSummary):
    results: list[CompletedResultItem]


@app.get(
    '/sources',
    response_model=SourcesResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def getsources(request: Request) -> Response:
    """Endpoint to query for available sources theHarvester supports.

    Returns a list of all supported data sources that can be used with the query endpoint.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    try:
        sources = __main__.Core.get_supportedengines()
        return JSONResponse({'sources': sources})
    except Exception as e:
        logger.exception('Error in getsources endpoint')

        return JSONResponse(
            {
                'detail': 'An error occurred while retrieving sources',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/runs',
    response_model=list[CompletedRunSummary],
    responses={status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse}},
)
@limiter.limit(API_RATE_LIMIT)
async def list_runs(
    request: Request,
    _api_key: Annotated[str, Depends(get_api_key)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> list[dict[str, object]]:
    """List recently completed enumeration runs."""
    manager = stash.StashManager()
    await manager.do_init()
    return await manager.list_completed_results(limit=limit)


@app.get(
    '/runs/{run_id}',
    response_model=CompletedRunDetail,
    responses={
        status.HTTP_404_NOT_FOUND: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def get_run(
    request: Request,
    run_id: UUID,
    _api_key: Annotated[str, Depends(get_api_key)],
) -> dict[str, object]:
    """Retrieve one completed enumeration run with its normalized evidence."""
    manager = stash.StashManager()
    await manager.do_init()
    try:
        result = await manager.load_completed_result(run_id)
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Completed run not found') from error
    return {
        'run_id': str(result.run_id),
        'target': result.target,
        'started_at': result.started_at.isoformat(),
        'completed_at': result.completed_at.isoformat(),
        'result_count': len(result.results),
        'results': [{'type': kind, 'value': value} for kind, value in result.results],
    }


# Define Pydantic model for DNS brute force response
class DnsBruteResponse(BaseModel):
    dns_bruteforce: list[str] = Field(default_factory=list, description='List of DNS brute force results')


@app.get(
    '/dnsbrute',
    response_model=DnsBruteResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def dnsbrute(
    request: Request,
    domain: Annotated[str, Query(min_length=3, description='Domain to be brute forced')],
    user_agent: Annotated[str | None, Header()] = None,
    dns_resolve: Annotated[
        str, Query(description='Perform DNS resolution on subdomains with a resolver list or passed in resolvers')
    ] = '',
) -> Response:
    """Endpoint for DNS brute forcing.

    This endpoint performs DNS brute force on the specified domain and returns the results.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate domain
        if not domain or len(domain) < 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Domain must be at least 3 characters long')

        # Call the main function with the provided parameters
        dns_bruteforce = await __main__.start(
            argparse.Namespace(
                dns_brute=True,
                dns_lookup=False,
                dns_server=False,
                dns_tld=False,
                domain=domain,
                filename='',
                google_dork=False,
                limit=500,
                proxies=False,
                shodan=False,
                source=','.join([]),
                start=0,
                take_over=False,
                wordlist='',
                api_scan=False,
                dns_resolve=dns_resolve,
            )
        )

        return JSONResponse({'dns_bruteforce': dns_bruteforce})

    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise e
    except Exception as e:
        logger.exception('Error in dnsbrute endpoint')

        return JSONResponse(
            {
                'detail': 'An error occurred while processing your request',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@app.get(
    '/query',
    response_model=QueryResponse,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {'model': ErrorResponse},
        status.HTTP_400_BAD_REQUEST: {'model': ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {'model': ErrorResponse},
    },
)
@limiter.limit(API_RATE_LIMIT)
async def query(
    request: Request,
    source: Annotated[
        list[str],
        Query(
            description=(
                'Source names or source capabilities to query. Multiple capabilities select the union of matching '
                'sources; they do not filter returned fields.'
            )
        ),
    ],
    domain: Annotated[str, Query(min_length=3, description='Domain to be harvested')],
    dns_server: Annotated[
        str,
        Query(description='Accepted for compatibility but currently unused; use dns_resolve to select resolvers.'),
    ] = '',
    user_agent: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias='X-API-Key')] = None,
    dns_brute: Annotated[bool, Query(description='Perform a DNS brute force on the domain')] = False,
    dns_lookup: Annotated[
        bool,
        Query(
            description=(
                'Perform PTR lookups across the /24 network containing each discovered IPv4 address. '
                'This sends active DNS queries.'
            )
        ),
    ] = False,
    dns_resolve: Annotated[str, Query(description='Resolve discovered hostnames using resolver IPs or a resolver file')] = '',
    dns_recursive_depth: Annotated[int, Query(ge=0, description='Maximum recursive DNS discovery depth. Zero disables it.')] = 0,
    dns_recursive_query_limit: Annotated[
        int, Query(gt=0, description='Hard cap on recursive DNS record queries across all resolver vantages')
    ] = DEFAULT_RECURSIVE_DNS_QUERY_LIMIT,
    dns_recursive_runtime_seconds: Annotated[
        float, Query(gt=0, allow_inf_nan=False, description='Hard runtime cap in seconds for recursive DNS discovery')
    ] = 60.0,
    filename: Annotated[
        str,
        Query(description=('Write uniquely prefixed server-side XML, JSON, and JSONL files using NAME as the filename suffix.')),
    ] = '',
    proxies: Annotated[
        bool,
        Query(
            description=(
                'Use proxies.yaml for supported discovery-source requests. Direct takeover and API-path checks '
                'connect directly so their target addresses can be validated.'
            )
        ),
    ] = False,
    shodan: Annotated[bool, Query(description='Use Shodan to query discovered hosts')] = False,
    take_over: Annotated[
        bool,
        Query(
            description=('Check discovered hosts for known takeover indicators. The takeover check bypasses configured proxies.')
        ),
    ] = False,
    wordlist: Annotated[str, Query(description='Path to the endpoint wordlist used by api_scan')] = '',
    api_scan: Annotated[
        bool,
        Query(
            description=('Check common API paths with GET, HEAD, and OPTIONS. Requests do not use proxies or follow redirects.')
        ),
    ] = False,
    limit: Annotated[int, Query(description='Maximum results requested from each source that supports result limits')] = 500,
    start: Annotated[int, Query(description='Result offset for sources that support pagination')] = 0,
) -> Response:
    """Query function that allows user to query theHarvester rest API.

    This endpoint performs searches using the specified data sources and returns the results.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate sources
        selected_sources = __main__.Core.expand_source_selection(','.join(source))
        credentialed_source = any(
            source_name in selected_sources and bool((key_getter() or '').strip())
            for source_name, key_getter in (
                ('dehashed', __main__.Core.dehashed_key),
                ('hibpverified', __main__.Core.hibpverified_key),
                ('leaklookup', __main__.Core.leaklookup_key),
            )
        )
        if credentialed_source:
            get_api_key(x_api_key)
        supported_engines = __main__.Core.get_supportedengines()
        for s in selected_sources:
            if s not in supported_engines:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Source '{s}' is not supported. Supported sources: {', '.join(supported_engines)}",
                )

        if dns_recursive_depth > 0:
            get_api_key(x_api_key)
            try:
                recursive_resolvers = {
                    str(ipaddress.ip_address(value.strip())) for value in dns_resolve.split(',') if value.strip()
                }
            except ValueError as error:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='recursive DNS requires exactly three distinct resolver IPs',
                ) from error
            if len(recursive_resolvers) != 3:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='recursive DNS requires exactly three distinct resolver IPs',
                )

        if api_scan and not await _is_public_target(domain):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='api_scan target must be a publicly routable host',
            )

        # Call the main function with the provided parameters
        (
            asns,
            iurls,
            twitter_people_list,
            linkedin_people_list,
            linkedin_links,
            aurls,
            aips,
            aemails,
            ahosts,
            abreaches,
        ) = await __main__.start(
            argparse.Namespace(
                dns_brute=dns_brute,
                dns_lookup=dns_lookup,
                dns_server=dns_server,
                domain=domain,
                filename=filename,
                limit=limit,
                proxies=proxies,
                shodan=shodan,
                source=','.join(selected_sources),
                start=start,
                take_over=take_over,
                wordlist=wordlist,
                api_scan=api_scan,
                dns_resolve=dns_resolve,
                dns_recursive_depth=dns_recursive_depth,
                dns_recursive_query_limit=dns_recursive_query_limit,
                dns_recursive_runtime_seconds=dns_recursive_runtime_seconds,
                quiet=False,
                screenshot='',
            ),
            persist_completed_result=True,
            include_breaches=True,
        )

        # Return the results using the Pydantic model
        return JSONResponse(
            {
                'asns': asns,
                'interesting_urls': iurls,
                'twitter_people': twitter_people_list,
                'linkedin_people': linkedin_people_list,
                'linkedin_links': linkedin_links,
                'trello_urls': aurls,
                'ips': aips,
                'emails': aemails,
                'hosts': ahosts,
                'breaches': abreaches,
            }
        )
    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise e
    except Exception as e:
        logger.exception('Error in query endpoint')

        return JSONResponse(
            {
                'detail': 'An error occurred while processing your request',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
