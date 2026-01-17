import argparse
import os
import traceback

from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response, UJSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.staticfiles import StaticFiles

from theHarvester import __main__
from theHarvester.lib.api.additional_endpoints import router as additional_router

API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '5/minute')


# Define Pydantic models for request and response validation
class QueryResponse(BaseModel):
    asns: list[str] = Field(default_factory=list, description='List of ASNs')
    interesting_urls: list[str] = Field(default_factory=list, description='List of interesting URLs')
    twitter_people: list[str] = Field(default_factory=list, description='List of Twitter people')
    linkedin_people: list[dict] = Field(default_factory=list, description='List of LinkedIn people')
    linkedin_links: list[str] = Field(default_factory=list, description='List of LinkedIn links')
    trello_urls: list[str] = Field(default_factory=list, description='List of Trello URLs')
    ips: list[str] = Field(default_factory=list, description='List of IPs')
    emails: list[str] = Field(default_factory=list, description='List of emails')
    hosts: list[str] = Field(default_factory=list, description='List of hosts')


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
    CORSMiddleware,
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
async def root(*, user_agent: str = Header(None)) -> Response:
    """
    Root endpoint that displays the theHarvester logo and links to the GitHub repository.

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
    """
    Easter egg endpoint for bots.

    Returns a Star Wars reference when accessed.
    """
    return UJSONResponse({'bot': 'These are not the droids you are looking for'})


# Define Pydantic model for sources response
class SourcesResponse(BaseModel):
    sources: list[str] = Field(..., description='List of supported data sources')


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
    """
    Endpoint to query for available sources theHarvester supports.

    Returns a list of all supported data sources that can be used with the query endpoint.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    try:
        sources = __main__.Core.get_supportedengines()
        return UJSONResponse({'sources': sources})
    except Exception as e:
        # Log the error and return a detailed error response
        error_traceback = traceback.format_exc()
        print(f'Error in getsources endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': 'An error occurred while retrieving sources',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


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
    user_agent: str = Header(None),
    domain: str = Query(..., description='Domain to be brute forced'),
    dns_resolve: str = Query('', description='Perform DNS resolution on subdomains with a resolver list or passed in resolvers'),
) -> Response:
    """
    Endpoint for DNS brute forcing.

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

        return UJSONResponse({'dns_bruteforce': dns_bruteforce})

    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise e
    except Exception as e:
        # Log the error and return a detailed error response
        error_traceback = traceback.format_exc()
        print(f'Error in dnsbrute endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
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
    dns_server: str = Query('', description='DNS server to use for lookup'),
    user_agent: str = Header(None),
    dns_brute: bool = Query(False, description='Perform a DNS brute force on the domain'),
    dns_lookup: bool = Query(False, description='Enable DNS server lookup'),
    dns_resolve: str = Query('', description='Perform DNS resolution on subdomains with a resolver list or passed in resolvers'),
    filename: str = Query('', description='Save the results to an XML and JSON file'),
    proxies: bool = Query(False, description='Use proxies for requests'),
    shodan: bool = Query(False, description='Use Shodan to query discovered hosts'),
    take_over: bool = Query(False, description='Check for takeovers'),
    wordlist: str = Query('', description='Specify a wordlist for API endpoint scanning'),
    api_scan: bool = Query(False, description='Scan for API endpoints'),
    source: list[str] = Query(..., description='Data sources to query (comma separated with no space)'),
    limit: int = Query(500, description='Limit the number of search results'),
    start: int = Query(0, description='Start with result number X'),
    domain: str = Query(..., description='Domain to be harvested'),
) -> Response:
    """
    Query function that allows user to query theHarvester rest API.

    This endpoint performs searches using the specified data sources and returns the results.
    Rate limit is configurable via CLI argument (default: 5 requests per minute).
    """
    # Basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    try:
        # Validate sources
        supported_engines = __main__.Core.get_supportedengines()
        for s in source:
            if s not in supported_engines:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Source '{s}' is not supported. Supported sources: {', '.join(supported_engines)}",
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
                source=','.join(source),
                start=start,
                take_over=take_over,
                wordlist=wordlist,
                api_scan=api_scan,
                dns_resolve=dns_resolve,
                quiet=False,
                screenshot='',
            )
        )

        # Return the results using the Pydantic model
        return UJSONResponse(
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
            }
        )
    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise e
    except Exception as e:
        # Log the error and return a detailed error response
        error_traceback = traceback.format_exc()
        print(f'Error in query endpoint: {e!s}\n{error_traceback}')

        return UJSONResponse(
            {
                'detail': 'An error occurred while processing your request',
                'error_type': type(e).__name__,
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
