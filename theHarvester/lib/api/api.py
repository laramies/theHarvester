import argparse
from typing import Any, Dict, Union, List
import os
from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, UJSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from theHarvester import __main__

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title='Restful Harvest', description='Rest API for theHarvester powered by FastAPI', version='0.0.2')
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# This is where we will host files that arise if the user specifies a filename
try:
    app.mount('/static', StaticFiles(directory='theHarvester/lib/api/static/'), name='static')
except RuntimeError:
    static_path = os.path.expanduser('~/.local/share/theHarvester/static/')
    if not os.path.isdir(static_path):
        os.makedirs(static_path)
        app.mount('/static', StaticFiles(directory='~/.local/share/theHarvester/static/'), name='static')


@app.get('/', response_class=HTMLResponse)
async def root(*, user_agent: str = Header(None)) -> Union[RedirectResponse, str]:
    # very basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response

    html = """
    <!DOCTYPE html>
    <html lang="en-US">
        <head>
            <title>theHarvester API</title>
             <style>
              .img-container {
                text-align: center;
                display: block;
                }
            </style>
        </head>
        <body>
            <br/>
            <a href="https://github.com/laramies/theHarvester" target="_blank">
            <span class="img-container">
                <img src="https://raw.githubusercontent.com/laramies/theHarvester/master/theHarvester-logo.png" alt="theHarvester logo"/>
            </span>
            </a>
        </body>
    </html>
    """
    return html


@app.get('/nicebot')
async def bot() -> Dict[str, str]:
    # nice bot
    string = {'bot': 'These are not the droids you are looking for'}
    return string


@app.get('/sources', response_class=UJSONResponse)
@limiter.limit('5/minute')
async def getsources(request: Request):
    # Endpoint for user to query for available sources theHarvester supports
    # Rate limit of 5 requests per minute
    sources = __main__.Core.get_supportedengines()
    return {'sources': sources}


@app.get('/dnsbrute', response_class=UJSONResponse)
@limiter.limit('5/minute')
async def dnsbrute(request: Request, user_agent: str = Header(None),
                   domain: str = Query(..., description='Domain to be brute forced')) -> Union[Dict[str, Any], RedirectResponse]:
    # Endpoint for user to signal to do DNS brute forcing
    # Rate limit of 5 requests per minute
    # basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response
    dns_bruteforce = await __main__.start(argparse.Namespace(dns_brute=True,
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
                                                             virtual_host=False))
    return {'dns_bruteforce': dns_bruteforce}


@app.get('/query', response_class=UJSONResponse)
@limiter.limit('2/minute')
async def query(request: Request, dns_server: str = Query(""), user_agent: str = Header(None),
                dns_brute: bool = Query(False),
                dns_lookup: bool = Query(False),
                dns_tld: bool = Query(False),
                filename: str = Query(""),
                google_dork: bool = Query(False), proxies: bool = Query(False), shodan: bool = Query(False),
                take_over: bool = Query(False), virtual_host: bool = Query(False),
                source: List[str] = Query(..., description='Data sources to query comma separated with no space'),
                limit: int = Query(500), start: int = Query(0),
                domain: str = Query(..., description='Domain to be harvested')) -> Union[Dict[str, Any], RedirectResponse]:

    # Query function that allows user to query theHarvester rest API
    # Rate limit of 2 requests per minute
    # basic user agent filtering
    if user_agent and ('gobuster' in user_agent or 'sqlmap' in user_agent or 'rustbuster' in user_agent):
        response = RedirectResponse(app.url_path_for('bot'))
        return response
    try:
        asns, iurls, twitter_people_list, \
            linkedin_people_list, linkedin_links, \
            aurls, aips, aemails, ahosts = await __main__.start(argparse.Namespace(dns_brute=dns_brute,
                                                                                   dns_lookup=dns_lookup,
                                                                                   dns_server=dns_server,
                                                                                   dns_tld=dns_tld,
                                                                                   domain=domain,
                                                                                   filename=filename,
                                                                                   google_dork=google_dork,
                                                                                   limit=limit,
                                                                                   proxies=proxies,
                                                                                   shodan=shodan,
                                                                                   source=','.join(source),
                                                                                   start=start,
                                                                                   take_over=take_over,
                                                                                   virtual_host=virtual_host))

        return {'asns': asns, 'interesting_urls': iurls,
                'twitter_people': twitter_people_list,
                'linkedin_people': linkedin_people_list,
                'linkedin_links': linkedin_links,
                'trello_urls': aurls,
                'ips': aips,
                'emails': aemails,
                'hosts': ahosts}
    except Exception:
        return {'exception': 'Please contact the server administrator to check the issue'}
