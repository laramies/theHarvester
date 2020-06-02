from fastapi import FastAPI
from argparse import Namespace
from theHarvester import __main__
app = FastAPI()


@app.get("/")
async def read_root():
    return {"Hello": "World"}


@app.get("/test")
async def read_item():
    try:
        emails, ips, urls = await __main__.start(
            Namespace(dns_brute=False,
                      dns_lookup=False,
                      dns_server=None,
                      dns_tld=False,
                      domain='yale.edu',
                      filename='',
                      google_dork=False,
                      limit='',
                      proxies=False,
                      shodan=False,
                      source='bing,intelx',
                      start=0,
                      take_over=False,
                      virtual_host=False))
        return {'emails': emails, 'ips': ips, 'urls': urls}
    except Exception as e:
        return {'exception': f'{e}'}
if __name__ == '__main__':
    print(__name__)
