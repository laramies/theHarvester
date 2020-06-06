"""
Example script to query theHarvester rest API, obtain results, and write out to stdout as well as an html & xml file
"""

import asyncio
import pprint

import aiohttp


async def fetch_json(session, url):
    async with session.get(url) as response:
        return await response.json()


async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text()


async def main():
    """
    Just a simple example of how to interact with the rest api
    you can easily use requests instead of aiohttp or whatever you best see fit
    """
    url = "http://127.0.0.1:5000"
    domain = "netflix.com"
    query_url = f'{url}/query?limit=300&filename=helloworld&source=bing,baidu,duckduckgo,dogpile&domain={domain}'
    async with aiohttp.ClientSession() as session:
        fetched_json = await fetch_json(session, query_url)
        emails = fetched_json["emails"]
        ips = fetched_json["ips"]
        urls = fetched_json["urls"]
        html_filename = fetched_json["html_file"]
        xml_filename = fetched_json["xml_file"]

    async with aiohttp.ClientSession() as session:
        html_file = await fetch(session, f"{url}{html_filename}")
        xml_file = await fetch(session, f"{url}{xml_filename}")

    if len(html_file) > 0:
        with open('results.html', 'w+') as fp:
            fp.write(html_file)

    if len(xml_file) > 0:
        with open('results.xml', 'w+') as fp:
            fp.write(xml_file)

    print('Emails found: ')
    pprint.pprint(emails, indent=4)
    print('\n')
    print('Ips found: ')
    pprint.pprint(ips, indent=4)
    print('\n')
    print('Urls found: ')
    pprint.pprint(urls, indent=4)


if __name__ == '__main__':
    asyncio.run(main())
