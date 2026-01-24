"""
Example script to query theHarvester rest API, obtain results, and write out to stdout as well as an html
"""

import asyncio

import aiohttp
import netaddr

from theHarvester.lib.output import print_section, sorted_unique


async def fetch_json(session, url):
    try:
        async with session.get(url) as response:
            response.raise_for_status()  # Raise an exception for 4XX/5XX responses
            return await response.json()
    except Exception as e:
        print(f'Error fetching data from {url}: {e}')
        return {}


async def fetch(session, url):
    try:
        async with session.get(url) as response:
            response.raise_for_status()  # Raise an exception for 4XX/5XX responses
            return await response.text()
    except Exception as e:
        print(f'Error fetching data from {url}: {e}')
        return ''


async def main() -> None:
    """
    Just a simple example of how to interact with the rest api
    you can use httpx instead of aiohttp or whatever you best see fit
    """
    url = 'http://127.0.0.1:5000'
    domain = 'netflix.com'
    query_url = f'{url}/query?dns_brute=false&dns_lookup=false&dns_tld=false&proxies=false&shodan=false&take_over=false&virtual_host=false&api_scan=false&source=otx&source=subdomaincenter&limit=500&start=0&domain={domain}'

    async with aiohttp.ClientSession() as session:
        fetched_json = await fetch_json(session, query_url)
        total_asns = fetched_json.get('asns', [])
        interesting_urls = fetched_json.get('interesting_urls', [])
        twitter_people_list_tracker = fetched_json.get('twitter_people', [])
        linkedin_people_list_tracker = fetched_json.get('linkedin_people', [])
        linkedin_links_tracker = fetched_json.get('linkedin_links', [])
        trello_urls = fetched_json.get('trello_urls', [])
        ips = fetched_json.get('ips', [])
        emails = fetched_json.get('emails', [])
        hosts = fetched_json.get('hosts', [])

    if len(total_asns) > 0:
        print_section(f'\n[*] ASNS found: {len(total_asns)}', total_asns, '--------------------')
        total_asns = sorted_unique(total_asns)

    if len(interesting_urls) > 0:
        print_section(f'\n[*] Interesting Urls found: {len(interesting_urls)}', interesting_urls, '--------------------')
        interesting_urls = sorted_unique(interesting_urls)

    if len(twitter_people_list_tracker) == 0:
        print('\n[*] No Twitter users found.')
    elif len(twitter_people_list_tracker) >= 1:
        print_section(
            '\n[*] Twitter Users found: ' + str(len(twitter_people_list_tracker)),
            twitter_people_list_tracker,
            '---------------------',
        )
        twitter_people_list_tracker = sorted_unique(twitter_people_list_tracker)

    if len(linkedin_people_list_tracker) == 0:
        print('\n[*] No LinkedIn users found.')
    elif len(linkedin_people_list_tracker) >= 1:
        print_section(
            '\n[*] LinkedIn Users found: ' + str(len(linkedin_people_list_tracker)),
            linkedin_people_list_tracker,
            '---------------------',
        )
        linkedin_people_list_tracker = sorted_unique(linkedin_people_list_tracker)

    if len(linkedin_links_tracker) == 0:
        print('\n[*] No LinkedIn links found.')
    else:
        print_section(
            f'\n[*] LinkedIn Links found: {len(linkedin_links_tracker)}', linkedin_links_tracker, '---------------------'
        )
        linkedin_links_tracker = sorted_unique(linkedin_links_tracker)

    length_urls = len(trello_urls)
    if length_urls == 0:
        print('\n[*] No Trello URLs found.')
    else:
        print_section('\n[*] Trello URLs found: ' + str(length_urls), trello_urls, '--------------------')

    if len(ips) == 0:
        print('\n[*] No IPs found.')
    else:
        print('\n[*] IPs found: ' + str(len(ips)))
        print('-------------------')
        # use netaddr as the list may contain ipv4 and ipv6 addresses
        ip_list = sorted([netaddr.IPAddress(ip.strip()) for ip in set(ips)])
        print('\n'.join(map(str, ip_list)))

    if len(emails) == 0:
        print('\n[*] No emails found.')
    else:
        print('\n[*] Emails found: ' + str(len(emails)))
        print('----------------------')
        all_emails = sorted_unique(emails)
        print('\n'.join(all_emails))

    if len(hosts) == 0:
        print('\n[*] No hosts found.\n\n')
    else:
        print('\n[*] Hosts found: ' + str(len(hosts)))
        print('---------------------')
        print('\n'.join(hosts))


if __name__ == '__main__':
    asyncio.run(main())
