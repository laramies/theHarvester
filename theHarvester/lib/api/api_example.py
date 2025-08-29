"""
Example script to query theHarvester rest API, obtain results, and write out to stdout as well as an html
"""

import asyncio

import aiohttp
import netaddr


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
        print(f'\n[*] ASNS found: {len(total_asns)}')
        print('--------------------')
        total_asns = list(sorted(set(total_asns)))
        for asn in total_asns:
            print(asn)

    if len(interesting_urls) > 0:
        print(f'\n[*] Interesting Urls found: {len(interesting_urls)}')
        print('--------------------')
        interesting_urls = list(sorted(set(interesting_urls)))
        for iurl in interesting_urls:
            print(iurl)

    if len(twitter_people_list_tracker) == 0:
        print('\n[*] No Twitter users found.')
    elif len(twitter_people_list_tracker) >= 1:
        print('\n[*] Twitter Users found: ' + str(len(twitter_people_list_tracker)))
        print('---------------------')
        twitter_people_list_tracker = list(sorted(set(twitter_people_list_tracker)))
        for usr in twitter_people_list_tracker:
            print(usr)

    if len(linkedin_people_list_tracker) == 0:
        print('\n[*] No LinkedIn users found.')
    elif len(linkedin_people_list_tracker) >= 1:
        print('\n[*] LinkedIn Users found: ' + str(len(linkedin_people_list_tracker)))
        print('---------------------')
        linkedin_people_list_tracker = list(sorted(set(linkedin_people_list_tracker)))
        for usr in linkedin_people_list_tracker:
            print(usr)

    if len(linkedin_links_tracker) == 0:
        print('\n[*] No LinkedIn links found.')
    else:
        print(f'\n[*] LinkedIn Links found: {len(linkedin_links_tracker)}')
        print('---------------------')
        linkedin_links_tracker = list(sorted(set(linkedin_links_tracker)))
        for link in linkedin_links_tracker:
            print(link)

    length_urls = len(trello_urls)
    if length_urls == 0:
        print('\n[*] No Trello URLs found.')
    else:
        print('\n[*] Trello URLs found: ' + str(length_urls))
        print('--------------------')
        all_urls = list(sorted(set(trello_urls)))
        for url in sorted(all_urls):
            print(url)

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
        all_emails = sorted(list(set(emails)))
        print('\n'.join(all_emails))

    if len(hosts) == 0:
        print('\n[*] No hosts found.\n\n')
    else:
        print('\n[*] Hosts found: ' + str(len(hosts)))
        print('---------------------')
        print('\n'.join(hosts))


if __name__ == '__main__':
    asyncio.run(main())
