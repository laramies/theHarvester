"""
Example script to query theHarvester rest API, obtain results, and write out to stdout as well as an html
"""

import asyncio
import aiohttp
import netaddr


async def fetch_json(session, url):
    async with session.get(url) as response:
        return await response.json()


async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text()


async def main() -> None:
    """
    Just a simple example of how to interact with the rest api
    you can easily use requests instead of aiohttp or whatever you best see fit
    """
    url = "http://127.0.0.1:5000"
    domain = "netflix.com"
    query_url = f'{url}/query?limit=300&source=bing,baidu,duckduckgo,dogpile&domain={domain}'
    async with aiohttp.ClientSession() as session:
        fetched_json = await fetch_json(session, query_url)
        total_asns = fetched_json['asns']
        interesting_urls = fetched_json['interesting_urls']
        twitter_people_list_tracker = fetched_json['twitter_people']
        linkedin_people_list_tracker = fetched_json['linkedin_people']
        linkedin_links_tracker = fetched_json['linkedin_links']
        trello_urls = fetched_json['trello_urls']
        ips = fetched_json['ips']
        emails = fetched_json['emails']
        hosts = fetched_json['hosts']

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
        print('\n[*] No Twitter users found.\n\n')
    else:
        if len(twitter_people_list_tracker) >= 1:
            print('\n[*] Twitter Users found: ' + str(len(twitter_people_list_tracker)))
            print('---------------------')
            twitter_people_list_tracker = list(sorted(set(twitter_people_list_tracker)))
            for usr in twitter_people_list_tracker:
                print(usr)

    if len(linkedin_people_list_tracker) == 0:
        print('\n[*] No LinkedIn users found.\n\n')
    else:
        if len(linkedin_people_list_tracker) >= 1:
            print('\n[*] LinkedIn Users found: ' + str(len(linkedin_people_list_tracker)))
            print('---------------------')
            linkedin_people_list_tracker = list(sorted(set(linkedin_people_list_tracker)))
            for usr in linkedin_people_list_tracker:
                print(usr)

    if len(linkedin_links_tracker) == 0:
        print(f'\n[*] LinkedIn Links found: {len(linkedin_links_tracker)}')
        linkedin_links_tracker = list(sorted(set(linkedin_links_tracker)))
        print('---------------------')
        for link in linkedin_links_tracker:
            print(link)

    length_urls = len(trello_urls)
    total = length_urls
    print('\n[*] Trello URLs found: ' + str(total))
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
        print(('\n'.join(all_emails)))

    if len(hosts) == 0:
        print('\n[*] No hosts found.\n\n')
    else:
        print('\n[*] Hosts found: ' + str(len(hosts)))
        print('---------------------')
        print('\n'.join(hosts))


if __name__ == '__main__':
    asyncio.run(main())
