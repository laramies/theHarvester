from theHarvester.lib.core import *
from typing import Union
import random
import aiohttp
import re
from bs4 import BeautifulSoup

googleUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 ' \
           'Safari/537.36 '


async def splitter(links):
    """
    Method that tries to remove duplicates
    LinkedinLists pulls a lot of profiles with the same name.
    This method tries to remove duplicates from the list.
    :param links: list of links to remove duplicates from
    :return: unique-ish list
    """
    unique_list = []
    name_check = []
    for url in links:
        tail = url.split("/")[-1]
        if len(tail) == 2 or tail == "zh-cn":
            tail = url.split("/")[-2]
        name = tail.split("-")
        if len(name) > 1:
            joined_name = name[0] + name[1]
        else:
            joined_name = name[0]
        if joined_name not in name_check:
            unique_list.append(url)
            name_check.append(joined_name)
    return unique_list


def filter(lst):
    """
    Method that filters list
    :param lst: list to be filtered
    :return: new filtered list
    """
    if lst is None:
        return []
    if not isinstance(lst, set):
        lst = set(lst)  # Remove duplicates.
    new_lst = []
    for item in lst:
        item = str(item)
        if (item[0].isalpha() or item[0].isdigit()) and ('xxx' not in item) and ('..' not in item):
            item = item.replace('252f', '').replace('2F', '').replace('2f', '')
            new_lst.append(item.lower())
    return new_lst


def getDelay() -> float:
    return random.randint(1, 3) - .5


async def search(text: str) -> bool:
    # Helper function to check if Google has blocked traffic.
    for line in text.strip().splitlines():
        if 'This page appears when Google automatically detects requests coming from your computer network' in line \
                or 'http://www.google.com/sorry/index' in line or 'https://www.google.com/sorry/index' in line:
            # print('\tGoogle is blocking your IP due to too many automated requests, wait or change your IP')
            return True
    return False


async def google_workaround(visit_url: str) -> Union[bool, str]:
    """
    Function that makes a request on our behalf, if Google starts to block us
    :param visit_url: Url to scrape
    :return: Correct html that can be parsed by BS4
    """
    return True
    url = 'https://websniffer.cc/'
    data = {
        'Cookie': '',
        'url': visit_url,
        'submit': 'Submit',
        'type': 'GET&http=1.1',
        'uak': str(random.randint(4, 8))  # select random UA to send to Google
    }
    import requests
    returned_html = requests.post(url, data=data, headers={'User-Agent': Core.get_user_agent()})
    returned_html = returned_html.text
    # TODO FIX
    # returned_html = await AsyncFetcher.post_fetch(url, headers={'User-Agent': Core.get_user_agent()}, data=data)
    import pprint as p
    print('returned html')
    p.pprint(returned_html, indent=4)
    returned_html = "This page appears when Google automatically detects requests coming from your computer network"
    if await search(returned_html):
        print('going to second method!')
        # indicates that google is serving workaround a captcha
        # That means we will try out second option which will utilize proxies
        return await second_method(visit_url)
    # the html we get is malformed for BS4 as there are no greater than or less than signs
    if '&lt;html&gt;' in returned_html:
        start_index = returned_html.index('&lt;html&gt;')
    else:
        start_index = returned_html.index('&lt;html')

    end_index = returned_html.index('&lt;/html&gt;') + 1
    correct_html = returned_html[start_index:end_index]
    # Slice list to get the response's html
    correct_html = ''.join([ch.strip().replace('&lt;', '<').replace('&gt;', '>') for ch in correct_html])
    return correct_html


async def request(url, params):
    headers = {'User-Agent': Core.get_user_agent()}
    session = aiohttp.ClientSession(headers=headers)
    results = await AsyncFetcher.fetch(session, url=url, params=params)
    await session.close()
    return results


async def proxy_fetch(session, url, proxy):
    try:
        async with session.get(url, proxy=proxy, ssl=False) as resp:
            return f'success:{proxy}', await resp.text()
    except Exception:
        return f'failed:{proxy}', proxy


async def proxy_test(proxies, url):
    print('doing proxy test with this number of proxies: ', len(proxies))
    headers = {'User-Agent': Core.get_user_agent()}
    timeout = aiohttp.ClientTimeout(total=40)
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        texts = await asyncio.gather(*[proxy_fetch(session, url, proxy) for proxy in proxies])
        return texts


async def get_proxies():
    print('inside get proxies')
    # ideas borrowed and modified from twitterscraper
    proxy_url = 'https://free-proxy-list.net/'
    response = await AsyncFetcher.fetch_all([proxy_url])
    response = response[0]
    soup = BeautifulSoup(response, 'lxml')
    table = soup.find('table', id='proxylisttable')
    list_tr = table.find_all('tr')
    list_td = [elem.find_all('td') for elem in list_tr]
    list_td = [x for x in list_td if x is not None and len(x) > 0]
    list_ip = [elem[0].text for elem in list_td]
    list_ports = [elem[1].text for elem in list_td]
    list_proxies = [f"http://{':'.join(elem)}" for elem in list(zip(list_ip, list_ports))]
    return list_proxies


async def clean_dct(dct: dict, second_test=False):
    print('cleaning dct and second test is: ', second_test)
    good_proxies = set()
    for proxy, text in dct.items():
        if 'failed' not in proxy:
            if second_test:
                if await search(text) is False:
                    print(text)
                    return text
            else:
                good_proxies.add(proxy[proxy.find(':') + 1:])
    return good_proxies if second_test is False else True


async def create_init_proxies():
    print('inside create init proxies')
    url = "https://suip.biz"
    first_param = [url, (('act', 'proxy1'),), ]
    second_param = [url, (('act', 'proxy2'),), ]
    third_param = [url, (('act', 'proxy3'),), ]
    async_requests = [
        request(url=url, params=params)
        for url, params in [first_param, second_param, third_param]
    ]
    results = await asyncio.gather(*async_requests)
    proxy_set = set()
    for resp in results:
        ip_candidates = re.findall(r'[0-9]+(?:\.[0-9]+){3}:[0-9]+', resp)
        proxy_set.update({f'http://{ip}' for ip in ip_candidates})

    new_proxies = await get_proxies()
    proxy_set.update({proxy for proxy in new_proxies})
    return proxy_set


async def second_method(url: str) -> Union[str, bool]:
    print('inside second method')
    # First visit example.com to make to filter out bad proxies
    init_url = "http://example.com"
    proxy_set = await create_init_proxies()
    tuples = await proxy_test(proxy_set, init_url)
    mega_dct = dict((x, y) for x, y in tuples)
    proxy_set = await clean_dct(mega_dct)
    # After we clean our proxy set now we use them to visit the url we care about
    print('got working proxies now onto the juice')
    tuples = await proxy_test(proxy_set, url)
    mega_dct = dict((x, y) for x, y in tuples)
    results = await clean_dct(mega_dct, second_test=True)
    print('returning the juice')
    # pass in second_test flag as True to indicate this will
    # the text we care about or a bool to indicate it was
    # not successful
    return results


class MissingKey(Exception):

    def __init__(self, identity_flag: bool):
        if identity_flag:
            self.message = '\n\033[93m[!] Missing API key. \033[0m'
        else:
            self.message = '\n\033[93m[!] Missing CSE id. \033[0m'

    def __str__(self) -> str:
        return self.message
