from theHarvester.lib.core import *
from typing import Union, Optional
import random

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


def get_delay() -> float:
    """Method that is used to generate a random delay"""
    return random.randint(1, 3) - .5


async def search(text: str) -> bool:
    """Helper function to check if Google has blocked traffic.
    :param text: See if certain text is returned which means Google is blocking us
    :return bool:
    """
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
    url = 'https://websniffer.cc/'
    data = {
        'Cookie': '',
        'url': visit_url,
        'submit': 'Submit',
        'type': 'GET&http=1.1',
        'uak': str(random.randint(4, 8))  # select random UA to send to Google
    }
    returned_html = await AsyncFetcher.post_fetch(url, headers={'User-Agent': Core.get_user_agent()}, data=data)
    returned_html = "This page appears when Google automatically detects requests coming from your computer network" \
        if returned_html == "" else returned_html[0]

    returned_html = "" if 'Please Wait... | Cloudflare' in returned_html else returned_html

    if len(returned_html) == 0 or await search(returned_html) or '&lt;html' not in returned_html:
        # indicates that google is serving workaround a captcha
        # That means we will try out second option which will utilize proxies
        return True
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


class MissingKey(Exception):
    """
    :raise: When there is a module that has not been provided its API key
    """
    def __init__(self, source: Optional[str]) -> None:
        if source:
            self.message = f'\n\033[93m[!] Missing API key for {source}. \033[0m'
        else:
            self.message = '\n\033[93m[!] Missing CSE id. \033[0m'

    def __str__(self) -> str:
        return self.message
