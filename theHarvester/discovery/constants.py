from typing import Union
import random

googleUA = 'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1464.0 Safari/537.36'


def splitter(links):
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


def search(text: str) -> bool:
    # Helper function to check if Google has blocked traffic.
    for line in text.strip().splitlines():
        if 'This page appears when Google automatically detects requests coming from your computer network' in line \
                or 'http://www.google.com/sorry/index' in line or 'https://www.google.com/sorry/index' in line:
            # print('\tGoogle is blocking your IP due to too many automated requests, wait or change your IP')
            return True
    return False


def google_workaround(visit_url: str) -> Union[bool, str]:
    """
    Function that makes a request on our behalf, if Google starts to block us
    :param visit_url: Url to scrape
    :return: Correct html that can be parsed by BS4
    """
    import requests
    url = 'https://websniffer.cc/'
    data = {
        'Cookie': '',
        'url': visit_url,
        'submit': 'Submit',
        'type': 'GET&http=1.1',
        'uak': str(random.randint(4, 8))  # select random UA to send to Google
    }
    resp = requests.post(url, headers={'User-Agent': googleUA}, data=data)
    returned_html = resp.text
    if search(returned_html):
        # indicates that google is serving workaround a captcha
        # TODO rework workaround with more websites to send requests on our behalf or utilize proxies option in request
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

    def __init__(self, identity_flag: bool):
        if identity_flag:
            self.message = '\n\033[93m[!] Missing API key. \033[0m'
        else:
            self.message = '\n\033[93m[!] Missing CSE id. \033[0m'

    def __str__(self) -> str:
        return self.message
