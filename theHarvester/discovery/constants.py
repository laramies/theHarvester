import random

from theHarvester.lib.core import AsyncFetcher, Core


async def splitter(links):
    """Deduplicate profile URLs using name-like path segments.

    :param links: Profile URLs to deduplicate.
    :return: URLs with repeated name segments removed.
    """
    unique_list = []
    name_check = []
    for url in links:
        tail = url.split('/')[-1]
        if len(tail) == 2 or tail == 'zh-cn':
            tail = url.split('/')[-2]
        name = tail.split('-')
        if len(name) > 1:
            joined_name = name[0] + name[1]
        else:
            joined_name = name[0]
        if joined_name not in name_check:
            unique_list.append(url)
            name_check.append(joined_name)
    return unique_list


def filter(lst):
    """Normalize a collection into unique, filtered lowercase strings.

    :param lst: Values to filter.
    :return: The filtered values.
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
    """Return a random delay between 0.5 and 2.5 seconds."""
    return random.randint(1, 3) - 0.5


async def search(text: str) -> bool:
    """Return whether text contains Google's automated-traffic block page.

    :param text: Response text to inspect.
    """
    for line in text.strip().splitlines():
        if (
            'This page appears when Google automatically detects requests coming from your computer network' in line
            or 'http://www.google.com/sorry/index' in line
            or 'https://www.google.com/sorry/index' in line
        ):
            return True
    return False


async def google_workaround(visit_url: str) -> bool | str:
    """Fetch a Google result page through the websniffer fallback.

    :param visit_url: Google URL to fetch.
    :return: Decoded HTML, or ``True`` when no usable page is returned.
    """
    url = 'https://websniffer.cc/'
    data = {
        'Cookie': '',
        'url': visit_url,
        'submit': 'Submit',
        'type': 'GET&http=1.1',
        'uak': str(random.randint(4, 8)),  # select random UA to send to Google
    }
    returned_html = await AsyncFetcher.post_fetch(url, headers={'User-Agent': Core.get_browser_user_agent()}, data=data)
    returned_html = (
        'This page appears when Google automatically detects requests coming from your computer network'
        if returned_html == ''
        else returned_html[0]
    )

    returned_html = '' if 'Please Wait... | Cloudflare' in returned_html else returned_html

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


class MissingKeyError(Exception):
    """Raised when a discovery source is missing required credentials."""

    def __init__(self, source: str | None) -> None:
        if source:
            self.message = f'\n[!] Missing API key for {source}. '
        else:
            self.message = '\n[!] Missing CSE id. '

    def __str__(self) -> str:
        return self.message


# Backward compatibility: keep old name for external imports
MissingKey = MissingKeyError
