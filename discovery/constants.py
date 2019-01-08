"""
Module that contains constants used across plugins
Contains list of user agents, api_keys, and a function to get random delay and user agent.
As well as a defined User Agent for Google Search
User-Agents from: https://github.com/tamimibrahim17/List-of-user-agents
"""

import random

googleUA = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1464.0 Safari/537.36"

bingAPI_key = ''

googleCSEAPI_key = ''

googleCSE_id = ''

hunterAPI_key = ''

securityTrailsAPI_key = ''

shodanAPI_key = 'oCiMsgM6rQWqiTvPxFHYcExlZgg7wvTt'  # this is the default key


def filter(lst):
    """
    Method that filters list
    :param lst: list to be filtered
    :return: new filtered list
    """
    lst = set(lst)  # remove duplicates
    new_lst = []
    for item in lst:
        item = str(item)
        if (item[0].isalpha() or item[0].isdigit()) and ('xxx' not in item) and ('..' not in item):
            if '252f' in item:
                item = item.replace('252f', '')
            if '2F' in item:
                item = item.replace('2F', '')
            if '2f' in item:
                item = item.replace('2f', '')
            new_lst.append(item.lower())
    return new_lst


def getDelay():
    return random.randint(1, 3) - .5


def search(text):
    # helper function to check if google has blocked traffic
    for line in text.strip().splitlines():
        if 'This page appears when Google automatically detects requests coming from your computer network' in line:
            print('\tGoogle is blocking your IP due to too many automated requests, wait or change your IP')
            return True
    return False


class MissingKey(Exception):
    """This class is for when a user is missing their api key or cse id"""

    def __init__(self, identity_flag):
        if identity_flag:  # flag that checks what kind of error was raised
            self.message = '\tMissing API key!'
        else:
            self.message = '\tMissing CSE id!'

    def __str__(self):
        return self.message
