import random


googleUA = 'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1464.0 Safari/537.36'


def filter(lst):
    """
    Method that filters list
    :param lst: list to be filtered
    :return: new filtered list
    """
    lst = set(lst)  # Remove duplicates.
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
    # Helper function to check if Google has blocked traffic.
    for line in text.strip().splitlines():
        if 'This page appears when Google automatically detects requests coming from your computer network' in line:
            print('\tGoogle is blocking your IP due to too many automated requests, wait or change your IP')
            return True
    return False


class MissingKey(Exception):

    def __init__(self, identity_flag):
        if identity_flag:
            self.message = '\n\033[93m[!] Missing API key. \033[0m'
        else:
            self.message = '\n\033[93m[!] Missing CSE id. \033[0m'

    def __str__(self):
        return self.message
