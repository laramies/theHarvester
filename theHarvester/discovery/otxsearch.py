from theHarvester.lib.core import *
import json
import grequests


class SearchOtx:

    def __init__(self, word):
        self.word = word
        self.results = ''
        self.totalresults = ''
        self.totalhosts = set()
        self.totalips = set()

    def do_search(self):
        base_url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.word}/passive_dns'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            request = grequests.get(base_url, headers=headers)
            data = grequests.map([request])
            self.results = data[0].content.decode('UTF-8')
        except Exception as e:
            print(e)

        self.totalresults += self.results
        dct = json.loads(self.totalresults)
        self.totalhosts: set = {host['hostname'] for host in dct['passive_dns']}
        # filter out ips that are just called NXDOMAIN
        self.totalips: set = {ip['address'] for ip in dct['passive_dns'] if 'NXDOMAIN' not in ip['address']}

    def get_hostnames(self) -> set:
        return self.totalhosts

    def get_ips(self) -> set:
        return self.totalips

    def process(self):
        self.do_search()
        print('\tSearching results.')
