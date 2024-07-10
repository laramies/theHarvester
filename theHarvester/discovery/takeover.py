import re
from collections import defaultdict
from random import shuffle

import ujson

from theHarvester.lib.core import AsyncFetcher, Core


class TakeOver:
    def __init__(self, hosts) -> None:
        # NOTE THIS MODULE IS ACTIVE RECON
        self.hosts = hosts
        self.proxy = False
        self.fingerprints: dict[str, str] = dict()
        # https://stackoverflow.com/questions/33080869/python-how-to-create-a-dict-of-dict-of-list-with-defaultdict
        self.results: defaultdict[str, list] = defaultdict()

    async def populate_fingerprints(self):
        # Thank you to https://github.com/EdOverflow/can-i-take-over-xyz for these fingerprints
        populate_url = 'https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json'
        headers = {'User-Agent': Core.get_user_agent()}
        response = await AsyncFetcher.fetch_all([populate_url], headers=headers)
        try:
            resp = response[0]
            unparsed_json = ujson.loads(resp)
            for unparsed_fingerprint in unparsed_json:
                if unparsed_fingerprint['service'] in ['Smugsmug']:
                    # Subdomain must be in format domain.smugsmug.com
                    # This will never happen as subdomains are parsed and filtered to be in format of *.word.com
                    continue
                if unparsed_fingerprint['status'] == 'Vulnerable' or unparsed_fingerprint['status'] == 'Edge case':
                    self.fingerprints[unparsed_fingerprint['fingerprint']] = unparsed_fingerprint['service']
        except Exception as e:
            print(f'An exception has occurred populating takeover fingerprints: {e}, defaulting to static list')
            self.fingerprints = {
                "'Trying to access your account?'": 'Campaign Monitor',
                '404 Not Found': 'Fly.io',
                '404 error unknown site!': 'Pantheon',
                'Do you want to register *.wordpress.com?': 'Wordpress',
                'Domain uses DO name serves with no records in DO.': 'Digital Ocean',
                "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.": 'LaunchRock',
                'No Site For Domain': 'Kinsta',
                'No settings were found for this company:': 'Help Scout',
                'Project doesnt exist... yet!': 'Readme.io',
                'Repository not found': 'Bitbucket',
                'The feed has not been found.': 'Feedpress',
                'No such app': 'Heroku',
                'The specified bucket does not exist': 'AWS/S3',
                'The thing you were looking for is no longer here, or never was': 'Ghost',
                "There isn't a Github Pages site here.": 'Github',
                'This UserVoice subdomain is currently available!': 'UserVoice',
                "Uh oh. That page doesn't exist.": 'Intercom',
                "We could not find what you're looking for.": 'Help Juice',
                "Whatever you were looking for doesn't currently exist at this address": 'Tumblr',
                'is not a registered InCloud YouTrack': 'JetBrains',
                'page not found': 'Uptimerobot',
                'project not found': 'Surge.sh',
            }

    async def check(self, url, resp) -> None:
        # Simple function that takes response and checks if any fingerprints exist
        # If a fingerprint exists figures out which one and prints it out
        regex = re.compile('(?=(' + '|'.join(map(re.escape, list(self.fingerprints.keys()))) + '))')
        # Sanitize fingerprints
        matches = re.findall(regex, resp)
        matches = list(set(matches))
        for match in matches:
            print(f'\t\033[91m Takeover detected: {url}\033[1;32;40m')
            if match in self.fingerprints.keys():
                # Validation check as to not error out
                service = self.fingerprints[match]
                print(f'\t\033[91m Type of takeover is: {service} with match: {match}\033[1;32;40m')
                self.results[url].append({match: service})

    async def do_take(self) -> None:
        try:
            if len(self.hosts) > 0:
                # Returns a list of tuples in this format: (url, response)
                # Filter out responses whose responses are empty strings (indicates errored)
                https_hosts = [f'https://{host}' for host in self.hosts]
                http_hosts = [f'http://{host}' for host in self.hosts]
                all_hosts = https_hosts + http_hosts
                shuffle(all_hosts)
                resps: list = await AsyncFetcher.fetch_all(all_hosts, takeover=True, proxy=self.proxy)
                for url, resp in tuple(resp for resp in resps if len(resp[1]) >= 1):
                    await self.check(url, resp)
            else:
                return
        except Exception as e:
            print(e)

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_take()

    async def get_takeover_results(self):
        return self.results
