from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import *
import rocketreach


class SearchRocketreach:

    def __init__(self, word):
        self.word = word
        self.key = Core.rocketreach_key()
        if self.key is None:
            raise MissingKey('Rocketreach')
        self.total_results = ""
        self.proxy = False

    async def do_search(self):
        rr = rocketreach.Gateway(rocketreach.GatewayConfig(self.key))
        s = rr.person.search().filter(current_employer=self.word)
        result = s.execute()
        if result.is_success:
            lookup = rr.person.lookup(result.people[0].id)
            if lookup.is_success:
                print(repr(lookup.person))

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()  # Only need to do it once.

    # async def get_emails(self):
    #     rawres = myparser.Parser(self.total_results, self.word)
    #     return await rawres.emails()
