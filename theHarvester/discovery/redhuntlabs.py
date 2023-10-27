import asyncio
import requests

from theHarvester.discovery.constants import MissingKey
from theHarvester.lib.core import AsyncFetcher, Core

class SearchRedHuntLabs:
    def __init__(self, word, page=1, page_size=40):
        self.key = Core.virustotal_key()
        if self.key is None:
            raise MissingKey("virustotal")
        self.word = word
        self.page = page
        self.page_size = page_size
        self.hostnames = []
        self.proxy = False

    async def do_search(self):
        # RedHunt Labs API URL
        api_url = f"https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain={self.word}&page_size={self.page_size}&page={self.page}"

        headers = {
            "X-BLOBR-KEY": self.key,
        }

        fail_counter = 0
        while True:
            try:
                response = requests.get(api_url, headers=headers, proxies=self.proxy)
                response.raise_for_status()  # Check for HTTP request errors

                jdata = response.json()

                if "results" in jdata:
                    data = jdata["results"]
                    self.hostnames.extend(await self.parse_hostnames(data, self.word))
                    self.page += 1
                else:
                    break

            except requests.exceptions.RequestException as e:
                # Handle request exceptions (e.g., connection error)
                fail_counter += 1
                if fail_counter >= 2 and "limit has been reached" in e.response.json(['message']):
                    print ("Your API credits have been exhausted. Head over to https://devportal.redhuntlabs.com/")
                    break

            await asyncio.sleep(16)  # Sleep for rate limiting

        self.hostnames = list(sorted(set(self.hostnames)))

    async def get_hostnames(self):
        return self.hostnames

    async def process(self, proxy: bool = False):
        self.proxy = proxy
        await self.do_search()

# Usage:
async def main():
    word = "example.com"
    searcher = SearchRedHuntLabs(word)
    await searcher.process()
    hostnames = await searcher.get_hostnames()
    print(hostnames)

if __name__ == "__main__":
    asyncio.run(main())
