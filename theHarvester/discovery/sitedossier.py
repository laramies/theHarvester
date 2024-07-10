import asyncio

from bs4 import BeautifulSoup

from theHarvester.discovery.constants import get_delay
from theHarvester.lib.core import AsyncFetcher, Core


class SearchSitedossier:
    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.server = 'www.sitedossier.com'
        self.proxy = False

    async def do_search(self):
        # 2023 but this site doesn't support https...
        # This site seems to yield a lot of results but is a bit annoying to scrape
        # Hence the need for delays after each request to get the most results
        # Feel free to tweak the delays as needed
        url = f'http://{self.server}/parentdomain/{self.word}'
        headers = {'User-Agent': Core.get_user_agent()}
        response = await AsyncFetcher.fetch_all([url], headers=headers, proxy=self.proxy)
        base_response = response[0]
        soup = BeautifulSoup(base_response, 'html.parser')
        # iter_counter = 1
        # iterations_needed = total_number // 100
        # iterations_needed += 1
        flagged_counter = 0
        stop_conditions = ['End of list.', 'No data currently available.']
        bot_string = (
            'Our web servers have detected unusual or excessive requests '
            'from your computer or network. Please enter the unique "word"'
            ' below to confirm that you are a human interactively using this site.'
        )
        if (
            stop_conditions[0] not in base_response and stop_conditions[1] not in base_response
        ) and bot_string not in base_response:
            total_number = soup.find('i')
            total_number = int(total_number.text.strip().split(' ')[-1].replace(',', ''))
            hrefs = soup.find_all('a', href=True)
            for a in hrefs:
                unparsed = a['href']
                if '/site/' in unparsed:
                    subdomain = str(unparsed.split('/')[-1]).lower()
                    self.totalhosts.add(subdomain)
            await asyncio.sleep(get_delay() + 15 + get_delay())
            for i in range(101, total_number, 100):
                headers = {'User-Agent': Core.get_user_agent()}
                iter_url = f'http://{self.server}/parentdomain/{self.word}/{i}'
                print(f'My current iter_url: {iter_url}')
                response = await AsyncFetcher.fetch_all([iter_url], headers=headers, proxy=self.proxy)
                response = response[0]
                if stop_conditions[0] in response or stop_conditions[1] in response or flagged_counter >= 3:
                    break
                if bot_string in response:
                    new_sleep_time = get_delay() * 30
                    print(f'Triggered a captcha for sitedossier sleeping for: {new_sleep_time} seconds')
                    flagged_counter += 1
                    await asyncio.sleep(new_sleep_time)
                    response = await AsyncFetcher.fetch_all(
                        [iter_url],
                        headers={'User-Agent': Core.get_user_agent()},
                        proxy=self.proxy,
                    )
                    response = response[0]
                    if bot_string in response:
                        new_sleep_time = get_delay() * 30 * get_delay()
                        print(
                            f'Still triggering a captcha, sleeping longer for: {new_sleep_time}'
                            f' and skipping this batch: {iter_url}'
                        )
                        await asyncio.sleep(new_sleep_time)
                        flagged_counter += 1
                        if flagged_counter >= 3:
                            break
                soup = BeautifulSoup(response, 'html.parser')
                hrefs = soup.find_all('a', href=True)
                for a in hrefs:
                    unparsed = a['href']
                    if '/site/' in unparsed:
                        subdomain = str(unparsed.split('/')[-1]).lower()
                        self.totalhosts.add(subdomain)
                await asyncio.sleep(get_delay() + 15 + get_delay())
            print(f'In total found: {len(self.totalhosts)}')
            print(self.totalhosts)
        else:
            print('Sitedossier module has triggered a captcha on first iteration, no results can be found.')
            print('Change IPs, manually solve the captcha, or wait before rerunning Sitedossier module')

    async def get_hostnames(self):
        return self.totalhosts

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()
