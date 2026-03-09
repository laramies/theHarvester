from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.parsers import myparser


class SearchMojeek:

    def __init__(self, word, limit) -> None:
        self.word = word
        self.limit = limit
        self.total_results = ""
        self.proxy = False
        self.server = 'www.mojeek.com'
        self.api_server = 'api.mojeek.com'
        
        try:
            self.api_key = Core.mojeek_key()
        except Exception:
            self.api_key = ""
        
        if self.api_key:
            print("[*] Mojeek: API key detected.")
        else:
            print("[*] Mojeek: No API key found, using default scraping mode.")

    async def do_search(self) -> None:
        headers = {'User-Agent': Core.get_user_agent()}
        
        if self.api_key:
            urls = [f'https://{self.api_server}/search?api_key={self.api_key}&q={self.word}&fmt=json&s={num}' 
                    for num in range(1, self.limit, 10)]
            
            responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy, json=True)
            
            api_success = False
            for response in responses:
                data = response.get('response', response) 
                
                if data and 'results' in data:
                    results = data['results']
                    if len(results) > 0:
                        api_success = True
                        for result in results:
                            url = result.get('url', '').replace('\\/', '/')
                            self.total_results += f" {url} {result.get('title', '')} {result.get('desc', '')} "
                
                elif data and 'status' in data and 'denied' in data['status'].lower():
                    print(f"[!] Mojeek API: Access denied ({data['status']}).")
                    break

            if api_success:
                print("[*] Mojeek: API search completed successfully.")
                return 
            else:
                print("[*] Mojeek: API returned no results, falling back to scraping...")

        urls = [f'https://{self.server}/search?q={self.word}&s={num}' 
                for num in range(0, self.limit, 10)]
        
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += str(response)
            
    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
