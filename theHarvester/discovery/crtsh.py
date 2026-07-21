from theHarvester.lib.core import AsyncFetcher


class SearchCrtsh:
    def __init__(self, word) -> None:
        self.word = word
        self.data: list = []
        self.proxy = False

    async def do_search(self) -> list:
        import asyncio  # Serve per il delay tra i tentativi
        data: set = set()
        url = f'https://crt.sh/?q=%25.{self.word}&exclude=expired&deduplicate=Y&output=json'
        
        tries = 3
        for attempt in range(tries):
            try:
                response = await AsyncFetcher.fetch_all([url], json=True, proxy=self.proxy)
                response = response[0]
                
                # Se la risposta è valida (e non una lista vuota causata da un errore), processiamo i dati
                if response:
                    data = set([(dct['name_value'][2:] if dct['name_value'][:2] == '*.' else dct['name_value']) for dct in response])
                    data = {domain for domain in data if (domain[0] != '*' and str(domain[0:4]).isnumeric() is False)}
                    break  # Successo! Usciamo dal ciclo di retry
                    
            except (IndexError, KeyError, Exception) as e:
                # Se è l'ultimo tentativo, stampiamo l'errore ed usciamo
                if attempt == tries - 1:
                    print(f'crt.sh request failed after {tries} attempts. Error: {e}')
                    break
                # Altrimenti, aspettiamo 2 secondi e riproviamo
                await asyncio.sleep(2)
                
        clean: list = []
        for x in data:
            pre = x.split()
            for y in pre:
                clean.append(y)
        return clean

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        data = await self.do_search()
        self.data = data

    async def get_hostnames(self) -> list:
        return self.data
