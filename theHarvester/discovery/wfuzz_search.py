try:
    import wfuzz
except ImportError:
    pass


class SearchWfuzz:

    def __init__(self, host):
        self.host = host
        self.results = ""
        self.totalresults = ""

    def do_search(self):
        print('elo')
        try:
            for r in wfuzz.fuzz(url=f'https://{self.host}/FUZZ', hc=[404], payloads=[('file', dict(fn='wordlists/general/common.txt'))]):
                print(r)
                self.results += r
        except Exception as e:
            print(e)
        self.totalresults += self.results

    def get_results(self):
        return self.totalresults

    def do_check(self):
        return

    def process(self):
        self.do_search()
        print('\tSearching Wfuzz')
