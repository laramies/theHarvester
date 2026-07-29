class Parser:
    def __init__(self) -> None:
        self.emails: set[str] = set()
        self.selectors: set[str] = set()

    async def parse_dictionaries(self, results: object) -> tuple[set[str], set[str]]:
        """Parse method to parse json results
        :param results: Dictionary containing a list of dictionaries known as selectors
        :return: tuple of emails and non-email selectors
        """
        if not isinstance(results, dict):
            return self.emails, self.selectors
        selectors = results.get('selectors')
        if not isinstance(selectors, list):
            return self.emails, self.selectors

        for selector in selectors:
            if not isinstance(selector, dict):
                continue
            selector_value = selector.get('selectorvalue')
            if not isinstance(selector_value, str):
                continue
            selector_value = selector_value.strip().rstrip('),')
            if not selector_value:
                continue
            if '@' in selector_value and '://' not in selector_value:
                self.emails.add(selector_value)
            else:
                self.selectors.add(selector_value)
        return self.emails, self.selectors
