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

        for dictionary in selectors:
            if not isinstance(dictionary, dict):
                continue
            field = dictionary.get('selectorvalue')
            if not isinstance(field, str):
                continue
            field = field.strip().rstrip('),')
            if not field:
                continue
            if '@' in field and '://' not in field:
                self.emails.add(field)
            else:
                self.selectors.add(field)
        return self.emails, self.selectors
