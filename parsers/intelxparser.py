class Parser:

    def __init__(self):
        self.emails = set()
        self.hosts = set()

    def parse_dictionaries(self, results):
        """
        Parse method to parse json results
        :param results: Dictionary containing a list of dictionaries known as selectors
        :return: tuple of emails and hosts
        """
        if results is not None:
            for dictionary in results["selectors"]:
                field = dictionary['selectorvalue']
                if '@' in field:
                    self.emails.add(field)
                else:
                    self.hosts.add(str(field).replace(')', ''))
            return self.emails, self.hosts
        return None, None
