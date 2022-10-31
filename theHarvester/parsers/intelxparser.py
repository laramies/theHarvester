from typing import Set


class Parser:

    def __init__(self) -> None:
        self.emails: Set = set()
        self.hosts: Set = set()

    async def parse_dictionaries(self, results: dict) -> tuple:
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
                    field = str(field)
                    if 'http' in field or 'https' in field:
                        if field[:5] == 'https':
                            field = field[8:]
                        else:
                            field = field[7:]
                    self.hosts.add(field.replace(')', '').replace(',', ''))
            return self.emails, self.hosts
        return None, None
