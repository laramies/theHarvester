import enum
from collections.abc import Mapping
from typing import Any


class TokenTypesEnum(str, enum.Enum):
    ID = 'id'
    FIRSTNAME = 'firstname'
    LASTNAME = 'lastname'
    EMAIL = 'email'
    DOB = 'dob'
    URL = 'url'
    PHONE = 'phone'
    DATE = 'date'
    TIME = 'time'
    IP = 'ip_address'
    HASH = 'hash'
    PASSWORD = 'password'
    ADDRESS = 'address'
    COMPANY = 'company'
    JOB_TITLE = 'job_title'
    USERNAME = 'username'
    COUNTRY = 'country'
    CITY = 'city'
    STATE = 'state'
    ZIP_CODE = 'zip_code'
    CURRENCY = 'currency'
    INDUSTRY = 'industry'
    DEPARTMENT = 'department'
    ROLE = 'role'


class Parser:
    def __init__(self) -> None:
        self.parsed_data: dict[str, set[str]] = {}
        self.people: list[dict[str, str]] = []

    async def parse_text_tokens(self, results: list[dict[str, Any]]) -> Mapping[str, set[str] | list[dict[str, str]]]:
        """
        Extracts different types of information from the recognized text tokens
        """
        if not results:
            return {'people': set(), 'emails': set(), 'ips': set(), 'urls': set()}

        for res in results:
            person: dict[str, str] | None = None
            for token in res['tokens']:
                if token['type'] == TokenTypesEnum.EMAIL:
                    if 'emails' not in self.parsed_data:
                        self.parsed_data['emails'] = set()
                    self.parsed_data['emails'].add(token['value'])
                    person = person or {}
                    person['email'] = token['value']
                elif token['type'] == TokenTypesEnum.IP:
                    if 'ips' not in self.parsed_data:
                        self.parsed_data['ips'] = set()
                    self.parsed_data['ips'].add(token['value'])
                elif token['type'] == TokenTypesEnum.URL:
                    if 'urls' not in self.parsed_data:
                        self.parsed_data['urls'] = set()
                    self.parsed_data['urls'].add(token['value'])
                elif token['type'] == TokenTypesEnum.FIRSTNAME:
                    person = person or {}
                    person['firstname'] = token['value']
                elif token['type'] == TokenTypesEnum.LASTNAME:
                    person = person or {}
                    person['lastname'] = token['value']
                elif token['type'] == TokenTypesEnum.COMPANY:
                    person = person or {}
                    person['company'] = token['value']
                elif token['type'] == TokenTypesEnum.CITY:
                    person = person or {}
                    person['city'] = token['value']
                elif token['type'] == TokenTypesEnum.STATE:
                    person = person or {}
                    person['state'] = token['value']
                elif token['type'] == TokenTypesEnum.COUNTRY:
                    person = person or {}
                    person['country'] = token['value']
                elif token['type'] == TokenTypesEnum.ZIP_CODE:
                    person = person or {}
                    person['zip_code'] = token['value']
                elif token['type'] == TokenTypesEnum.PHONE:
                    person = person or {}
                    person['phone'] = token['value']
                elif token['type'] == TokenTypesEnum.ADDRESS:
                    person = person or {}
                    person['address'] = token['value']
                elif token['type'] == TokenTypesEnum.ROLE:
                    person = person or {}
                    person['role'] = token['value']
                elif token['type'] == TokenTypesEnum.DOB:
                    person = person or {}
                    person['dob'] = token['value']
                elif token['type'] == TokenTypesEnum.JOB_TITLE:
                    person = person or {}
                    person['job_title'] = token['value']
                elif token['type'] == TokenTypesEnum.INDUSTRY:
                    person = person or {}
                    person['industry'] = token['value']
                elif token['type'] == TokenTypesEnum.DEPARTMENT:
                    person = person or {}
                    person['department'] = token['value']

            if person:
                for key in person:
                    if key != 'email':
                        self.people.append(person)
                        break

        if self.people:
            self.parsed_data['people'] = self.people  # type: ignore

        return self.parsed_data
