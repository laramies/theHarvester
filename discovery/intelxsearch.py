import requests
import myparser


def search():
    # {"term":"linkedin.com","lookuplevel":0,"maxresults":1000,"timeout":null,"datefrom":"","dateto":"","sort":2,"media":0,"terminate":[]}:
    domain = 'linkedin.com'
    s = requests.session()
    tm = s.get('https://intelx.io')
    print(tm.status_code)
    params = {"term": "linkedin.com", "lookuplevel": 0, "maxresults": 1000, "timeout": 1, "datefrom": "", "dateto": "",
              "sort": 2, "media": 0, "terminate": []}
    url = 'https://api.intelx.io/intelligent/search'
    r = s.post(url, params=params)
    print(r.status_code)
    print('r.text: ', r.text)


def test():
    print(requests.get('https://www.intelx.io').text)


def main():
    search()


if __name__ == '__main__':
    main()

"""
    class Creds():


        def __init__(self, id):
            self.id = id


        def get_key(self):
            with open('credentials.txt', 'r', encoding='UTF-8') as file:
                for line in file:
                    line = line.strip().split(':')
                    id = line[0]
                    key = line[1]
                    print('id: ', id)
                    print('key: ', key)
                    if 'hunter' in id:
                        return key
                    elif 'bing' in id:
                        return key
                    elif 'shodan' in id:
                        return key
                    elif 'securityTrails' in id:
                        return key
                    elif 'googleCSEapi' in id:
                        return key
                    elif 'googleCSEid' in id:
                        return key
                    else:
                        continue
            return None
x = 'YXNkYWRhZGFkYWQ='
import base64
print(base64.b64decode(x).decode('UTF-8'))
"""