import requests
import myparser

def search():
    #{"term":"linkedin.com","lookuplevel":0,"maxresults":1000,"timeout":null,"datefrom":"","dateto":"","sort":2,"media":0,"terminate":[]}:
    domain = 'linkedin.com'
    s = requests.session()
    tm = s.get('https://intelx.io')
    print(tm.status_code)
    params = {"term":"linkedin.com","lookuplevel":0,"maxresults":1000,"timeout":1,"datefrom":"","dateto":"","sort":2,"media":0,"terminate":[]}
    url = 'https://api.intelx.io/intelligent/search'
    r = s.post(url,params=params)
    print(r.status_code)
    print('r.text: ',r.text)

def test():
    print(requests.get('https://www.intelx.io').text)


def main():
    search()

if __name__ == '__main__':
    main()