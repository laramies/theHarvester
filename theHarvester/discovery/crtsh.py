import psycopg2


class SearchCrtsh:

    def __init__(self, word):
        self.word = word
        self.db_server = 'crt.sh'
        self.db_database = 'certwatch'
        self.db_user = 'guest'

    def do_search(self):
        try:
            conn = psycopg2.connect('dbname={0} user={1} host={2}'.format(self.db_database, self.db_user, self.db_server))
            conn.autocommit = True
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(
                    self.word))
        except ConnectionError:
            print('[!] Unable to connect to the database')
        return cursor

    def process(self):
        self.do_search()
        print('\tSearching results.')
