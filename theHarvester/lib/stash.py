import datetime
import sqlite3


class stash_manager:

    def __init__(self):
        self.db = "stash.sqlite"
        self.results = ""
        self.totalresults = ""
        self.latestscandomain = {}
        self.domainscanhistory = []
        #self.scanboarddata = []
        self.scanboarddata = {}
        self.scanstats = []
        self.latestscanresults = []
        self.previousscanresults = []

    def do_init(self):
        conn = sqlite3.connect(self.db)
        c = conn.cursor()
        c.execute('CREATE TABLE results (domain text, resource text, type text, find_date date, source text)')
        conn.commit()
        conn.close()
        return

    def store(self, domain, resource, res_type, source):
        self.domain = domain
        self.resource = resource
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        try:
            conn = sqlite3.connect(self.db)
            c = conn.cursor()
            c.execute('INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                      (self.domain, self.resource, self.type, self.date, self.source))
            conn.commit()
            conn.close()
        except Exception as e:
            print(e)
        return

    def store_all(self, domain, all, res_type, source):
        self.domain = domain
        self.all = all
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        for x in self.all:
            try:
                conn = sqlite3.connect(self.db)
                c = conn.cursor()
                c.execute('INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                          (self.domain, x, self.type, self.date, self.source))
                conn.commit()
                conn.close()
            except Exception as e:
                print(e)
        return

    def generatedashboardcode(self, domain):
        try:
            self.latestscandomain["domain"] = domain
            conn = sqlite3.connect(self.db)
            c = conn.cursor()
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="host"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["host"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="email"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["email"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["ip"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["vhost"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["shodan"] = data[0]
            c.execute('''SELECT MAX(find_date) FROM results WHERE domain=?''', (domain,))
            data = c.fetchone()
            self.latestscandomain["latestdate"] = data[0]
            latestdate = data[0]
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''', (domain, latestdate,))
            scandetailshost = c.fetchall()
            self.latestscandomain["scandetailshost"] = scandetailshost
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''',
                      (domain, latestdate,))
            scandetailsemail = c.fetchall()
            self.latestscandomain["scandetailsemail"] = scandetailsemail
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''', (domain, latestdate,))
            scandetailsip = c.fetchall()
            self.latestscandomain["scandetailsip"] = scandetailsip
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''',
                      (domain, latestdate,))
            scandetailsvhost = c.fetchall()
            self.latestscandomain["scandetailsvhost"] = scandetailsvhost
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''',
                      (domain, latestdate,))
            scandetailsshodan = c.fetchall()
            self.latestscandomain["scandetailsshodan"] = scandetailsshodan
            return self.latestscandomain
        except Exception as e:
            print(e)
        finally:
            conn.close()

    def getlatestscanresults(self, domain, previousday=False):
        try:
            conn = sqlite3.connect(self.db)
            if previousday:
                try:
                    c = conn.cursor()
                    c.execute('''
                    SELECT DISTINCT(find_date)
                    FROM results
                    WHERE find_date=date('now', '-1 day') and domain=?''', (domain,))
                    previousscandate = c.fetchone()
                    if not previousscandate:   # When theHarvester runs first time/day this query will return.
                        self.previousscanresults = ["No results", "No results", "No results", "No results", "No results"]
                    else:
                        c = conn.cursor()
                        c.execute('''
                        SELECT find_date, domain, source, type, resource
                        FROM results
                        WHERE find_date=? and domain=?
                        ORDER BY source,type
                        ''', (previousscandate[0], domain,))
                        results = c.fetchall()
                        self.previousscanresults = results
                    return self.previousscanresults
                except Exception as e:
                    print('Error in getting the previous scan results from the database: ' + str(e))
            else:
                try:
                    c = conn.cursor()
                    c.execute('''SELECT MAX(find_date) FROM results WHERE domain=?''', (domain,))
                    latestscandate = c.fetchone()
                    c = conn.cursor()
                    c.execute('''
                    SELECT find_date, domain, source, type, resource
                    FROM results
                    WHERE find_date=? and domain=?
                    ORDER BY source,type
                    ''', (latestscandate[0], domain,))
                    results = c.fetchall()
                    self.latestscanresults = results
                    return self.latestscanresults
                except Exception as e:
                    print('Error in getting the latest scan results from the database: ' + str(e))
        except Exception as e:
            print('Error connecting to theHarvester database: ' + str(e))
        finally:
            conn.close()

    def getscanboarddata(self):
        try:
            conn = sqlite3.connect(self.db)
            c = conn.cursor()
            c.execute('''SELECT COUNT(*) from results WHERE type="host"''')
            data = c.fetchone()
            self.scanboarddata["host"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE type="email"''')
            data = c.fetchone()
            self.scanboarddata["email"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE type="ip"''')
            data = c.fetchone()
            self.scanboarddata["ip"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE type="vhost"''')
            data = c.fetchone()
            self.scanboarddata["vhost"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE type="shodan"''')
            data = c.fetchone()
            self.scanboarddata["shodan"] = data[0]
            c.execute('''SELECT COUNT(DISTINCT(domain)) FROM results ''')
            data = c.fetchone()
            self.scanboarddata["domains"] = data[0]
            return self.scanboarddata
        except Exception as e:
            print(e)
        finally:
            conn.close()

    def getscanhistorydomain(self, domain):
        try:
            conn = sqlite3.connect(self.db)
            c = conn.cursor()
            c.execute('''SELECT DISTINCT(find_date) FROM results WHERE domain=?''', (domain,))
            dates = c.fetchall()
            for date in dates:
                c = conn.cursor()
                c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="host" AND find_date=?''',
                          (domain, date[0]))
                counthost = c.fetchone()
                c = conn.cursor()
                c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="email" AND find_date=?''',
                          (domain, date[0]))
                countemail = c.fetchone()
                c = conn.cursor()
                c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="ip" AND find_date=?''',
                          (domain, date[0]))
                countip = c.fetchone()
                c = conn.cursor()
                c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="vhost" AND find_date=?''',
                          (domain, date[0]))
                countvhost = c.fetchone()
                c = conn.cursor()
                c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="shodan" AND find_date=?''',
                          (domain, date[0]))
                countshodan = c.fetchone()
                results = {
                    "date": str(date[0]),
                    "hosts": str(counthost[0]),
                    "email": str(countemail[0]),
                    "ip": str(countip[0]),
                    "vhost": str(countvhost[0]),
                    "shodan": str(countshodan[0])
                }
                self.domainscanhistory.append(results)
            return self.domainscanhistory
        except Exception as e:
            print(e)
        finally:
            conn.close()

    def getpluginscanstatistics(self):
        try:
            conn = sqlite3.connect(self.db)
            c = conn.cursor()
            c.execute('''
            SELECT domain,find_date, type, source, count(*)
            FROM results
            GROUP BY domain, find_date, type, source
            ''')
            results = c.fetchall()
            self.scanstats = results
            return self.scanstats
        except Exception as e:
            print(e)
        finally:
            conn.close()

    def latestscanchartdata(self, domain):
        try:
            self.latestscandomain["domain"] = domain
            conn = sqlite3.connect(self.db)
            c = conn.cursor()
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="host"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["host"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="email"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["email"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["ip"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["vhost"] = data[0]
            c.execute('''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''', (domain,))
            data = c.fetchone()
            self.latestscandomain["shodan"] = data[0]
            c.execute('''SELECT MAX(find_date) FROM results WHERE domain=?''', (domain,))
            data = c.fetchone()
            self.latestscandomain["latestdate"] = data[0]
            latestdate = data[0]
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''', (domain, latestdate,))
            scandetailshost = c.fetchall()
            self.latestscandomain["scandetailshost"] = scandetailshost
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''',
                      (domain, latestdate,))
            scandetailsemail = c.fetchall()
            self.latestscandomain["scandetailsemail"] = scandetailsemail
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''', (domain, latestdate,))
            scandetailsip = c.fetchall()
            self.latestscandomain["scandetailsip"] = scandetailsip
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''',
                      (domain, latestdate,))
            scandetailsvhost = c.fetchall()
            self.latestscandomain["scandetailsvhost"] = scandetailsvhost
            c.execute('''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''',
                      (domain, latestdate,))
            scandetailsshodan = c.fetchall()
            self.latestscandomain["scandetailsshodan"] = scandetailsshodan
            return self.latestscandomain
        except Exception as e:
            print(e)
        finally:
            conn.close()
