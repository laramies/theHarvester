import sqlite3
import datetime


class stash_manager:

    def __init__(self):
        self.db = "stash.sqlite"
        self.results = ""
        self.totalresults = ""
          
    def do_init(self):
        conn = sqlite3.connect(self.db) 
        c = conn.cursor()
        c.execute ('CREATE TABLE results (domain text, resource text, type text, find_date date, source text)')
        conn.commit()
        conn.close()
        return
    
    def store(self,domain, resource,res_type,source):
        self.domain = domain
        self.resource = resource
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        try:
         conn = sqlite3.connect(self.db) 
         c = conn.cursor()
         c.execute ('INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',(self.domain,self.resource,self.type,self.date,self.source))
         conn.commit()
         conn.close()
        except Exception, e:
            print e
        return

    def store_all(self,domain,all,res_type,source):
        self.domain = domain
        self.all = all
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        for x in self.all:
            try:
                conn = sqlite3.connect(self.db) 
                c = conn.cursor()
                c.execute ('INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',(self.domain,x,self.type,self.date,self.source))
                conn.commit()
                conn.close()
            except Exception, e:
                print e
        return