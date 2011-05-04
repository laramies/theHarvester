import string
import httplib, sys
import parser
import re
import time

class search_exalead:
	def __init__(self,word,limit,start):
		self.word=word
		self.files="pdf"
		self.results=""
		self.totalresults=""
		self.server="www.exalead.com"
		self.hostname="www.exalead.com"
		self.userAgent="(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
		self.limit=limit
		self.counter=start
		
	def do_search(self):
		h = httplib.HTTP(self.server)
		h.putrequest('GET', "/search/web/results/?q=%40"+ self.word + "&elements_per_page=100&start_index="+str(self.counter))
		h.putheader('Host', self.hostname)
		h.putheader('User-agent', self.userAgent)	
		h.endheaders()
		returncode, returnmsg, headers = h.getreply()
		self.results = h.getfile().read()
		self.totalresults+= self.results

	def do_search_files(self,files):
		h = httplib.HTTP(self.server)
		h.putrequest('GET', "search/web/results/?q="+ self.word + "filetype:"+ self.files +"&elements_per_page=100&start_index="+self.counter)
		h.putheader('Host', self.hostname)
		h.putheader('User-agent', self.userAgent)	
		h.endheaders()
		returncode, returnmsg, headers = h.getreply()
		self.results = h.getfile().read()
		self.totalresults+= self.results

	def check_next(self):
		renext = re.compile('topNextUrl')
		nextres=renext.findall(self.results)	
		if nextres !=[]:
			nexty="1"
			print str(self.counter)
		else:
			nexty="0"
		return nexty
		
	def get_emails(self):
		rawres=parser.parser(self.totalresults,self.word)
		return rawres.emails()
	
	def get_hostnames(self):
		rawres=parser.parser(self.totalresults,self.word)
		return rawres.hostnames()
	
	def get_files(self):
		rawres=parser.parser(self.totalresults,self.word)
		return rawres.fileurls(self.files)
	

	def process(self):
		while self.counter <= self.limit:
			self.do_search()
			self.counter+=100
			print "\tSearching " + str(self.counter) + " results..."
			
				
	def process_files(self,files):
		while self.counter < self.limit:
			self.do_search_files(files)
			time.sleep(1)
			more = self.check_next()
			if more == "1":
				self.counter+=100
			else:
				break

