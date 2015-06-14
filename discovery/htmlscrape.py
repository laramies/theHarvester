import myparser
import time
import sys
import subprocess


class html_scape:
    #, 
    def __init__(self, word, depth, wait, limit_rate, timeout, save):
        self.word = word
        self.depth = "--level=" + str(depth)
        self.wait = "--wait=" + str(wait)
        self.limit_rate = "--limit-rate=" + str(limit_rate)
        self.timeout = "--read-timeout=" + str(timeout)
        self.save = "--directory-prefix=" + str(save)

    def do_search(self):
      try:
        #Using subprocess, more or less because of the rebust HTML miroring ability 
        #And also allows proxy / VPN Support
        subprocess.call(["wget", self.save, "--recursive", self.depth, self.wait, self.limit_rate, 
                          self.timeout, "--page-requisites", "--html-extension", 
                          "--convert-links", "--domains", self.word, self.word])
        print "[*] Wget completed miror"
      except:
        print "[!] ERROR during Wget Request"

    def get_emails(self):
      #Direct location of new dir created during wget
      directory = self.save.strip('--directory-prefix=') + self.word
      #Grep for any data containing "@", sorting out binary files as well
      try:
        ps = subprocess.Popen(('grep', '-r', "@", directory), stdout=subprocess.PIPE)
        #Take in "ps" var and parse it for only email addresses 
        output = []
        val = subprocess.check_output(("grep", "-i", "-o", '[A-Z0-9._%+-]\+@[A-Z0-9.-]\+\.[A-Z]\{2,4\}'),
                                        stdin=ps.stdout)
        output.append(val)
        print "[*] Patern mattching completed"
      except: 
        print "[!] ERROR during patern matching"
      #using PIPE output/input to avoid using "shell=True", 
      #which can leave major security holes if script has certain permisions
      return output
