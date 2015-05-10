from lib import markup
from lib import graphs
import re


class htmlExport():

    def __init__(self, users, hosts, vhosts, dnsres,
                 dnsrev, file, domain, shodan, tldres):
        self.users = users
        self.hosts = hosts
        self.vhost = vhosts
        self.fname = file
        self.dnsres = dnsres
        self.dnsrev = dnsrev
        self.domain = domain
        self.shodan = shodan
        self.tldres = tldres
        self.style = ""

    def styler(self):
        a = """<style type='text/css'>body {
			 background: #FFFFFF  top no-repeat;
		 }

		h1 { font-family: arial, Times New Roman, times-roman, georgia, serif;
			color: #680000;
			margin: 0;
			padding: 0px 0px 6px 0px;
			font-size: 51px;
			line-height: 44px;
			letter-spacing: -2px;
			font-weight: bold;
		}

		h3 { font-family: arial, Times New Roman, times-roman, georgia, serif;
			color: #444;
			margin: 0;
			padding: 0px 0px 6px 0px;
			font-size: 30px;
			line-height: 44px;
			letter-spacing: -2px;
			font-weight: bold;
		}

		li { font-family: arial, Times New Roman, times-roman, georgia, serif;
			color: #444;
			margin: 0;
			padding: 0px 0px 6px 0px;
			font-size: 15px;
			line-height: 15px;
			letter-spacing: 0.4px;

		}

		h2{
		font-family: arial, Times New Roman, times-roman, georgia, serif;
				font-size: 48px;
				line-height: 40px;
				letter-spacing: -1px;
				color: #680000 ;
				margin: 0 0 0 0;
				padding: 0 0 0 0;
				font-weight: 100;

		}

		pre {
		overflow: auto;
		padding-left: 15px;
		padding-right: 15px;
		font-size: 11px;
		line-height: 15px;
		margin-top: 10px;
		width: 93%;
		display: block;
		background-color: #eeeeee;
		color: #000000;
		max-height: 300px;
		}
		</style>
		"""
        self.style = a

    def writehtml(self):
        page = markup.page()
        # page.init (title="theHarvester
        # Results",css=('edge.css'),footer="Edge-security 2011")A
        page.html()
        self.styler()
        page.head(self.style)
        page.body()
        page.h1("theHarvester results")
        page.h2("for :" + self.domain)
        page.h3("Dashboard:")
        graph = graphs.BarGraph('vBar')
        graph.values = [len(
            self.users),
            len(self.hosts),
            len(self.vhost),
            len(self.tldres),
            len(self.shodan)]
        graph.labels = ['Emails', 'hosts', 'Vhost', 'TLD', 'Shodan']
        graph.showValues = 1
        page.body(graph.create())
        page.h3("E-mails names found:")
        if self.users != []:
            page.ul(class_="userslist")
            page.li(self.users, class_="useritem")
            page.ul.close()
        else:
            page.h2("No emails found")
        page.h3("Hosts found:")
        if self.hosts != []:
            page.ul(class_="softlist")
            page.li(self.hosts, class_="softitem")
            page.ul.close()
        else:
            page.h2("No hosts found")
        if self.tldres != []:
            page.h3("TLD domains found in TLD expansion:")
            page.ul(class_="tldlist")
            page.li(self.tldres, class_="tlditem")
            page.ul.close()
        if self.dnsres != []:
            page.h3("Hosts found in DNS brute force:")
            page.ul(class_="dnslist")
            page.li(self.dnsres, class_="dnsitem")
            page.ul.close()
        if self.dnsrev != []:
            page.h3("Hosts found with reverse lookup :")
            page.ul(class_="dnsrevlist")
            page.li(self.dnsrev, class_="dnsrevitem")
            page.ul.close()
        if self.vhost != []:
            page.h3("Virtual hosts found:")
            page.ul(class_="pathslist")
            page.li(self.vhost, class_="pathitem")
            page.ul.close()
        if self.shodan != []:
            shodanalysis = []
            page.h3("Shodan results:")
            for x in self.shodan:
                res = x.split("SAPO")
                page.h3(res[0])
                page.a("Port :" + res[2])
                page.pre(res[1])
                page.pre.close()
                ban = res[1]
                reg_server = re.compile('Server:.*')
                temp = reg_server.findall(res[1])
                if temp != []:
                    shodanalysis.append(res[0] + ":" + temp[0])
            if shodanalysis != []:
                page.h3("Server technologies:")
                repeated = []
                for x in shodanalysis:
                    if x not in repeated:
                        page.pre(x)
                        page.pre.close()
                        repeated.append(x)
        page.body.close()
        page.html.close()
        file = open(self.fname, 'w')
        for x in page.content:
            try:
                file.write(x)
            except:
                print "Exception" + x  # send to logs
                pass
        file.close
        return "ok"
