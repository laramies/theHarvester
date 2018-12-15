class htmlgenerator:
    def __init__(self,word):
        self.domain = word

    def generatedashboardcode(self, scanboarddata):
        totalnumberofdomains = scanboarddata['domains']
        totalnumberofhosts = scanboarddata['host']
        totalnumberofip = scanboarddata['ip']
        totalnumberofvhost= scanboarddata['vhost']
        totalnumberofemail= scanboarddata['email']
        totalnumberofshodan= scanboarddata['shodan']
        html='''
        <head><script src="https://cdn.plot.ly/plotly-latest.min.js"></script></head>
        <html>
        <body>
        <h1 style="text-align: center;"><span style="color: #ff0000;">theHarvester Scan Report</span></h1>
        <h2><span style="color: #000000;"><strong>TheHarvester scanning dashboard</strong></span></h2>
        <table align="left" style="height: 108px; border-color: #000000; margin-left: auto; margin-right: auto;" border=" #000000" width="713">
        <tbody>
        <tr>
        <td style="width: 113px; text-align: center;background: #ffff38"><h2><strong>Domains</strong></h2></td>
        <td style="width: 108px; text-align: center;background: #1f77b4"><h2><strong>Hosts</strong></h2></td>
        <td style="width: 119px; text-align: center;background: #ff7f0e"><h2><strong>IP Addresses</strong></h2></td>
        <td style="width: 111px; text-align: center;background: #2ca02c"><h2><strong>Vhosts</strong></h2></td>
        <td style="width: 110px; text-align: center;background: #9467bd"><h2><strong>Emails</strong></h2></td>
        <td style="width: 110px; text-align: center;background: #d62728"><h2><strong>Shodan</strong></h2></td>
        </tr>
        <tr>
        <td style="width: 113px; text-align: center;background: #ffff38"><h2><strong>'''+str(totalnumberofdomains)+'''</strong></h2></td>
        <td style="width: 108px; text-align: center;background: #1f77b4"><h2><strong>'''+str(totalnumberofhosts)+'''</strong></h2></td>
        <td style="width: 119px; text-align: center;background: #ff7f0e"><h2><strong>'''+str(totalnumberofip)+'''</strong></h2></td>
        <td style="width: 111px; text-align: center;background: #2ca02c"><h2><strong>'''+str(totalnumberofvhost)+'''</strong></h2></td>
        <td style="width: 110px; text-align: center;background: #9467bd"><h2><strong>'''+str(totalnumberofemail)+'''</strong></h2></td>
        <td style="width: 110px; text-align: center;background: #d62728"><h2><strong>'''+str(totalnumberofshodan)+'''</strong></h2></td>
         </tr>
        </tbody>
        </table>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        '''
        return html
    
    def generatescandetailsdomain(self, word, latestscandomain):
        emails = latestscandomain['scandetailsemail']
        hosts = latestscandomain['scandetailshost']
        ips = latestscandomain['scandetailsip']
        vhosts = latestscandomain['scandetailsvhost']
        shodans = latestscandomain['scandetailsshodan']
        html='''
        <p>&nbsp;</p>
        <p>&nbsp;</p>
        <h2><span style="color: #000000;">Latest scan details for '''+ word + ''' on: '''+str(latestscandomain['latestdate'])+'''</span></h2>
        <h3><strong><span style="color: #0000ff;">Emails found:</span></strong></h3>
        <ul>
        '''
        for email in emails:
            html += '<li><span style="color: #000000;">'+ str(email[1]) + "</span></li>"
        html +='''
        </ul>
        <h3><span style="color: #0000ff;">Hosts found:</span></h3>
        <ul>
        '''
        for host in hosts:
            html += '<li><span style="color: #000000;">'+ str(host[1]) + "</span></li>"
        html +='''
        </ul>
        <h3><span style="color: #0000ff;">IP found:</span></h3>
        <ul>
        '''
        for ip in ips:
            html += '<li><span style="color: #000000;">'+str(ip[1])+"</span></li>"
        html +='''
        </ul>
        <h3><span style="color: #0000ff;">vhosts found:</span></h3>
        <ul>
        '''
        for vhost in vhosts:
            html +='<li><span style="color: #000000;">'+str(vhost[1])+"</span></li>"
        html +='''
        </ul>
        <h3><span style="color: #0000ff;">Shodan results:</span></h3>
        <ul>
        '''
        for shodan in shodans:
            html +='<li><span style="color: #000000;">'+str(shodan[1])+"</span></li>"
        html +='''
        </ul>       
        '''
        return html