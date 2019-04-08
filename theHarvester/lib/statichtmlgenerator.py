class htmlgenerator:

    def __init__(self, word):
        self.domain = word

    def generatepreviousscanresults(self, previousscanresults):
        try:
            if previousscanresults[0]=='No results':
                html='''
<h2><span style="color: #000000;"><strong>Previous scan report </strong></span></h2>
<p>&nbsp;</p>
<table style="height: 63px; border-color: #000000;" border="#000000" width="811">
<tbody>
<tr>
<td style="width: 156.042px; text-align: center;"><strong>Date</strong></td>
<td style="width: 156.042px; text-align: center;"><strong>Domain</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Plugin</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Record type</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Result</strong></td>
</tr>
<tr>
'''
                for i in previousscanresults:
                    html += '<td style="width: 156.042px;">' + str(i) + "</td>"
                    html += '<td style="width: 156.042px;">' + str(i) + "</td>"
                    html += '<td style="width: 157.153px;">' + str(i) + "</td>"
                    html += '<td style="width: 157.153px;">' + str(i) + "</td>"
                    html += '<td style="width: 157.153px;">' + str(i) + "</td>"
                    html += '</tr>'
            else:
                html = '''
<h2><span style="color: #000000;"><strong>Previous scan report </strong></span></h2>
<p>&nbsp;</p>
<table style="height: 63px; border-color: #000000;" border="#000000" width="811">
<tbody>
<tr>
<td style="width: 156.042px; text-align: center;"><strong>Date</strong></td>
<td style="width: 156.042px; text-align: center;"><strong>Domain</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Plugin</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Record type</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Result</strong></td>
</tr>
<tr>
'''
                for i in previousscanresults:
                    html += '<td style="width: 156.042px;">' + str(i[0]) + "</td>"
                    html += '<td style="width: 156.042px;">' + str(i[1]) + "</td>"
                    html += '<td style="width: 157.153px;">' + str(i[2]) + "</td>"
                    html += '<td style="width: 157.153px;">' + str(i[3]) + "</td>"
                    html += '<td style="width: 157.153px;">' + str(i[4]) + "</td>"
                    html += '</tr>'
            html += '''
</tbody>
</table>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
'''
            return html
        except Exception as e:
            print('Error generating the previous scan results HTML code: ' + str(e))

    def generatelatestscanresults(self, latestscanresults):
        try:
            html='''
<h2><span style="color: #000000;"><strong>Latest scan report </strong></span></h2>
<p>&nbsp;</p>
<table style="height: 63px; border-color: #000000;" border="#000000" width="811">
<tbody>
<tr>
<td style="width: 156.042px; text-align: center;"><strong>Date</strong></td>
<td style="width: 156.042px; text-align: center;"><strong>Domain</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Plugin</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Record type</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Result</strong></td>
</tr>
<tr>
'''
            for i in latestscanresults:
                html += '<td style="width: 156.042px;">' + str(i[0]) + "</td>"
                html += '<td style="width: 156.042px;">' + str(i[1]) + "</td>"
                html += '<td style="width: 157.153px;">' + str(i[2]) + "</td>"
                html += '<td style="width: 157.153px;">' + str(i[3]) + "</td>"
                html += '<td style="width: 157.153px;">' + str(i[4]) + "</td>"
                html += '</tr>'
            html += '''
</tbody>
</table>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
'''
            return html
        except Exception as e:
            print('Error generating the latest scan results HTML code: ' + str(e))

    def beginhtml(self):
        html = '''
<head><script src="https://cdn.plot.ly/plotly-latest.min.js"></script></head>
<html>
<body>
<h1 style="text-align: center;"><span style="color: #ff0000;">theHarvester Scan Report</span></h1>
        '''
        return html

    def generatedashboardcode(self, scanboarddata):
        try:
            totalnumberofdomains = scanboarddata['domains']
            totalnumberofhosts = scanboarddata['host']
            totalnumberofip = scanboarddata['ip']
            totalnumberofvhost= scanboarddata['vhost']
            totalnumberofemail= scanboarddata['email']
            totalnumberofshodan= scanboarddata['shodan']
            html='''
<h2 style="text-align: center;"><span style="color: #ff0000;">Scan dashboard</span></h2>
<table style="height: 108px; border-color: #000000; margin-left: auto; margin-right: auto;" border=" #000000" width="713">
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
'''
            return html
        except Exception as e:
            print('Error generating dashboard HTML code: ' + str(e))

    def generatepluginscanstatistics(self, scanstatistics):
        try:
            html = '''
<h2 style="text-align: center;"><span style="color: #ff0000;">theHarvester plugin statistics</span></h2>
<p>&nbsp;</p>
<table style="height: 63px; border-color: #000000; margin-left: auto; margin-right: auto;" border="#000000" width="811">
<tbody>
<tr>
<td style="width: 156.042px; text-align: center;"><strong>Domain</strong></td>
<td style="width: 156.042px; text-align: center;"><strong>Date</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Recordtype</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Source</strong></td>
<td style="width: 157.153px; text-align: center;"><strong>Total results</strong></td>
</tr>
<tr>
'''
            for i in scanstatistics:
                html += '<td style="width: 156.042px;">' + str(i[0]) + "</td>"
                html += '<td style="width: 156.042px;">' + str(i[1]) + "</td>"
                html += '<td style="width: 157.153px;">' + str(i[2]) + "</td>"
                html += '<td style="width: 157.153px;">' + str(i[3]) + "</td>"
                html += '<td style="width: 157.153px;">' + str(i[4]) + "</td>"
                html += '</tr>'
            html += '''
</tbody>
</table>
<p>&nbsp;</p>
<p>&nbsp;</p>
'''
            return html
        except Exception as e:
            print('Error generating scan statistics HTML code: ' + str(e))
