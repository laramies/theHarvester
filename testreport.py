try:
    import plotly
    import plotly.graph_objs as go
    import plotly.plotly as py
    import datetime
    scanneddomain='google.com'
    totalnumberofdomains = 4
    totalnumberofhosts = 14
    totalnumberofip = 10
    totalnumberofvhost=3
    totalnumberofemail=15
    totalnumberofshodan=7
    date1=datetime.date(2018,12,1)
    date2=datetime.date(2018,12,3)
    date3=datetime.date(2018,12,5)
    date4=datetime.date(2018,12,8)
    date5=datetime.date(2018,12,10)
    HTML='''
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
    '''+'''<tr>
    <td style="width: 113px; text-align: center;background: #ffff38"><h2><strong>'''+str(totalnumberofdomains)+'''</strong></h2></td>
    <td style="width: 108px; text-align: center;background: #1f77b4"><h2><strong>'''+str(totalnumberofhosts)+'''</strong></h2></td>
    <td style="width: 119px; text-align: center;background: #ff7f0e"><h2><strong>'''+str(totalnumberofip)+'''</strong></h2></td>
    <td style="width: 111px; text-align: center;background: #2ca02c"><h2><strong>'''+str(totalnumberofvhost)+'''</strong></h2></td>
    <td style="width: 110px; text-align: center;background: #9467bd"><h2><strong>'''+str(totalnumberofemail)+'''</strong></h2></td>
    <td style="width: 110px; text-align: center;background: #d62728"><h2><strong>'''+str(totalnumberofshodan)+'''</strong></h2></td>
    '''+'''
    </tr>
    </tbody>
    </table>
    <p>&nbsp;</p>
    <p>&nbsp;</p>
    <p>&nbsp;</p>
    <p>&nbsp;</p>
    <h2><span style="color: #000000;">Latest scan summary for '''+scanneddomain+'''</span></h2>
    <h3><strong><span style="color: #0000ff;">Emails found:</span></strong></h3>
    <ul>
    <li><span style="color: #000000;">email1@google.com</span></li>
    <li><span style="color: #000000;">email2@google.com</span></li>
    </ul>
    <h3><span style="color: #0000ff;">Hosts found:</span></h3>
    <ul>
    <li><span style="color: #000000;">host1.google.com</span></li>
    <li><span style="color: #000000;">host2.google.com</span></li>
    <li><span style="color: #000000;">host3.google.com</span></li>
    </ul>
    <h3><strong><span style="color: #0000ff;">IP addresses found:</span></strong></h3>
    <ul>
    <li><span style="color: #000000;">87.12.42.12</span></li>
    <li><span style="color: #000000;">87.12.42.11</span></li>
    <li><span style="color: #000000;">87.12.43.11</span></li>
    <li><span style="color: #000000;">87.12.44.11</span></li>
    </ul>
    <h3><span style="color: #0000ff;"><strong>Shodan results:</strong></span></h3>
    <ul>
    <li><span style="color: #000000;">NONE</span></li>
    </ul>
    '''
    barcolumns = ["host","ip","vhost","shodan","email"]
    bardata = [totalnumberofhosts,totalnumberofip,totalnumberofvhost,totalnumberofshodan,totalnumberofemail]
    layout = dict(title = "Last scan - number of targets identified for "+scanneddomain+" on "+str(date5),
              xaxis = dict(title = 'Targets'),
              yaxis = dict(title = 'Hits'),
              )

    barchart=plotly.offline.plot({
    "data": [go.Bar(x=barcolumns,y=bardata)],
    "layout": layout,
    }, auto_open=False,include_plotlyjs=False,filename='report.html', output_type='div')
    HTML+=barchart
    
    
    trace0 = go.Scatter(
    x=[date1,date2,date3,date4,date5],
    y=[3, 10, 9, 17,10],
    mode = 'lines+markers',
    name = 'hosts')
    
    trace1 = go.Scatter(
    x=[date1,date2,date3,date4,date5],
    y=[2, 6, 9, 10, 5],
    mode = 'lines+markers',
    name = 'IP address')

    trace2 = go.Scatter(
    x=[date1,date2,date3,date4,date5],
    y=[1, 2, 4, 6, 2],
    mode = 'lines+markers',
    name = 'vhost')

    trace3 = go.Scatter(
    x=[date1,date2,date3,date4,date5],
    y=[2, 3, 2, 5, 7],
    mode = 'lines+markers',
    name = 'shodan')

    trace4 = go.Scatter(
    x=[date1,date2,date3,date4,date5],
    y=[12, 14, 20, 24, 20],
    mode = 'lines+markers',
    name = 'email')


    data = [trace0, trace1, trace2, trace3, trace4]
    layout = dict(title = "Scanning history for "+scanneddomain,
              xaxis = dict(title = 'Date'),
              yaxis = dict(title = 'Results'),
              )

    scatterchart = plotly.offline.plot({
    "data": data,
    "layout": layout}, auto_open=False,include_plotlyjs=False,filename='report.html', output_type='div')
    HTML+=scatterchart
    HTML+='<p><span style="color: #000000;">Report generated on '+ str(datetime.datetime.now())+'</span></p>'
    HTML+='''
    </body>
    </html>
    '''
    
    Html_file= open("report.html","w")
    Html_file.write(HTML)
    Html_file.close()
except Exception as e:
    print("ERROR: "+str(e))
