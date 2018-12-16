try:
    import plotly.graph_objs as go
    import plotly.plotly as py
    import plotly
    import stash
    try:
        db=stash.stash_manager()
        db.do_init()
    except Exception as e:
        pass

    class graphgenerator:

        def __init__(self, domain):
            self.domain = domain
            self.bardata = []
            self.barcolumns = []
            self.scatterxhosts = []
            self.scatteryhosts = []
        
        def drawlatestscangraph(self,domain,latestscandata):
            self.barcolumns= ['email','host','ip','shodan','vhost']
            self.bardata.append(latestscandata['email'])
            self.bardata.append(latestscandata['host'])
            self.bardata.append(latestscandata['ip'])
            self.bardata.append(latestscandata['shodan'])
            self.bardata.append(latestscandata['vhost'])
            # for i in scandata:
            #     self.bardata.append(scandata[i])
            layout = dict(title = "Last scan - number of targets identified for "+ domain +" on "+str(latestscandata["latestdate"]),
            xaxis = dict(title = 'Targets'),
            yaxis = dict(title = 'Hits'),)
            barchartcode = plotly.offline.plot({
            "data": [go.Bar(x=self.barcolumns,y=self.bardata)],
            "layout": layout,
            }, auto_open=False,include_plotlyjs=False,filename='report.html', output_type='div')
            return barchartcode

        def drawscattergraph(self,domain,latestscandata):
            scandata = latestscandata
            for i in scandata['scandetails']:
                self.scatterxhosts.append(i)
                self.scatteryhosts.append(scandata[i])

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
            layout = dict(title = "Scanning history for " + domain,
                    xaxis = dict(title = 'Date'),
                    yaxis = dict(title = 'Results'),
                    )
            scatterchartcode = plotly.offline.plot({
            "data": data,
            "layout": layout}, auto_open=False,include_plotlyjs=False,filename='report.html', output_type='div')
            return scatterchartcode

except Exception as e:
    print(e)
            
