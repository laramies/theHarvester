from theHarvester.lib import stash
from datetime import datetime
import plotly
import plotly.graph_objs as go

try:
    db = stash.StashManager()
    db.do_init()
except Exception as error:
    print(f'{error}')


class GraphGenerator:

    def __init__(self, domain):
        self.domain = domain
        self.bardata = []
        self.barcolumns = []
        self.scatterxdata = []
        self.scattercountemails = []
        self.scattercounthosts = []
        self.scattercountips = []
        self.scattercountshodans = []
        self.scattercountvhosts = []

    def drawlatestscangraph(self, domain, latestscandata):
        try:
            self.barcolumns = ['email', 'host', 'ip', 'shodan', 'vhost']
            self.bardata.append(latestscandata['email'])
            self.bardata.append(latestscandata['host'])
            self.bardata.append(latestscandata['ip'])
            self.bardata.append(latestscandata['shodan'])
            self.bardata.append(latestscandata['vhost'])
            layout = dict(title='Latest scan - number of targets identified for ' + domain,
                          xaxis=dict(title='Targets'),
                          yaxis=dict(title='Hits'),)
            barchartcode = plotly.offline.plot({
                'data': [go.Bar(x=self.barcolumns, y=self.bardata)],
                'layout': layout,
            }, auto_open=False, include_plotlyjs=False, filename='report.html', output_type='div')
            return barchartcode
        except Exception as e:
            print(f'Error generating HTML bar graph code for domain: {e}')

    def drawscattergraphscanhistory(self, domain, scanhistorydomain):
        try:
            scandata = scanhistorydomain
            for i in scandata:
                self.scatterxdata.append(datetime.date(datetime.strptime(i['date'], '%Y-%m-%d')))
                self.scattercountemails.append(int(i['email']))
                self.scattercounthosts.append(int(i['hosts']))
                self.scattercountips.append(int(i['ip']))
                self.scattercountshodans.append(int(i['shodan']))
                self.scattercountvhosts.append(int(i['vhost']))

            trace0 = go.Scatter(
                x=self.scatterxdata,
                y=self.scattercounthosts,
                mode='lines+markers',
                name='hosts')

            trace1 = go.Scatter(
                x=self.scatterxdata,
                y=self.scattercountips,
                mode='lines+markers',
                name='IP address')

            trace2 = go.Scatter(
                x=self.scatterxdata,
                y=self.scattercountvhosts,
                mode='lines+markers',
                name='vhost')

            trace3 = go.Scatter(
                x=self.scatterxdata,
                y=self.scattercountshodans,
                mode='lines+markers',
                name='shodan')

            trace4 = go.Scatter(
                x=self.scatterxdata,
                y=self.scattercountemails,
                mode='lines+markers',
                name='email')

            data = [trace0, trace1, trace2, trace3, trace4]
            layout = dict(title=f'Scanning history for {domain}', xaxis=dict(title='Date'),
                          yaxis=dict(title='Results'))
            scatterchartcode = plotly.offline.plot({
                'data': data,
                'layout': layout}, auto_open=False, include_plotlyjs=False, filename='report.html',
                output_type='div')
            return scatterchartcode
        except Exception as e:
            print(f'Error generating HTML for the historical graph for domain: {e}')
