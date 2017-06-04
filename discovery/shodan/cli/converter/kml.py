
from .base import Converter
from ...helpers import iterate_files

class KmlConverter(Converter):
    
    def header(self):
        self.fout.write("""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>""")
    
    def footer(self):
        self.fout.write("""</Document></kml>""")
    
    def process(self, files):
        # Write the header
        self.header()
        
        hosts = {}
        for banner in iterate_files(files):
            ip = banner.get('ip_str', banner.get('ipv6', None))
            if not ip:
                continue
    
            if ip not in hosts:
                hosts[ip] = banner
                hosts[ip]['ports'] = []
    
            hosts[ip]['ports'].append(banner['port'])
    
        for ip, host in iter(hosts.items()):
            self.write(host)
        
        self.footer()
            
    
    def write(self, host):
        try:
            ip = host.get('ip_str', host.get('ipv6', None))
            lat, lon = host['location']['latitude'], host['location']['longitude']

            placemark = '<Placemark><name><![CDATA[<h1 style="margin-bottom:0;padding-bottom:0;font-size:1.5em">{}</h1>]]></name>'.format(ip)
            placemark += '<description><![CDATA['

            if 'hostnames' in host and host['hostnames']:
                placemark += '<div><a style="color: #999;margin-top:-10px;padding-top:0;" href="http://{0}" target="_blank">{0}</a></div>'.format(host['hostnames'][0])

            test = """
    <table>
        <tbody>
          <tr>
            <td>City</td>
            <th>Albuquerque</th>
          </tr>
          <tr>
            <td>Country</td>
            <th>United States</th>
          </tr>
          <tr>
            <td>Organization</td>
            <th>Nexcess.net L.L.C.</th>
          </tr>
        </tbody>
    </table>
    <h2>Ports</h2>
    <ul>
            """

            placemark += '<h2>Ports</h2><ul>'

            for port in host['ports']:
                placemark += """
                    <li style="background-color: #1CA8DD;
                    color: #FFF;
                    float: left;
                    font-family: Arial;
                    font-size: 12px;
                    font-weight: bold;
                    height: 48px;
                    margin: 5px;
                    position: relative;
                    text-shadow: none;
                    width: 48px;"><span style="color: #FFF;
                    height: 34px;
                    position: absolute;
                    text-align: center;
                    top: 30%;
                    width: 48px;">{}</span>
                        </li>
                """.format(port)

            placemark += '</ul><div style="clear:both"></div>'

            placemark += """
                <div style="text-align:center"><a href="https://www.shodan.io/host/{0}" style="display: inline-block;
                    padding: 4px 10px;
                    margin-bottom: 0px;
                    font-size: 13px;
                    line-height: 18px;
                    color: #333;
                    text-align: center;
                    text-shadow: 0px 1px 1px rgba(255, 255, 255, 0.75);
                    vertical-align: middle;
                    cursor: pointer;
                    background-color: #F5F5F5;
                    background-image: -moz-linear-gradient(center top , #FFF, #E6E6E6);
                    background-repeat: repeat-x;
                    border-width: 1px;
                    border-style: solid;
                    border-color: #CCC #CCC #B3B3B3;
                    -moz-border-top-colors: none;
                    -moz-border-right-colors: none;
                    -moz-border-bottom-colors: none;
                    -moz-border-left-colors: none;
                    border-image: none;
                    border-radius: 4px;
                    box-shadow: 0px 1px 0px rgba(255, 255, 255, 0.2) inset, 0px 1px 2px rgba(0, 0, 0, 0.05);" target="_blank">View Details</a></div>
                    <div>powered by <a href="https://www.shodan.io" target="_blank">Shodan</a></div>
            """.format(ip)

            placemark += ']]></description>'
            placemark += '<Point><coordinates>{},{}</coordinates></Point>'.format(lon, lat)
            placemark += '</Placemark>'

            self.fout.write(placemark.encode('utf-8'))
        except Exception as e:
            pass
