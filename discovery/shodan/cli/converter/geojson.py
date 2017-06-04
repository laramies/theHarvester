
from .base import Converter
from ...helpers import get_ip, iterate_files

class GeoJsonConverter(Converter):
    
    def header(self):
        self.fout.write("""{
            "type": "FeatureCollection",
            "features": [
        """)
    
    def footer(self):
        self.fout.write("""{ }]}""")
    
    def process(self, files):
        # Write the header
        self.header()
        
        hosts = {}
        for banner in iterate_files(files):
            ip = get_ip(banner)
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
            ip = get_ip(host)
            lat, lon = host['location']['latitude'], host['location']['longitude']

            feature = """{
                "type": "Feature",
                "id": "{}",
                "properties": {
                    "name": "{}"
                 },
                "geometry": {
                    "type": "Point",
                    "coordinates": [{}, {}]
                }
            }""".format(ip, ip, lat, lon)

            self.fout.write(feature)
        except Exception as e:
            pass
