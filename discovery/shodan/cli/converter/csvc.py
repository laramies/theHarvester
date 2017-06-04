
from .base import Converter
from ...helpers import iterate_files

from collections import MutableMapping
from csv import writer as csv_writer, excel


class CsvConverter(Converter):

    fields = [
        'data',
        'hostnames',
        'ip',
        'ip_str',
        'ipv6',
        'org',
        'isp',
        'location.country_code',
        'location.city',
        'location.country_name',
        'location.latitude',
        'location.longitude',
        'os',
        'asn',
        'port',
        'transport',
        'product',
        'version',
        
        'ssl.cipher.version',
        'ssl.cipher.bits',
        'ssl.cipher.name',
        'ssl.alpn',
        'ssl.versions',
        'ssl.cert.serial',
        'ssl.cert.fingerprint.sha1',
        'ssl.cert.fingerprint.sha256',
        
        'html',
        'title',
    ]
    
    def process(self, files):
        writer = csv_writer(self.fout, dialect=excel)
        
        # Write the header
        writer.writerow(self.fields)
        
        for banner in iterate_files(files):
            try:
                row = []
                for field in self.fields:
                    value = self.banner_field(banner, field)
                    row.append(value)
                writer.writerow(row)
            except:
                pass
    
    def banner_field(self, banner, flat_field):
        # The provided field is a collapsed form of the actual field
        fields = flat_field.split('.')
    
        try:
            current_obj = banner
            for field in fields:
                current_obj = current_obj[field]
            
            # Convert a list into a concatenated string
            if isinstance(current_obj, list):
                current_obj = ','.join([str(i) for i in current_obj])
            
            return current_obj
        except:
            pass
    
        return ''
    
    def flatten(self, d, parent_key='', sep='.'):
        items = []
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            if isinstance(v, MutableMapping):
                items.extend(flatten(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)