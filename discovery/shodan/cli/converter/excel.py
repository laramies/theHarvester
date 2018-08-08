
from .base import Converter
from ...helpers import iterate_files, get_ip

from collections import defaultdict, MutableMapping
from xlsxwriter import Workbook


class ExcelConverter(Converter):

    fields = [
        'port',
        'timestamp',
        'data',
        'hostnames',
        'org',
        'isp',
        'location.country_name',
        'location.country_code',
        'location.city',
        'os',
        'asn',
        'transport',
        'product',
        'version',
        
        'http.server',
        'http.title',
    ]

    field_names = {
        'org': 'Organization',
        'isp': 'ISP',
        'location.country_code': 'Country ISO Code',
        'location.country_name': 'Country',
        'location.city': 'City',
        'os': 'OS',
        'asn': 'ASN',

        'http.server': 'Web Server',
        'http.title': 'Website Title',
    }
    
    def process(self, files):
        # Get the filename from the already-open file handle
        filename = self.fout.name

        # Close the existing file as the XlsxWriter library handles that for us
        self.fout.close()

        # Create the new workbook
        workbook = Workbook(filename)

        # Define some common styles/ formats
        bold = workbook.add_format({
            'bold': 1,
        })
        
        # Create the main worksheet where all the raw data is shown
        main_sheet = workbook.add_worksheet('Raw Data')

        # Write the header
        main_sheet.write(0, 0, 'IP', bold) # The IP field can be either ip_str or ipv6 so we treat it differently
        main_sheet.set_column(0, 0, 20)
        
        row = 0
        col = 1
        for field in self.fields:
            name = self.field_names.get(field, field.capitalize())
            main_sheet.write(row, col, name, bold)
            col += 1
        row += 1

        total = 0
        ports = defaultdict(int)
        for banner in iterate_files(files):
            try:
                # Build the list that contains all the relevant values
                data = []
                for field in self.fields:
                    value = self.banner_field(banner, field)
                    data.append(value)
                
                # Write those values to the main workbook
                # Starting off w/ the special "IP" property
                main_sheet.write_string(row, 0, get_ip(banner))
                col = 1

                for value in data:
                    main_sheet.write(row, col, value)
                    col += 1
                row += 1
            except:
                pass
            
            # Aggregate summary information
            total += 1
            ports[banner['port']] += 1
        
        summary_sheet = workbook.add_worksheet('Summary')
        summary_sheet.write(0, 0, 'Total', bold)
        summary_sheet.write(0, 1, total)

        # Ports Distribution
        summary_sheet.write(0, 3, 'Ports Distribution', bold)
        row = 1
        col = 3
        for key, value in sorted(ports.items(), reverse=True, key=lambda kv: (kv[1], kv[0])):
            summary_sheet.write(row, col, key)
            summary_sheet.write(row, col + 1, value)
            row += 1
    
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