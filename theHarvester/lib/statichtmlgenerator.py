class HtmlGenerator:

    def __init__(self, word):
        self.domain = word

    async def generatepreviousscanresults(self, previousscanresults):
        try:
            if previousscanresults[0] == 'No results':
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
'''
                for i in previousscanresults:
                    html += '<tr>'
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

'''
            return html
        except Exception as e:
            print(f'Error generating the previous scan results HTML code: {e}')

    async def generatelatestscanresults(self, latestscanresults):
        try:
            html = '''
<h2><span style="color: #000000;"><strong>Latest scan report </strong></span></h2>
<p>&nbsp;</p>

'''
            html += '<div id="example-table"></div>'
            html += '<script type="text/javascript" src="https://unpkg.com/tabulator-tables@4.6.2/dist/js/tabulator.min.js"></script>'
            html += '<script type="text/javascript">'
            html += 'var tabledata = ['
            for i in latestscanresults:
                html += '{date:"' + str(i[0]) + '", domain:"' + str(i[1]) + '", plugin:"' + str(
                    i[2]) + '", record:"' + str(i[3]) + '",result:"' + str(i[4]) + '"},'
            html += '];'
            html += '''

var minMaxFilterEditor = function(cell, onRendered, success, cancel, editorParams){

    var end;

    var container = document.createElement("span");

    //create and style inputs
    var start = document.createElement("input");
    start.setAttribute("type", "number");
    start.setAttribute("placeholder", "Min");
    start.setAttribute("min", 0);
    start.setAttribute("max", 100);
    start.style.padding = "4px";
    start.style.width = "50%";
    start.style.boxSizing = "border-box";

    start.value = cell.getValue();

    function buildValues(){
        success({
            start:start.value,
            end:end.value,
        });
    }

    function keypress(e){
        if(e.keyCode == 13){
            buildValues();
        }

        if(e.keyCode == 27){
            cancel();
        }
    }

    end = start.cloneNode();
    end.setAttribute("placeholder", "Max");

    start.addEventListener("change", buildValues);
    start.addEventListener("blur", buildValues);
    start.addEventListener("keydown", keypress);

    end.addEventListener("change", buildValues);
    end.addEventListener("blur", buildValues);
    end.addEventListener("keydown", keypress);


    container.appendChild(start);
    container.appendChild(end);

    return container;
 }

//custom max min filter function
function minMaxFilterFunction(headerValue, rowValue, rowData, filterParams){
    //headerValue - the value of the header filter element
    //rowValue - the value of the column in this row
    //rowData - the data for the row being filtered
    //filterParams - params object passed to the headerFilterFuncParams property

        if(rowValue){
            if(headerValue.start != ""){
                if(headerValue.end != ""){
                    return rowValue >= headerValue.start && rowValue <= headerValue.end;
                }else{
                    return rowValue >= headerValue.start;
                }
            }else{
                if(headerValue.end != ""){
                    return rowValue <= headerValue.end;
                }
            }
        }

    return true; //must return a boolean, true if it passes the filter.
}


//create Tabulator on DOM element with id "example-table"
var table = new Tabulator("#example-table", {
    height:700, // set height of table (in CSS or here), this enables the Virtual DOM and improves render speed dramatically (can be any valid css height value)
    data:tabledata, //assign data to table
    layout:"fitColumns", //fit columns to width of table (optional)
    columns:[ //Define Table Columns
        {title:"Date", field:"date", width:150},
        {title:"Domain", field:"domain", hozAlign:"left", headerFilter:"select" },
        {title:"Plugin", field:"plugin", headerFilter:"select"},
        {title:"Record", field:"record", headerFilter:"select", hozAlign:"center"},
        {title:"Result", field:"result", headerFilter:"select", hozAlign:"center"},
    ]
    },
);
</script>
<p>&nbsp;</p>
<p>&nbsp;</p>

'''
            return html
        except Exception as e:
            print(f'Error generating the latest scan results HTML code: {e}')

    async def beginhtml(self):
        html = '''
<!doctype html>
<html>
<head><script src="https://cdn.plot.ly/plotly-latest.min.js" type="text/javascript"></script>
<link href="https://unpkg.com/tabulator-tables@4.6.2/dist/css/tabulator.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
</head>
<title>theHarvester Scan Report</title>
<body>
<h1 style="text-align: center;"><span>theHarvester Scan Report</span></h1>
        '''
        return html

    async def generatedashboardcode(self, scanboarddata):
        try:
            totalnumberofdomains = scanboarddata['domains']
            totalnumberofhosts = scanboarddata['host']
            totalnumberofip = scanboarddata['ip']
            totalnumberofvhost = scanboarddata['vhost']
            totalnumberofemail = scanboarddata['email']
            totalnumberofshodan = scanboarddata['shodan']
            html = '''
<h2 style="text-align: center;"><span>Overall statistics</span></h2>
<table style="height: 108px; border-color: #000000; margin-left: auto; margin-right: auto;" border=" #000000" width="713">
<tbody>
<tr>
<td style="width: 113px; text-align: center;background: #065A82;color:#ffffff"><strong>Domains</strong></td>
<td style="width: 108px; text-align: center;background: #065A82;color:#ffffff"><strong>Hosts</strong></td>
<td style="width: 119px; text-align: center;background: #065A82;color:#ffffff"><strong>IP Addresses</strong></td>
<td style="width: 111px; text-align: center;background: #065A82;color:#ffffff"><strong>Vhosts</strong></td>
<td style="width: 110px; text-align: center;background: #065A82;color:#ffffff"><strong>Emails</strong></td>
<td style="width: 110px; text-align: center;background: #065A82;color:#ffffff"><strong>Shodan</strong></td>
</tr>
<tr>
<td style="width: 113px; text-align: center;background: #ffffff"><strong>''' + str(totalnumberofdomains) + '''</strong></td>
<td style="width: 108px; text-align: center;background: #ffffff"><strong>''' + str(totalnumberofhosts) + '''</strong></td>
<td style="width: 119px; text-align: center;background: #ffffff"><strong>''' + str(totalnumberofip) + '''</strong></td>
<td style="width: 111px; text-align: center;background: #ffffff"><strong>''' + str(totalnumberofvhost) + '''</strong></td>
<td style="width: 110px; text-align: center;background: #ffffff"><strong>''' + str(totalnumberofemail) + '''</strong></td>
<td style="width: 110px; text-align: center;background: #ffffff"><strong>''' + str(totalnumberofshodan) + '''</strong></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<p>&nbsp;</p>
'''
            return html
        except Exception as e:
            print(f'Error generating dashboard HTML code: {e}')

    async def generatepluginscanstatistics(self, scanstatistics):
        try:
            html = '''
<h2 style="text-align: center;"><span>theHarvester plugin statistics</span></h2>
<p>&nbsp;</p>
<table style="height: 63px; border-color: #000000; margin-left: auto; margin-right: auto;" border="#000000" width="811">
<tbody>
<tr>
<td style="width: 156.042px; text-align: center;background: #065A82;color:#ffffff"><strong>Domain</strong></td>
<td style="width: 156.042px; text-align: center;background: #065A82;color:#ffffff"><strong>Date</strong></td>
<td style="width: 157.153px; text-align: center;background: #065A82;color:#ffffff"><strong>Recordtype</strong></td>
<td style="width: 157.153px; text-align: center;background: #065A82;color:#ffffff"><strong>Source</strong></td>
<td style="width: 157.153px; text-align: center;background: #065A82;color:#ffffff"><strong>Total results</strong></td>
</tr>
'''
            for i in scanstatistics:
                html += '<tr>'
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
            print(f'Error generating scan statistics HTML code: {e}')
