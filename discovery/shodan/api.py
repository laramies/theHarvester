try:
    # Python 2
    from urllib2    import urlopen
    from urllib     import urlencode
except:
    # Python 3
    from urllib.request     import urlopen
    from urllib.parse       import urlencode

from json import dumps, loads

from .exception import WebAPIError


__all__ = ['WebAPI']


class WebAPI:
    """Wrapper around the SHODAN webservices API"""
    
    class Exploits:
        
        def __init__(self, parent):
            self.parent = parent
            
        def search(self, query, sources=[], cve=None, osvdb=None, msb=None, bid=None):
            """Search the entire Shodan Exploits archive using the same query syntax
            as the website.
            
            Arguments:
            query    -- exploit search query; same syntax as website
            
            Optional arguments:
            sources  -- metasploit, cve, osvdb, exploitdb
            cve      -- CVE identifier (ex. 2010-0432)
            osvdb    -- OSVDB identifier (ex. 11666)
            msb      -- Microsoft Security Bulletin ID (ex. MS05-030)
            bid      -- Bugtraq identifier (ex. 13951)
            
            """
            if sources:
                query += ' source:%s' % (','.join(sources))
            if cve:
                query += ' cve:%s' % (str(cve).strip())
            if osvdb:
                query += ' osvdb:%s' % (str(osvdb).strip())
            if msb:
                query += ' msb:%s' % (str(msb).strip())
            if bid:
                query += ' bid:%s' % (str(bid).strip())
            return self.parent._request('api', {'q': query}, service='exploits')
    
    class ExploitDb:
        
        def __init__(self, parent):
            self.parent = parent
        
        def download(self, id):
            """DEPRECATED
            Download the exploit code from the ExploitDB archive.
    
            Arguments:
            id    -- ID of the ExploitDB entry
            """
            query = '_id:%s' % id
            return self.parent.search(query, sources=['exploitdb'])
        
        def search(self, query, **kwargs):
            """Search the ExploitDB archive.
    
            Arguments:
            query     -- Search terms
    
            Returns:
            A dictionary with 2 main items: matches (list) and total (int).
            """
            return self.parent.search(query, sources=['exploitdb'])

    
    class Msf:
        
        def __init__(self, parent):
            self.parent = parent
            
        def download(self, id):
            """Download a metasploit module given the fullname (id) of it.
            
            Arguments:
            id        -- fullname of the module (ex. auxiliary/admin/backupexec/dump)
            
            Returns:
            A dictionary with the following fields:
            filename        -- Name of the file
            content-type    -- Mimetype
            data            -- File content
            """
            query = '_id:%s' % id
            return self.parent.search(query, sources=['metasploit'])
        
        def search(self, query, **kwargs):
            """Search for a Metasploit module.
            """
            return self.parent.search(query, sources=['metasploit'])
    
    def __init__(self, key):
        """Initializes the API object.
        
        Arguments:
        key -- your API key
        
        """
        print('WARNING: This class is deprecated, please upgrade to use "shodan.Shodan()" instead of shodan.WebAPI()')
        self.api_key = key
        self.base_url = 'http://www.shodanhq.com/api/'
        self.base_exploits_url = 'https://exploits.shodan.io/'
        self.exploits = self.Exploits(self)
        self.exploitdb = self.ExploitDb(self.exploits)
        self.msf = self.Msf(self.exploits)
    
    def _request(self, function, params, service='shodan'):
        """General-purpose function to create web requests to SHODAN.
        
        Arguments:
        function  -- name of the function you want to execute
        params      -- dictionary of parameters for the function
        
        Returns
        A JSON string containing the function's results.
        
        """
        # Add the API key parameter automatically
        params['key'] = self.api_key
        
        # Determine the base_url based on which service we're interacting with
        base_url = {
            'shodan': self.base_url,
            'exploits': self.base_exploits_url,
        }.get(service, 'shodan')

        # Send the request
        try:
            data = urlopen(base_url + function + '?' + urlencode(params)).read().decode('utf-8')
        except:
            raise WebAPIError('Unable to connect to Shodan')
        
        # Parse the text from JSON to a dict
        data = loads(data)
        
        # Raise an exception if an error occurred
        if data.get('error', None):
            raise WebAPIError(data['error'])
        
        # Return the data
        return data
    
    def count(self, query):
        """Returns the total number of search results for the query.
        """
        return self._request('count', {'q': query})
    
    def locations(self, query):
        """Return a break-down of all the countries and cities that the results for
        the given search are located in.
        """
        return self._request('locations', {'q': query})
    
    def fingerprint(self, banner):
        """Determine the software based on the banner.
        
        Arguments:
        banner  - HTTP banner
        
        Returns:
        A list of software that matched the given banner.
        """
        return self._request('fingerprint', {'banner': banner})
    
    def host(self, ip):
        """Get all available information on an IP.

        Arguments:
        ip    -- IP of the computer

        Returns:
        All available information SHODAN has on the given IP,
        subject to API key restrictions.

        """
        return self._request('host', {'ip': ip})
    
    def info(self):
        """Returns information about the current API key, such as a list of add-ons
        and other features that are enabled for the current user's API plan.
        """
        return self._request('info', {})
    
    def search(self, query, page=1, limit=None, offset=None):
        """Search the SHODAN database.
        
        Arguments:
        query    -- search query; identical syntax to the website
        
        Optional arguments:
        page     -- page number of the search results 
        limit    -- number of results to return
        offset   -- search offset to begin getting results from
        
        Returns:
        A dictionary with 3 main items: matches, countries and total.
        Visit the website for more detailed information.
        
        """
        args = {
            'q': query,
            'p': page,
        }
        if limit:
            args['l'] = limit
        if offset:
            args['o'] = offset
        
        return self._request('search', args)
