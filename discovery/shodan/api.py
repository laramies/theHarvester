try:
    from json import dumps, loads
except:
    from simplejson import dumps, loads
from urllib2 import urlopen
from urllib import urlencode

__all__ = ['WebAPI']


class WebAPIError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class WebAPI:

    """Wrapper around the SHODAN webservices API"""

    class DatalossDb:

        def __init__(self, parent):
            self.parent = parent

        def search(self, **kwargs):
            """Search the Dataloss DB archive.

            Arguments:
            name          -- Name of the affected company/ organisation

            arrest        -- whether the incident resulted in an arrest
            breaches      -- the type of breach that occurred (Hack, MissingLaptop etc.)
            country       -- country where the incident took place
            ext           -- whether an external, third party was affected
            ext_names     -- the name of the third party company that was affected
            lawsuit       -- whether the incident resulted in a lawsuit
            records       -- the number of records that were lost/ stolen
            recovered     -- whether the affected items were recovered
            sub_types     -- the sub-categorization of the affected company/ organization
            source        -- whether the incident occurred from inside or outside the organization
            stocks        -- stock symbol of the affected company
            types         -- the basic type of organization (government, business, educational)
            uid           -- unique ID for the incident

            Returns:
            A dictionary with 2 main items: matches (list) and total (int).

            """
            return self.parent._request('datalossdb/search', dict(**kwargs))

    class Exploits:

        def __init__(self, parent):
            self.parent = parent

        def search(self, query, sources=[],
                   cve=None, osvdb=None, msb=None, bid=None):
            """Search the entire Shodan Exploits archive using the same query syntax
            as the website.

            Arguments:
            query    -- exploit search query; same syntax as website

            Optional arguments:
            sources  -- metasploit, cve, osvdb, exploitdb, or packetstorm
            cve      -- CVE identifier (ex. 2010-0432)
            osvdb    -- OSVDB identifier (ex. 11666)
            msb      -- Microsoft Security Bulletin ID (ex. MS05-030)
            bid      -- Bugtraq identifier (ex. 13951)

            """
            if sources:
                query += ' source:' + ','.join(sources)
            if cve:
                query += ' cve:%s' % (str(cve).strip())
            if osvdb:
                query += ' osvdb:%s' % (str(osvdb).strip())
            if msb:
                query += ' msb:%s' % (str(msb).strip())
            if bid:
                query += ' bid:%s' % (str(bid).strip())
            return self.parent._request('search_exploits', {'q': query})

    class ExploitDb:

        def __init__(self, parent):
            self.parent = parent

        def download(self, id):
            """Download the exploit code from the ExploitDB archive.

            Arguments:
            id    -- ID of the ExploitDB entry

            Returns:
            A dictionary with the following fields:
            filename        -- Name of the file
            content-type    -- Mimetype
            data            -- Contents of the file

            """
            return self.parent._request('exploitdb/download', {'id': id})

        def search(self, query, **kwargs):
            """Search the ExploitDB archive.

            Arguments:
            query     -- Search terms

            Optional arguments:
            author    -- Name of the exploit submitter
            platform  -- Target platform (e.g. windows, linux, hardware etc.)
            port      -- Service port number
            type      -- Any, dos, local, papers, remote, shellcode and webapps

            Returns:
            A dictionary with 2 main items: matches (list) and total (int).
            Each item in 'matches' is a dictionary with the following elements:

            id
            author
            date
            description
            platform
            port
            type

            """
            return (
                self.parent._request(
                    'exploitdb/search', dict(q=query, **kwargs))
            )

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
            return self.parent._request('msf/download', {'id': id})

        def search(self, query, **kwargs):
            """Search for a Metasploit module.
            """
            return self.parent._request('msf/search', dict(q=query, **kwargs))

    def __init__(self, key):
        """Initializes the API object.

        Arguments:
        key -- your API key

        """
        self.api_key = key
        self.base_url = 'http://www.shodanhq.com/api/'
        self.dataloss = self.DatalossDb(self)
        self.exploits = self.Exploits(self)
        self.exploitdb = self.ExploitDb(self)
        self.msf = self.Msf(self)

    def _request(self, function, params):
        """General-purpose function to create web requests to SHODAN.

        Arguments:
        function  -- name of the function you want to execute
        params      -- dictionary of parameters for the function

        Returns
        A JSON string containing the function's results.

        """
        # Add the API key parameter automatically
        params['key'] = self.api_key

        # Send the request
        data = urlopen(
            self.base_url +
            function +
            '?' +
            urlencode(
                params)).read(
        )

        # Parse the text into JSON
        data = loads(data)

        # Raise an exception if an error occurred
        if data.get('error', None):
            raise WebAPIError(data['error'])

        # Return the data
        return data

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

    def search(self, query):
        """Search the SHODAN database.

        Arguments:
        query    -- search query; identical syntax to the website

        Returns:
        A dictionary with 3 main items: matches, countries and total.
        Visit the website for more detailed information.

        """
        return self._request('search', {'q': query})
