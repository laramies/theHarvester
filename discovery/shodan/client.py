# -*- coding: utf-8 -*-
"""
shodan.client
~~~~~~~~~~~~~

This module implements the Shodan API.

:copyright: (c) 2014- by John Matherly
"""
import time

import requests
import json

from .exception import APIError
from .helpers import api_request, create_facet_string
from .stream import Stream


# Try to disable the SSL warnings in urllib3 since not everybody can install
# C extensions. If you're able to install C extensions you can try to run:
#
# pip install requests[security]
#
# Which will download libraries that offer more full-featured SSL classes
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Define a basestring type if necessary for Python3 compatibility
try:
    basestring
except NameError:
    basestring = str


class Shodan:
    """Wrapper around the Shodan REST and Streaming APIs

    :param key: The Shodan API key that can be obtained from your account page (https://account.shodan.io)
    :type key: str
    :ivar exploits: An instance of `shodan.Shodan.Exploits` that provides access to the Exploits REST API.
    :ivar stream: An instance of `shodan.Shodan.Stream` that provides access to the Streaming API.
    """
    
    class Data:

        def __init__(self, parent):
            self.parent = parent

        def list_datasets(self):
            """Returns a list of datasets that the user has permission to download.

            :returns: A list of objects where every object describes a dataset
            """
            return self.parent._request('/shodan/data', {})

        def list_files(self, dataset):
            """Returns a list of files that belong to the given dataset.

            :returns: A list of objects where each object contains a 'name', 'size', 'timestamp' and 'url'
            """
            return self.parent._request('/shodan/data/{}'.format(dataset), {})
    
    class Tools:

        def __init__(self, parent):
            self.parent = parent

        def myip(self):
            """Get your current IP address as seen from the Internet.

            :returns: str -- your IP address
            """
            return self.parent._request('/tools/myip', {})
    
    class Exploits:

        def __init__(self, parent):
            self.parent = parent
            
        def search(self, query, page=1, facets=None):
            """Search the entire Shodan Exploits archive using the same query syntax
            as the website.
            
            :param query: The exploit search query; same syntax as website.
            :type query: str
            :param facets: A list of strings or tuples to get summary information on.
            :type facets: str
            :param page: The page number to access.
            :type page: int
            :returns: dict -- a dictionary containing the results of the search.
            """
            query_args = {
                'query': query,
                'page': page,
            }
            if facets:
                query_args['facets'] = create_facet_string(facets)

            return self.parent._request('/api/search', query_args, service='exploits')
            
        def count(self, query, facets=None):
            """Search the entire Shodan Exploits archive but only return the total # of results,
            not the actual exploits.
            
            :param query: The exploit search query; same syntax as website.
            :type query: str
            :param facets: A list of strings or tuples to get summary information on.
            :type facets: str
            :returns: dict -- a dictionary containing the results of the search.
            
            """
            query_args = {
                'query': query,
            }
            if facets:
                query_args['facets'] = create_facet_string(facets)

            return self.parent._request('/api/count', query_args, service='exploits')
    
    class Labs:

        def __init__(self, parent):
            self.parent = parent

        def honeyscore(self, ip):
            """Calculate the probability of an IP being an ICS honeypot.
            
            :param ip: IP address of the device
            :type ip: str

            :returns: int -- honeyscore ranging from 0.0 to 1.0
            """
            return self.parent._request('/labs/honeyscore/{}'.format(ip), {})
    
    def __init__(self, key):
        """Initializes the API object.
        
        :param key: The Shodan API key.
        :type key: str
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.base_exploits_url = 'https://exploits.shodan.io'
        self.data = self.Data(self)
        self.exploits = self.Exploits(self)
        self.labs = self.Labs(self)
        self.tools = self.Tools(self)
        self.stream = Stream(key)
        self._session = requests.Session()
            
    def _request(self, function, params, service='shodan', method='get'):
        """General-purpose function to create web requests to SHODAN.
        
        Arguments:
            function  -- name of the function you want to execute
            params    -- dictionary of parameters for the function
        
        Returns
            A dictionary containing the function's results.
        
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
            if method.lower() == 'post':
                data = self._session.post(base_url + function, params)
            else:
                data = self._session.get(base_url + function, params=params)
        except:
            raise APIError('Unable to connect to Shodan')

        # Check that the API key wasn't rejected
        if data.status_code == 401:
            try:
                # Return the actual error message if the API returned valid JSON
                error = data.json()['error']
            except Exception as e:
                error = 'Invalid API key'
            
            raise APIError(error)
        
        # Parse the text into JSON
        try:
            data = data.json()
        except:
            raise APIError('Unable to parse JSON response')
        
        # Raise an exception if an error occurred
        if type(data) == dict and 'error' in data:
            raise APIError(data['error'])
        
        # Return the data
        return data
    
    def count(self, query, facets=None):
        """Returns the total number of search results for the query.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param facets: (optional) A list of properties to get summary information on
        :type facets: str
        
        :returns: A dictionary with 1 main property: total. If facets have been provided then another property called "facets" will be available at the top-level of the dictionary. Visit the website for more detailed information.
        """
        query_args = {
            'query': query,
        }
        if facets:
            query_args['facets'] = create_facet_string(facets)
        return self._request('/shodan/host/count', query_args)
    
    def host(self, ips, history=False, minify=False):
        """Get all available information on an IP.

        :param ip: IP of the computer
        :type ip: str
        :param history: (optional) True if you want to grab the historical (non-current) banners for the host, False otherwise.
        :type history: bool
        :param minify: (optional) True to only return the list of ports and the general host information, no banners, False otherwise.
        :type minify: bool
        """
        if isinstance(ips, basestring):
            ips = [ips]
        
        params = {}
        if history:
            params['history'] = history
        if minify:
            params['minify'] = minify
        return self._request('/shodan/host/%s' % ','.join(ips), params)
    
    def info(self):
        """Returns information about the current API key, such as a list of add-ons
        and other features that are enabled for the current user's API plan.
        """
        return self._request('/api-info', {})

    def ports(self):
        """Get a list of ports that Shodan crawls

        :returns: An array containing the ports that Shodan crawls for.
        """
        return self._request('/shodan/ports', {})

    def protocols(self):
        """Get a list of protocols that the Shodan on-demand scanning API supports.

        :returns: A dictionary containing the protocol name and description.
        """
        return self._request('/shodan/protocols', {})

    def scan(self, ips, force=False):
        """Scan a network using Shodan

        :param ips: A list of IPs or netblocks in CIDR notation or an object structured like:
                    {
                        "9.9.9.9": [
                            (443, "https"),
                            (8080, "http")
                        ],
                        "1.1.1.0/24": [
                            (503, "modbus")
                        ]
                    }
        :type ips: str or dict
        :param force: Whether or not to force Shodan to re-scan the provided IPs. Only available to enterprise users.
        :type force: bool

        :returns: A dictionary with a unique ID to check on the scan progress, the number of IPs that will be crawled and how many scan credits are left.
        """
        if isinstance(ips, basestring):
            ips = [ips]
        
        if isinstance(ips, dict):
            networks = json.dumps(ips)
        else:
            networks = ','.join(ips)

        params = {
            'ips': networks,
            'force': force,
        }

        return self._request('/shodan/scan', params, method='post')

    def scan_internet(self, port, protocol):
        """Scan a network using Shodan

        :param port: The port that should get scanned.
        :type port: int
        :param port: The name of the protocol as returned by the protocols() method.
        :type port: str

        :returns: A dictionary with a unique ID to check on the scan progress.
        """
        params = {
            'port': port,
            'protocol': protocol,
        }

        return self._request('/shodan/scan/internet', params, method='post')

    def scan_status(self, scan_id):
        """Get the status information about a previously submitted scan.

        :param id: The unique ID for the scan that was submitted
        :type id: str

        :returns: A dictionary with general information about the scan, including its status in getting processed.
        """
        return self._request('/shodan/scan/%s' % scan_id, {})
    
    def search(self, query, page=1, limit=None, offset=None, facets=None, minify=True):
        """Search the SHODAN database.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param page: (optional) Page number of the search results
        :type page: int
        :param limit: (optional) Number of results to return
        :type limit: int
        :param offset: (optional) Search offset to begin getting results from
        :type offset: int
        :param facets: (optional) A list of properties to get summary information on
        :type facets: str
        :param minify: (optional) Whether to minify the banner and only return the important data
        :type minify: bool
        
        :returns: A dictionary with 2 main items: matches and total. If facets have been provided then another property called "facets" will be available at the top-level of the dictionary. Visit the website for more detailed information.        
        """
        args = {
            'query': query,
            'minify': minify,
        }
        if limit:
            args['limit'] = limit
            if offset:
                args['offset'] = offset
        else:
            args['page'] = page

        if facets:
            args['facets'] = create_facet_string(facets)
        
        return self._request('/shodan/host/search', args)
    
    def search_cursor(self, query, minify=True, retries=5):
        """Search the SHODAN database.

        This method returns an iterator that can directly be in a loop. Use it when you want to loop over
        all of the results of a search query. But this method doesn't return a "matches" array or the "total"
        information. And it also can't be used with facets, it's only use is to iterate over results more
        easily.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param minify: (optional) Whether to minify the banner and only return the important data
        :type minify: bool
        :param retries: (optional) How often to retry the search in case it times out
        :type minify: int
        
        :returns: A search cursor that can be used as an iterator/ generator.
        """
        args = {
            'query': query,
            'minify': minify,
        }

        page = 1
        tries = 0
        while page == 1 or results['matches']:
            try:
                results = self.search(query, minify=minify, page=page)
                for banner in results['matches']:
                    try:
                        yield banner
                    except GeneratorExit:
                        return # exit out of the function
                page += 1
                tries = 0
            except:
                # We've retried several times but it keeps failing, so lets error out
                if tries >= retries:
                    break

                tries += 1
                time.sleep(1.0) # wait 1 second if the search errored out for some reason
    
    def search_tokens(self, query):
        """Returns information about the search query itself (filters used etc.)

        :param query: Search query; identical syntax to the website
        :type query: str
        
        :returns: A dictionary with 4 main properties: filters, errors, attributes and string.
        """
        query_args = {
            'query': query,
        }
        return self._request('/shodan/host/search/tokens', query_args)

    def services(self):
        """Get a list of services that Shodan crawls

        :returns: A dictionary containing the ports/ services that Shodan crawls for. The key is the port number and the value is the name of the service.
        """
        return self._request('/shodan/services', {})

    def queries(self, page=1, sort='timestamp', order='desc'):
        """List the search queries that have been shared by other users.

        :param page: Page number to iterate over results; each page contains 10 items
        :type page: int
        :param sort: Sort the list based on a property. Possible values are: votes, timestamp
        :type sort: str
        :param order: Whether to sort the list in ascending or descending order. Possible values are: asc, desc
        :type order: str

        :returns: A list of saved search queries (dictionaries).
        """
        args = {
            'page': page,
            'sort': sort,
            'order': order,
        }
        return self._request('/shodan/query', args)

    def queries_search(self, query, page=1):
        """Search the directory of saved search queries in Shodan.

        :param query: The search string to look for in the search query
        :type query: str
        :param page: Page number to iterate over results; each page contains 10 items
        :type page: int

        :returns: A list of saved search queries (dictionaries).
        """
        args = {
            'page': page,
            'query': query,
        }
        return self._request('/shodan/query/search', args)

    def queries_tags(self, size=10):
        """Search the directory of saved search queries in Shodan.

        :param query: The number of tags to return
        :type page: int

        :returns: A list of tags.
        """
        args = {
            'size': size,
        }
        return self._request('/shodan/query/tags', args)

    def create_alert(self, name, ip, expires=0):
        """Search the directory of saved search queries in Shodan.

        :param query: The number of tags to return
        :type page: int

        :returns: A list of tags.
        """
        data = {
            'name': name,
            'filters': {
                'ip': ip,
            },
            'expires': expires,
        }

        response = api_request(self.api_key, '/shodan/alert', data=data, params={}, method='post')

        return response

    def alerts(self, aid=None, include_expired=True):
        """List all of the active alerts that the user created."""
        if aid:
            func = '/shodan/alert/%s/info' % aid
        else:
            func = '/shodan/alert/info'

        response = api_request(self.api_key, func, params={
            'include_expired': include_expired,
            })

        return response

    def delete_alert(self, aid):
        """Delete the alert with the given ID."""
        func = '/shodan/alert/%s' % aid

        response = api_request(self.api_key, func, params={}, method='delete')

        return response

