"""
API endpoint scanner module.
This module contains the SearchApiEndpoints class that scans for common API endpoints
on target domains.
"""

import asyncio
import os
from typing import List, Set, Dict
from theHarvester.lib.core import AsyncFetcher, Core
from theHarvester.discovery.constants import MissingKey

class SearchApiEndpoints:
    """
    SearchApiEndpoints class for scanning common API endpoints on target domains.
    """

    def __init__(self, word: str, wordlist: str = None) -> None:
        """
        Initialize the SearchApiEndpoints class.

        Args:
            word: The target domain to scan.
            wordlist: Optional path to a custom wordlist file. If not provided, uses default api_endpoints.txt
        """
        self.word = word
        self.hosts: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.found_endpoints: Set[str] = set()
        self.interesting_endpoints: Set[str] = set()
        self.auth_required: Set[str] = set()
        self.api_versions: Set[str] = set()
        self.rate_limits: Dict[str, Dict] = {}
        self.methods: Set[str] = set()
        self.status_codes: Set[int] = set()
        self.response_sizes: Dict[str, int] = {}
        self.proxy = False
        
        # Set default wordlist path
        default_wordlist = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'wordlists', 'api_endpoints.txt')
        self.wordlist = wordlist if wordlist else default_wordlist

    async def do_search(self) -> None:
        """
        Perform the API endpoint scan.
        """
        try:
            # Load endpoints from wordlist
            endpoints = self._load_wordlist()
            if not endpoints:
                raise Exception(f"No endpoints found in wordlist: {self.wordlist}")
            
            # Create tasks for each endpoint
            tasks = []
            for endpoint in endpoints:
                url = f"https://{self.word}{endpoint}"
                tasks.append(self._check_endpoint(url))
            
            # Wait for all tasks to complete
            await asyncio.gather(*tasks)
            
        except Exception as e:
            print(f"Error in API endpoint scan: {str(e)}")

    def _load_wordlist(self) -> List[str]:
        """Load endpoints from wordlist file."""
        try:
            with open(self.wordlist, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except Exception as e:
            print(f"Error loading wordlist {self.wordlist}: {e}")
            return []

    async def _check_endpoint(self, url: str) -> None:
        """
        Check if an endpoint exists and is accessible.

        Args:
            url: The URL to check.
        """
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        headers = {
            'User-Agent': Core.get_user_agent(),
            'Accept': '*/*'
        }
        
        for method in methods:
            try:
                # Use AsyncFetcher to make the request
                response = await AsyncFetcher.fetch(
                    url=url,
                    method=method,
                    headers=headers,
                    proxy=self.proxy
                )
                
                # If we get a response, process it
                if response:
                    self._process_response(url, method, response)
                    
            except Exception:
                continue

    def _process_response(self, url: str, method: str, response) -> None:
        """Process and categorize API endpoint response."""
        status = getattr(response, 'status', 0)
        if status > 0:
            self.endpoints.add(url)
            self.found_endpoints.add(url)
            self.methods.add(method)
            self.status_codes.add(status)
            
            # Track response size
            content_length = len(getattr(response, 'content', b''))
            self.response_sizes[url] = content_length
            
            # Check for interesting endpoints
            if status in [200, 201, 202]:
                self.interesting_endpoints.add(url)
            
            # Check for authentication requirements
            if status in [401, 403]:
                self.auth_required.add(url)
            
            # Detect API versions
            if '/v' in url:
                version = url.split('/v')[1].split('/')[0]
                if version.isdigit():
                    self.api_versions.add(f"v{version}")
            
            # Check for rate limiting
            if status == 429:
                self.rate_limits[url] = {
                    'method': method,
                    'headers': dict(getattr(response, 'headers', {}))
                }

    def get_hostnames(self) -> Set[str]:
        """
        Get the set of hostnames found.

        Returns:
            Set[str]: The set of hostnames.
        """
        return self.hosts

    def get_endpoints(self) -> Set[str]:
        """
        Get the set of all endpoints checked.

        Returns:
            Set[str]: The set of endpoints.
        """
        return self.endpoints

    def get_found_endpoints(self) -> Set[str]:
        """
        Get the set of found and accessible endpoints.

        Returns:
            Set[str]: The set of found endpoints.
        """
        return self.found_endpoints

    def get_interesting_endpoints(self) -> Set[str]:
        """
        Get the set of interesting endpoints (returning 200, 201, or 202).

        Returns:
            Set[str]: The set of interesting endpoints.
        """
        return self.interesting_endpoints

    def get_auth_required(self) -> Set[str]:
        """
        Get the set of endpoints requiring authentication.

        Returns:
            Set[str]: The set of endpoints requiring auth.
        """
        return self.auth_required

    def get_api_versions(self) -> Set[str]:
        """
        Get the set of detected API versions.

        Returns:
            Set[str]: The set of API versions.
        """
        return self.api_versions

    def get_rate_limits(self) -> Dict[str, Dict]:
        """
        Get the rate limit information for endpoints.

        Returns:
            Dict[str, Dict]: Dictionary of rate limit information.
        """
        return self.rate_limits

    def get_methods(self) -> Set[str]:
        """
        Get the set of HTTP methods used.

        Returns:
            Set[str]: The set of HTTP methods.
        """
        return self.methods

    def get_status_codes(self) -> Set[int]:
        """
        Get the set of HTTP status codes encountered.

        Returns:
            Set[int]: The set of status codes.
        """
        return self.status_codes

    def get_response_sizes(self) -> Dict[str, int]:
        """
        Get the response sizes for each endpoint.

        Returns:
            Dict[str, int]: Dictionary mapping endpoints to their response sizes.
        """
        return self.response_sizes 