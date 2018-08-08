import requests
import json

from .exception import APIError


class Threatnet:
    """Wrapper around the Threatnet REST and Streaming APIs

    :param key: The Shodan API key that can be obtained from your account page (https://account.shodan.io)
    :type key: str
    :ivar stream: An instance of `shodan.Threatnet.Stream` that provides access to the Streaming API.
    """
    
    class Stream:

        base_url = 'https://stream.shodan.io'

        def __init__(self, parent):
            self.parent = parent

        def _create_stream(self, name):
            try:
                req = requests.get(self.base_url + name, params={'key': self.parent.api_key}, stream=True)
            except:
                raise APIError('Unable to contact the Shodan Streaming API')

            if req.status_code != 200:
                try:
                    raise APIError(data.json()['error'])
                except:
                    pass
                raise APIError('Invalid API key or you do not have access to the Streaming API')
            return req

        def events(self):
            stream = self._create_stream('/threatnet/events')
            for line in stream.iter_lines():
                if line:
                    banner = json.loads(line)
                    yield banner

        def backscatter(self):
            stream = self._create_stream('/threatnet/backscatter')
            for line in stream.iter_lines():
                if line:
                    banner = json.loads(line)
                    yield banner

        def activity(self):
            stream = self._create_stream('/threatnet/ssh')
            for line in stream.iter_lines():
                if line:
                    banner = json.loads(line)
                    yield banner
    
    def __init__(self, key):
        """Initializes the API object.
        
        :param key: The Shodan API key.
        :type key: str
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.stream = self.Stream(self)

