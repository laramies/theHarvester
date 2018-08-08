class WebAPIError(Exception):
    def __init__(self, value):
        self.value = value
    
    def __str__(self):
        return self.value


class APIError(Exception):
    """This exception gets raised whenever a non-200 status code was returned by the Shodan API."""
    def __init__(self, value):
        self.value = value
    
    def __str__(self):
        return self.value


class APITimeout(APIError):
	pass

