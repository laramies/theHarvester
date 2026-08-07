import os

from slowapi import Limiter
from slowapi.util import get_remote_address

API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '5/minute')
limiter = Limiter(key_func=get_remote_address)
