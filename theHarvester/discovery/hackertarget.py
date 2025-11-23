# theHarvester/discovery/hackertarget.py
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# yaml is optional; fall back gracefully if not installed
try:
    import yaml
except Exception:
    yaml = None

from theHarvester.lib.core import AsyncFetcher, Core


def _append_apikey_to_url(url: str, apikey: str | None) -> str:
    """
    Safely append an `apikey` query parameter to a URL, preserving existing params.
    If apikey is falsy, returns the original URL unchanged.
    """
    if not apikey:
        return url
    scheme, netloc, path, query, fragment = urlsplit(url)
    q = dict(parse_qsl(query))
    q['apikey'] = apikey
    new_query = urlencode(q)
    return urlunsplit((scheme, netloc, path, new_query, fragment))


def _load_api_keys_fallback() -> dict:
    """
    Fallback loader for api-keys.yml if the project does not provide a loader.
    Looks in a few likely paths and returns a dict (or {}).
    """
    if yaml is None:
        return {}

    candidates = [
        os.path.join(os.getcwd(), 'api-keys.yml'),
        os.path.join(os.getcwd(), 'theHarvester', 'api-keys.yml'),
        os.path.join(os.getcwd(), 'theHarvester', 'etc', 'api-keys.yml'),
        os.path.expanduser('~/.theHarvester/api-keys.yml'),
    ]

    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, encoding='utf-8') as fh:
                    return yaml.safe_load(fh) or {}
            except (OSError, yaml.YAMLError):
                # treat read/parse errors as "no keys found" for this fallback
                return {}
    return {}


def _get_hackertarget_key() -> str | None:
    """
    Try to obtain Hackertarget API key from repo-provided loader (preferred),
    or fall back to reading api-keys.yml directly.

    Accepts multiple common formats:
      hackertarget: "KEY"
      hackertarget:
        key: "KEY"
        apikey: "KEY"
    Also supports top-level names like hackertarget_key or hackertarget_apikey.
    """
    # 1) Try to use a Core loader if it exists
    try:
        # Many modules expose config/loaders on Core; try common names:
        if hasattr(Core, 'load_api_keys'):
            keys = Core.load_api_keys()
        elif hasattr(Core, 'get_api_keys'):
            keys = Core.get_api_keys()
        else:
            keys = None

        if isinstance(keys, dict):
            if 'hackertarget' in keys:
                ht = keys['hackertarget']
                if isinstance(ht, dict):
                    return ht.get('key') or ht.get('apikey') or ht.get('api_key')
                return ht
            # other possible top-level keys
            return keys.get('hackertarget') or keys.get('hackertarget_key') or keys.get('hackertarget_apikey')
    except Exception:
        # ignore and fall through to fallback loader
        pass

    # 2) Fallback: attempt to read api-keys.yml manually
    keys = _load_api_keys_fallback()
    if not isinstance(keys, dict):
        return None
    if 'hackertarget' in keys:
        ht = keys['hackertarget']
        if isinstance(ht, dict):
            return ht.get('key') or ht.get('apikey') or ht.get('api_key')
        return ht
    return keys.get('hackertarget') or keys.get('hackertarget_key') or keys.get('hackertarget_apikey')


class SearchHackerTarget:
    """
    Class uses the HackerTarget API to gather subdomains and IPs.

    This version supports reading a Hackertarget API key (if present) and
    appending it to the hackertarget request URLs as `apikey=<key>`.
    """

    def __init__(self, word) -> None:
        self.word = word
        self.total_results = ''
        self.hostname = 'https://api.hackertarget.com'
        self.proxy = False
        self.results = None

    async def do_search(self) -> None:
        headers = {'User-agent': Core.get_user_agent()}

        # base URLs used by the original implementation
        base_urls = [
            f'{self.hostname}/hostsearch/?q={self.word}',
            f'{self.hostname}/reversedns/?q={self.word}',
        ]

        # if user supplied an API key in api-keys.yml (or repo loader), append it
        ht_key = _get_hackertarget_key()
        request_urls = [_append_apikey_to_url(u, ht_key) for u in base_urls]

        # fetch all using existing AsyncFetcher helper
        responses = await AsyncFetcher.fetch_all(request_urls, headers=headers, proxy=self.proxy)

        # the original code concatenated responses and replaced commas with colons
        for response in responses:
            # response is expected to be a string; keep the original behavior
            self.total_results += response.replace(',', ':')

    async def process(self, proxy: bool = False) -> None:
        self.proxy = proxy
        await self.do_search()

    async def get_hostnames(self) -> list:
        return [result for result in self.total_results.splitlines() if 'No PTR records found' not in result]
