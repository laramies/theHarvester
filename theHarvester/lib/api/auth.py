import hmac
import os
import secrets
from pathlib import Path
from typing import Annotated

from fastapi import Cookie, Header, HTTPException, Request, status

API_KEY_ENV_VAR = 'THEHARVESTER_API_KEY'
API_KEY_FILE_ENV_VAR = f'{API_KEY_ENV_VAR}_FILE'
API_KEY_COOKIE_NAME = 'theharvester-api-key'
BROWSER_SESSION_CONTEXT = b'theharvester-browser-session'


def _configured_api_key() -> str | None:
    configured_api_key = os.getenv(API_KEY_ENV_VAR)
    if configured_api_key:
        return configured_api_key
    configured_api_key_file = os.getenv(API_KEY_FILE_ENV_VAR)
    if not configured_api_key_file:
        return None
    try:
        return Path(configured_api_key_file).read_text(encoding='utf-8').strip() or None
    except OSError:
        return None


def browser_session_token(configured_api_key: str) -> str:
    return hmac.digest(configured_api_key.encode(), BROWSER_SESSION_CONTEXT, 'sha256').hex()


def get_api_key(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias='X-API-Key')] = None,
    api_key_cookie: Annotated[str | None, Cookie(alias=API_KEY_COOKIE_NAME)] = None,
) -> str:
    """Validate the API key used by protected API routes."""
    configured_api_key = _configured_api_key()
    if not configured_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f'{API_KEY_ENV_VAR} is not configured',
        )

    valid_header = x_api_key is not None and secrets.compare_digest(x_api_key, configured_api_key)
    expected_cookie = browser_session_token(configured_api_key)
    valid_cookie = api_key_cookie is not None and secrets.compare_digest(api_key_cookie, expected_cookie)
    if not valid_header and not valid_cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid API key',
        )
    if valid_cookie and not valid_header and request.method not in {'GET', 'HEAD', 'OPTIONS'}:
        expected_origin = str(request.base_url).rstrip('/')
        if not secrets.compare_digest(request.headers.get('origin', ''), expected_origin):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='Invalid request origin',
            )

    return configured_api_key
