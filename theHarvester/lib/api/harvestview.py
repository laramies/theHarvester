from __future__ import annotations

import ipaddress
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse

from theHarvester import __version__
from theHarvester.lib.api.auth import API_KEY_COOKIE_NAME, _configured_api_key, browser_session_token
from theHarvester.lib.enumeration import DEFAULT_SOURCE_WORKERS
from theHarvester.lib.resolver_selection import DEFAULT_DNS_RESOLVERS

router = APIRouter()


def _docker_gateway() -> ipaddress.IPv4Address | None:
    try:
        for line in Path('/proc/net/route').read_text(encoding='ascii').splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3 and fields[1] == '00000000':
                return ipaddress.IPv4Address(bytes.fromhex(fields[2])[::-1])
    except (OSError, ValueError):
        pass
    return None


@router.get('/', include_in_schema=False)
async def harvestview_app(request: Request) -> HTMLResponse:
    try:
        client_address = ipaddress.ip_address(request.client.host) if request.client is not None else None
        trusted_gateway = (
            _docker_gateway() if os.getenv('THEHARVESTER_HARVESTVIEW_LOCAL_PROXY', '').casefold() == 'enabled' else None
        )
        is_local_client = client_address is not None and (client_address.is_loopback or client_address == trusted_gateway)
    except ValueError:
        is_local_client = False
    try:
        hostname = request.url.hostname
        is_loopback_host = hostname == 'localhost' or (hostname is not None and ipaddress.ip_address(hostname).is_loopback)
    except ValueError:
        is_loopback_host = False
    if not is_local_client or not is_loopback_host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='theHarvester is available only on localhost')

    static_dir = Path(__file__).parent / 'static' / 'harvestview'
    template = (static_dir / 'index.html').read_text(encoding='utf-8')
    asset_version = max((static_dir / name).stat().st_mtime_ns for name in ('app.css', 'app.js'))
    response = HTMLResponse(
        template.replace('{{VERSION}}', __version__)
        .replace('{{ASSET_VERSION}}', str(asset_version))
        .replace('{{DNS_RESOLVERS}}', ','.join(DEFAULT_DNS_RESOLVERS))
        .replace('{{SOURCE_WORKERS}}', str(DEFAULT_SOURCE_WORKERS))
    )
    if configured_api_key := _configured_api_key():
        response.set_cookie(
            API_KEY_COOKIE_NAME,
            browser_session_token(configured_api_key),
            httponly=True,
            samesite='strict',
            path='/api/v1',
        )
    return response
