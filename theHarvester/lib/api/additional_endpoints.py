from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from theHarvester.discovery.additional_apis import AdditionalAPIs
from theHarvester.lib.api.auth import get_api_key

router = APIRouter()


class DomainRequest(BaseModel):
    domain: str
    api_keys: dict[str, str] | None = None


@router.post('/breaches')
async def get_breaches(request: DomainRequest, api_key: str = Depends(get_api_key)):
    """Get breach information for a domain using HaveIBeenPwned."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_haveibeenpwned()
        results = apis.results['breaches']
        return {'status': 'success', 'data': results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/leaks')
async def get_leaks(request: DomainRequest, api_key: str = Depends(get_api_key)):
    """Get leaked credentials for a domain using Leak-Lookup."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_leaklookup()
        results = apis.results['leaks']
        return {'status': 'success', 'data': results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/security-score')
async def get_security_score(request: DomainRequest, api_key: str = Depends(get_api_key)):
    """Get security scorecard for a domain."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_securityscorecard()
        results = apis.results['security_score']
        return {'status': 'success', 'data': results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/tech-stack')
async def get_tech_stack(request: DomainRequest, api_key: str = Depends(get_api_key)):
    """Get technology stack information for a domain using BuiltWith."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_builtwith()
        results = apis.results['tech_stack']
        return {'status': 'success', 'data': results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/all')
async def get_all_info(request: DomainRequest, api_key: str = Depends(get_api_key)):
    """Get all additional information for a domain."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        results = await apis.process()
        return {'status': 'success', 'data': results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
