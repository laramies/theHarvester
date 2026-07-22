import logging
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from theHarvester.discovery.additional_apis import AdditionalAPIs
from theHarvester.lib.api.auth import get_api_key

router = APIRouter()
logger = logging.getLogger(__name__)


class DomainRequest(BaseModel):
    domain: str = Field(..., min_length=3)
    api_keys: dict[str, str] | None = None


def _raise_processing_error(endpoint: str, exc: Exception) -> NoReturn:
    logger.exception(f'Error processing additional API endpoint {endpoint}')
    raise HTTPException(status_code=500, detail='An error occurred while processing your request') from exc


@router.post('/breaches')
async def get_breaches(request: DomainRequest, _api_key: Annotated[str, Depends(get_api_key)]):
    """Get breach information for a domain using HaveIBeenPwned."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_haveibeenpwned()
        results = apis.results['breaches']
        return {'status': 'success', 'data': results}
    except Exception as e:
        _raise_processing_error('breaches', e)


@router.post('/leaks')
async def get_leaks(request: DomainRequest, _api_key: Annotated[str, Depends(get_api_key)]):
    """Get leaked credentials for a domain using Leak-Lookup."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_leaklookup()
        results = apis.results['leaks']
        return {'status': 'success', 'data': results}
    except Exception as e:
        _raise_processing_error('leaks', e)


@router.post('/security-score')
async def get_security_score(request: DomainRequest, _api_key: Annotated[str, Depends(get_api_key)]):
    """Get security scorecard for a domain."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_securityscorecard()
        results = apis.results['security_score']
        return {'status': 'success', 'data': results}
    except Exception as e:
        _raise_processing_error('security-score', e)


@router.post('/tech-stack')
async def get_tech_stack(request: DomainRequest, _api_key: Annotated[str, Depends(get_api_key)]):
    """Get technology stack information for a domain using BuiltWith."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        await apis._process_builtwith()
        results = apis.results['tech_stack']
        return {'status': 'success', 'data': results}
    except Exception as e:
        _raise_processing_error('tech-stack', e)


@router.post('/all')
async def get_all_info(request: DomainRequest, _api_key: Annotated[str, Depends(get_api_key)]):
    """Get all additional information for a domain."""
    try:
        apis = AdditionalAPIs(request.domain, request.api_keys or {})
        results = await apis.process()
        return {'status': 'success', 'data': results}
    except Exception as e:
        _raise_processing_error('all', e)
