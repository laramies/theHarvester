from typing import Optional
from fastapi import Header, HTTPException


def get_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """
    Simple API key authentication dependency.
    For now, this is a placeholder that allows any request.
    In a production environment, you would validate the API key here.
    """
    # For now, return a default value or the provided key
    # In production, you would validate against a database or config
    return x_api_key or "default"