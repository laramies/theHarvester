<<<<<<< HEAD
=======

>>>>>>> 8d897fdd4ad9b760e373a545ad99ae16a5796e01
from fastapi import Header


def get_api_key(x_api_key: str | None = Header(None)) -> str:
    """
    Simple API key authentication dependency.
    For now, this is a placeholder that allows any request.
    In a production environment, you would validate the API key here.
    """
    # For now, return a default value or the provided key
    # In production, you would validate against a database or config
<<<<<<< HEAD
    return x_api_key or 'default'
=======
    return x_api_key or "default"
>>>>>>> 8d897fdd4ad9b760e373a545ad99ae16a5796e01
