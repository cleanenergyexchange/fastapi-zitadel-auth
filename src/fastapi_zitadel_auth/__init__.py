"""
FastAPI Zitadel Auth
"""

from importlib.metadata import version

from fastapi_zitadel_auth.auth import ZitadelAuth

__version__ = version("fastapi-zitadel-auth")

__all__ = ["ZitadelAuth", "__version__"]
