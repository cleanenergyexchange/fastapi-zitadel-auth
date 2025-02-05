"""
FastAPI Zitadel Auth
"""

from fastapi_zitadel_auth.auth import ZitadelAuth
from fastapi_zitadel_auth.user import ZitadelUser

__all__ = ["ZitadelAuth", "ZitadelUser"]

__version__ = "0.1.1"  # remember to update also in pyproject.toml
