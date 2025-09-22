"""
Testing utilities for fastapi-zitadel-auth

This subpackage provides utilities to help users test their applications
that use fastapi-zitadel-auth.
"""

from .fixtures import *
from .utils import *

__all__ = [
    # From fixtures
    "mock_zitadel_auth",
    "mock_openid_config",
    "mock_openid_keys",
    "mock_openid_empty_keys",
    "mock_openid_invalid_keys",
    "mock_openid_key_rotation",
    "reset_openid_cache",
    
    # From utils
    "create_test_token",
    "create_openid_keys",
    "openid_configuration",
    "openid_config_url",
    "keys_url",
    "MockZitadelAuth",
    "ZITADEL_CLIENT_ID",
    "ZITADEL_HOST", 
    "ZITADEL_PROJECT_ID",
    "ZITADEL_PRIMARY_DOMAIN",
    "valid_key",
    "evil_key",
]
