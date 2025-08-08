"""
Test script to verify the testing utilities work correctly
"""

import asyncio
from fastapi_zitadel_auth.testing import (
    create_test_token,
    create_openid_keys,
    openid_configuration,
    MockZitadelAuth,
    ZITADEL_CLIENT_ID,
    ZITADEL_ISSUER,
    ZITADEL_PROJECT_ID,
)


async def test_utilities():
    """Test that all utilities work as expected"""
    
    # Test token creation
    token = create_test_token(subject="test-user", scopes="openid profile")
    print(f"Created token: {token[:50]}...")
    
    # Test OpenID config
    config = openid_configuration()
    print(f"OpenID config issuer: {config['issuer']}")
    
    # Test keys creation
    keys = create_openid_keys()
    print(f"Created {len(keys['keys'])} keys")
    
    # Test MockZitadelAuth
    mock_auth = MockZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"openid": "OpenID scope", "profile": "Profile scope"},
    )
    
    user_data = await mock_auth.get_current_user("dummy-token")
    print(f"Mock user data: {user_data}")
    
    print("All utilities work correctly!")


if __name__ == "__main__":
    asyncio.run(test_utilities())
