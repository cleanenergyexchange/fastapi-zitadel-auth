import asyncio
import json
import time
import jwt as pyjwt
from httpx import AsyncClient
from loguru import logger

from settings import get_settings

"""
This module demonstrates how to authenticate a service account with Zitadel.
"""

settings = get_settings()
with open(settings.SERVICE_USER_PRIVATE_KEY_FILE, "r") as file:
    json_data = json.load(file)

# Extracting necessary values from the JSON data
private_key = json_data["key"]
kid = json_data["keyId"]
user_id = json_data["userId"]

# Preparing the JWT header and payload for authentication
header = {"alg": "RS256", "kid": kid}
payload = {
    "iss": user_id,
    "sub": user_id,
    "aud": settings.ZITADEL_DOMAIN,
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,  # Token expires in 1 hour
}

# Generating JWT token with RS256 algorithm
jwt_token = pyjwt.encode(payload, private_key, algorithm="RS256", headers=header)
logger.debug(f"Locally signed token: {jwt_token}")


async def main():
    # Creating an asynchronous HTTP client context
    async with AsyncClient() as client:
        # Data payload for the OAuth2 token request
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "scope": " ".join(
                [
                    "openid",
                    "email",
                    "profile",
                    "urn:zitadel:iam:org:projects:roles",
                    f"urn:zitadel:iam:org:project:id:{settings.ZITADEL_PROJECT_ID}:aud",
                ]
            ),
            "assertion": jwt_token,
        }

        # Making a POST request to the OAuth2 token endpoint
        response = await client.post(
            url=f"{settings.ZITADEL_DOMAIN}/oauth/v2/token", data=data
        )

        # Handling the response
        if response.status_code == 200:
            access_token = response.json()["access_token"]
            logger.debug(f"Response: {response.json()}")
        else:
            logger.error(f"Error: {response.status_code} - {response.text}")
            return

        # Example API call using the acquired access token
        my_api_response = await client.get(
            "http://localhost:8001/api/private",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if my_api_response.status_code == 200:
            logger.info(my_api_response.json())
        else:
            logger.error(
                f"Error: {my_api_response.status_code} - {my_api_response.text}"
            )


if __name__ == "__main__":
    asyncio.run(main())
