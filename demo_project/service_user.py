"""
This module demonstrates how to authenticate a service account with Zitadel.
"""

import asyncio
import json
import time
import jwt as pyjwt
from httpx import AsyncClient


# CONFIG: Replace the following values with your own

# The service account private key file downloaded from Zitadel
SERVICE_USER_PRIVATE_KEY_FILE = "service_user.json"

# The Zitadel instance URL
ZITADEL_HOST = "https://myinstance.zitadel.cloud"

# The project ID for which the service account is created
ZITADEL_PROJECT_ID = "1234567"

# Loading the service account private key JSON file
with open(SERVICE_USER_PRIVATE_KEY_FILE, "r") as file:
    json_data = json.load(file)

# END CONFIG

# Extracting necessary values from the JSON data
private_key = json_data["key"]
kid = json_data["keyId"]
user_id = json_data["userId"]

# Preparing the JWT header and payload for authentication
header = {"alg": "RS256", "kid": kid}
payload = {
    "iss": user_id,
    "sub": user_id,
    "aud": ZITADEL_HOST,
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,  # Token expires in 1 hour
}

# Generating JWT token
jwt_token = pyjwt.encode(payload, private_key, algorithm="RS256", headers=header)


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
                    f"urn:zitadel:iam:org:project:id:{ZITADEL_PROJECT_ID}:aud",
                ]
            ),
            "assertion": jwt_token,
        }

        # Making a POST request to the OAuth2 token endpoint
        response = await client.post(url=f"{ZITADEL_HOST}/oauth/v2/token", data=data)

        # Handling the response
        response.raise_for_status()
        access_token = response.json()["access_token"]

        # Example API call using the acquired access token
        my_api_response = await client.get(
            "http://localhost:8001/api/private",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if my_api_response.status_code == 200:
            print(my_api_response.json())
        else:
            print(f"Error: {my_api_response.status_code} - {my_api_response.text}")


if __name__ == "__main__":
    asyncio.run(main())
