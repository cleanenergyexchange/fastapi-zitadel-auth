import json
import time
import os
from pathlib import Path
import jwt as pyjwt
from locust import HttpUser, task, events, between
from locust.runners import MasterRunner
import logging


ZITADEL_HOST = os.getenv("ZITADEL_HOST", "https://zitadel-instance.example.com")
ZITADEL_PROJECT_ID = os.getenv("ZITADEL_PROJECT_ID", "project-id")
ZITADEL_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "client-id")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
SERVICE_USER_PRIVATE_KEY_FILE = os.getenv("SERVICE_USER_KEY_FILE", "service_user.json")
ROLE = os.getenv("ZITADEL_ROLE", "admin")
API_HOST = os.getenv("API_HOST", "http://localhost:8001")

# Set up logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)

# Log all environment variables being used
logger.info(f"ZITADEL_HOST: {ZITADEL_HOST}")
logger.info(f"ZITADEL_PROJECT_ID: {ZITADEL_PROJECT_ID}")
logger.info(f"OAUTH_CLIENT_ID: {ZITADEL_CLIENT_ID}")
logger.info(f"LOG_LEVEL: {LOG_LEVEL}")
logger.info(f"SERVICE_USER_KEY_FILE: {SERVICE_USER_PRIVATE_KEY_FILE}")
logger.info(f"ZITADEL_ROLE: {ROLE}")
logger.info(f"API_HOST: {API_HOST}")


# Set up temp file to store token
TOKEN_PATH = Path("/mnt/locust/token.txt")


def load_token() -> str:
    """Load token from file if it exists"""
    try:
        return TOKEN_PATH.read_text().strip()
    except FileNotFoundError:
        return ""


def write_token(token: str) -> None:
    """Write token to file"""
    TOKEN_PATH.write_text(token)


def delete_token() -> None:
    """Delete token file if it exists"""
    try:
        TOKEN_PATH.unlink(missing_ok=True)
    except (PermissionError, FileNotFoundError):
        pass


def get_token_from_zitadel() -> str:
    """Generate a new token without counting as a Locust request"""
    try:
        key_file_path = Path(SERVICE_USER_PRIVATE_KEY_FILE)
        if not key_file_path.exists():
            raise FileNotFoundError(f"Service user key file not found: {SERVICE_USER_PRIVATE_KEY_FILE}")
        with open(key_file_path, "r") as file:
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
            "aud": str(ZITADEL_HOST).rstrip("/"),  # Remove trailing slash
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # Token expires in 1 hour
        }

        # Generating JWT token
        jwt_token = pyjwt.encode(payload, private_key, algorithm="RS256", headers=header)

        # Data payload for the OAuth2 token request
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "scope": " ".join(
                [
                    "openid",
                    f"urn:zitadel:iam:org:project:role:{ROLE}",
                    f"urn:zitadel:iam:org:project:id:{ZITADEL_PROJECT_ID}:aud",
                ]
            ),
            "assertion": jwt_token,
        }

        # Use requests directly instead of self.client to avoid counting this as a Locust request
        import requests

        oauth_url = f"{ZITADEL_HOST}/oauth/v2/token"
        response = requests.post(url=oauth_url, data=data)
        response.raise_for_status()

        return response.json()["access_token"]

    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return ""


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """
    Initialize token at test start (only for master)
    """
    if isinstance(environment.runner, MasterRunner):
        try:
            # First check if we already have a token
            token = load_token()
            if not token:
                logger.info("Getting new token from Zitadel")
                token = get_token_from_zitadel()
                if token:
                    write_token(token)
                    logger.info("Token acquired and saved successfully")
                else:
                    logger.error("Failed to get token from Zitadel")
                    environment.runner.quit()
        except Exception as e:
            logger.error(f"Failed during test startup: {e}")
            environment.runner.quit()


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """
    Clean up token on test end
    """
    if isinstance(environment.runner, MasterRunner):
        delete_token()
        logger.info("Token file deleted")


class ZitadelServiceUser(HttpUser):
    wait_time = between(1, 3)  # Wait between 1 and 3 seconds between tasks
    abstract = True  # This is a base class, don't create users of this type

    def on_start(self):
        """
        Get the access token for all requests
        """
        self.token = load_token()
        if not self.token:
            logger.error("No token available for user")

        self.token_timestamp = time.time()

    def refresh_token_if_needed(self):
        """
        Check if the token needs to be refreshed and refresh it if necessary.
        """
        # Refresh token if older than 55 minutes (tokens last 1 hour)
        if time.time() - self.token_timestamp > 55 * 60:
            logger.info("Token is about to expire, refreshing")
            # For simplicity, we'll just read the token again (assuming master has refreshed it)
            new_token = load_token()
            if new_token and new_token != self.token:
                self.token = new_token
                self.token_timestamp = time.time()


class DemoApiUser(ZitadelServiceUser):
    @task(1)
    def access_public_endpoint(self):
        """
        Test accessing a public endpoint (no authentication required).
        """
        with self.client.get(f"{API_HOST}/api/public", name="Public: Get public data", catch_response=True) as response:
            if response.status_code != 200:
                response.failure(f"Public endpoint failed: {response.status_code} - {response.text}")

    @task(2)
    def access_protected_admin_endpoint(self):
        """
        Test accessing a protected endpoint requiring admin role.
        """
        self.refresh_token_if_needed()

        if not self.token:
            logger.warning("Skipping protected endpoint test - no token available")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        with self.client.get(
            f"{API_HOST}/api/protected/admin", headers=headers, name="Protected: Admin endpoint", catch_response=True
        ) as response:
            if response.status_code != 200:
                response.failure(f"Admin endpoint failed: {response.status_code} - {response.text}")


@events.quitting.add_listener
def _(environment, **kw):
    """Set the exit code to non-zero if any of the following conditions are met:
    - More than 1% of the requests failed
    - The average response time is longer than 200 ms
    - The 95th percentile for response time is larger than 600 ms
    """
    if environment.stats.total.fail_ratio > 0.01:
        logger.error("Test failed due to failure ratio > 1%")
        environment.process_exit_code = 1
    elif environment.stats.total.avg_response_time > 200:
        logger.error("Test failed due to average response time > 200 ms")
        environment.process_exit_code = 1
    elif environment.stats.total.get_response_time_percentile(0.95) > 600:
        logger.error("Test failed due to 95th percentile response time > 600 ms")
        environment.process_exit_code = 1
    else:
        environment.process_exit_code = 0
