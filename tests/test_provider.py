import logging
from datetime import datetime, timedelta

from httpx import AsyncClient, ASGITransport

from demo_project.dependencies import zitadel_auth
from demo_project.main import app
from tests.conftest import openid_config_url
from tests.utils import create_test_token, create_openid_keys

log = logging.getLogger(__name__)


async def test_http_error_old_config_found(respx_mock):
    """Test that the OpenID config is fetched if the current one is old"""
    zitadel_auth.openid_config.last_refresh = datetime.now() - timedelta(hours=20)
    zitadel_auth.openid_config.signing_keys = create_openid_keys()
    respx_mock.get(openid_config_url()).respond(status_code=500)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {create_test_token(role='admin')}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {
            "detail": "Connection to Zitadel is down. Unable to fetch provider configuration"
        }


async def test_http_error_no_initial_connection(respx_mock):
    """Test that the OpenID config is fetched on the first request"""
    zitadel_auth.openid_config.last_refresh = None
    zitadel_auth.openid_config.signing_keys = {}
    respx_mock.get(openid_config_url()).respond(status_code=500)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {create_test_token(role='admin')}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {
            "detail": "Connection to Zitadel is down. Unable to fetch provider configuration"
        }
