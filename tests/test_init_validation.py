"""Tests for ``ZitadelAuth.__init__`` parameter validation.

These tests cover the constructor's defense-in-depth guards: rejecting
mistyped scopes, missing-scheme URLs, out-of-range leeway, and other
configuration mistakes at startup rather than at first request.
"""

import pytest
from pydantic import BaseModel

from fastapi_zitadel_auth import ZitadelAuth
from tests.utils import ZITADEL_ISSUER


class _InvalidClaims(BaseModel):
    """Claims class that doesn't inherit from JwtClaims."""

    some_field: str


class _InvalidUser(BaseModel):
    """User class that doesn't inherit from BaseZitadelUser."""

    some_field: str


class TestClaimsAndUserModel:
    """Reject ``claims_model`` / ``user_model`` overrides that don't inherit the base classes."""

    def test_invalid_claims_model(self):
        """A claims_model not inheriting from JwtClaims raises ValueError."""
        with pytest.raises(ValueError, match="claims_model must be a subclass of JwtClaims"):
            ZitadelAuth(
                claims_model=_InvalidClaims,  # type: ignore
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={"openid": "OpenID Connect"},
            )

    def test_invalid_user_model(self):
        """A user_model not inheriting from BaseZitadelUser raises ValueError."""
        with pytest.raises(ValueError, match="user_model must be a subclass of BaseZitadelUser"):
            ZitadelAuth(
                user_model=_InvalidUser,  # type: ignore
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={"openid": "OpenID Connect"},
            )


class TestSchemeNameAndDescription:
    """Reject empty / whitespace-only ``scheme_name`` and ``description``."""

    def test_empty_scheme_name(self):
        """An empty scheme_name raises ValueError."""
        with pytest.raises(ValueError, match="scheme_name must be a non-empty string"):
            ZitadelAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={"openid": "OpenID Connect"},
                scheme_name="",
            )

    def test_empty_description(self):
        """An empty description raises ValueError."""
        with pytest.raises(ValueError, match="description must be a non-empty string"):
            ZitadelAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={"openid": "OpenID Connect"},
                description="",
            )

    def test_whitespace_scheme_name(self):
        """A whitespace-only scheme_name raises ValueError."""
        with pytest.raises(ValueError, match="scheme_name must be a non-empty string"):
            ZitadelAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={"openid": "OpenID Connect"},
                scheme_name="   ",
            )

    def test_whitespace_description(self):
        """A whitespace-only description raises ValueError."""
        with pytest.raises(ValueError, match="description must be a non-empty string"):
            ZitadelAuth(
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={"openid": "OpenID Connect"},
                description="   ",
            )

    def test_custom_scheme_name_and_description(self):
        """A non-empty scheme_name override is preserved on the instance."""
        custom_auth = ZitadelAuth(
            issuer_url=ZITADEL_ISSUER,
            project_id="project_id",
            app_client_id="client_id",
            allowed_scopes={"openid": "OpenID Connect"},
            scheme_name="CustomAuthScheme",
            description="Custom authentication description",
        )
        assert custom_auth.scheme_name == "CustomAuthScheme"


class TestTokenLeewayValidation:
    """Guards on ``token_leeway`` to prevent misconfiguration that would weaken exp/nbf/iat."""

    @staticmethod
    def _build(token_leeway):
        """Construct a ZitadelAuth with the supplied token_leeway and library defaults elsewhere."""
        return ZitadelAuth(
            issuer_url=ZITADEL_ISSUER,
            project_id="project_id",
            app_client_id="client_id",
            allowed_scopes={"openid": "OpenID Connect"},
            token_leeway=token_leeway,
        )

    def test_default_zero_accepted(self):
        """Omitting token_leeway yields 0.0."""
        auth = ZitadelAuth(
            issuer_url=ZITADEL_ISSUER,
            project_id="project_id",
            app_client_id="client_id",
            allowed_scopes={"openid": "OpenID Connect"},
        )
        assert auth.token_leeway == 0.0

    def test_value_at_cap_accepted(self):
        """The exact cap value (30 s) is accepted."""
        auth = self._build(30)
        assert auth.token_leeway == 30.0

    def test_value_above_cap_rejected(self):
        """A value above the 30 s cap raises ValueError."""
        with pytest.raises(ValueError, match="token_leeway is invalid"):
            self._build(31)

    def test_negative_value_rejected(self):
        """A negative value raises ValueError."""
        with pytest.raises(ValueError, match="token_leeway is invalid"):
            self._build(-1)

    def test_non_numeric_value_rejected(self):
        """A non-numeric value raises ValueError."""
        with pytest.raises(ValueError, match="token_leeway is invalid"):
            self._build("5")  # type: ignore[arg-type]

    def test_bool_value_rejected(self):
        """A bool (subclass of int) is rejected thanks to pydantic strict mode."""
        with pytest.raises(ValueError, match="token_leeway is invalid"):
            self._build(True)  # type: ignore[arg-type]

    def test_nan_value_rejected(self):
        """NaN is rejected by the allow_inf_nan=False constraint."""
        with pytest.raises(ValueError, match="token_leeway is invalid"):
            self._build(float("nan"))

    def test_positive_infinity_rejected(self):
        """Positive infinity is rejected by the allow_inf_nan=False constraint."""
        with pytest.raises(ValueError, match="token_leeway is invalid"):
            self._build(float("inf"))

    def test_negative_infinity_rejected(self):
        """Negative infinity is rejected by the allow_inf_nan=False constraint."""
        with pytest.raises(ValueError, match="token_leeway is invalid"):
            self._build(float("-inf"))


class TestIssuerUrlValidation:
    """Guards on ``issuer_url`` — fail at construction time, not at first OIDC discovery."""

    @staticmethod
    def _build(issuer_url):
        """Construct a ZitadelAuth with the supplied issuer_url and library defaults elsewhere."""
        return ZitadelAuth(
            issuer_url=issuer_url,
            project_id="project_id",
            app_client_id="client_id",
            allowed_scopes={"openid": "OpenID Connect"},
        )

    def test_valid_https_url_accepted(self):
        """A valid https URL is preserved on the instance."""
        auth = self._build("https://example.zitadel.cloud")
        assert auth.issuer_url == "https://example.zitadel.cloud"

    def test_trailing_slash_stripped(self):
        """A trailing slash on the issuer URL is stripped."""
        auth = self._build("https://example.zitadel.cloud/")
        assert auth.issuer_url == "https://example.zitadel.cloud"

    def test_url_without_scheme_rejected(self):
        """A URL missing the http/https scheme raises ValueError."""
        with pytest.raises(ValueError, match="issuer_url is invalid"):
            self._build("example.zitadel.cloud")

    def test_empty_string_rejected(self):
        """An empty issuer_url raises ValueError."""
        with pytest.raises(ValueError, match="issuer_url is invalid"):
            self._build("")

    def test_non_http_scheme_rejected(self):
        """A non-http(s) scheme (e.g. javascript:) raises ValueError."""
        with pytest.raises(ValueError, match="issuer_url is invalid"):
            self._build("javascript:alert(1)")
