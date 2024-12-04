from typing import Any, List, Optional
from pydantic import BaseModel, Field


class JWTClaims(BaseModel):
    """Standard JWT claims as per RFC 7519"""

    aud: str | List[str]
    exp: int
    iat: int
    iss: str
    nbf: int
    sub: str
    jti: str | None = None


class ZitadelClaims(JWTClaims):
    """Zitadel specific claims extending JWT claims"""

    # Standard OpenID claims
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    preferred_username: str | None = None

    # Zitadel specific URN claims
    project_roles: dict[str, Any] = Field(
        default_factory=dict, alias="urn:zitadel:iam:org:project:roles"
    )
    user_metadata: dict[str, Any] = Field(
        default_factory=dict, alias="urn:zitadel:iam:user:metadata"
    )
    resource_owner_id: str | None = Field(
        None, alias="urn:zitadel:iam:user:resourceowner:id"
    )
    resource_owner_name: str | None = Field(
        None, alias="urn:zitadel:iam:user:resourceowner:name"
    )
    resource_owner_domain: str | None = Field(
        None, alias="urn:zitadel:iam:user:resourceowner:primary_domain"
    )


class AuthenticatedUser(BaseModel):
    """Authenticated user with claims and token"""

    claims: ZitadelClaims
    access_token: str

    @property
    def user_id(self) -> str:
        return self.claims.sub

    def __str__(self):
        """Return user but redact token"""
        return f"AuthenticatedUser(claims={self.claims}, access_token=***)"
