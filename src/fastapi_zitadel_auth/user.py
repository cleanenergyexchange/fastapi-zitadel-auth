from typing import (
    TypeVar,
    Generic,
    Any,  # noqa
)

from pydantic import BaseModel, Field, model_validator

# Generic type variables for claims and user models
ClaimsT = TypeVar("ClaimsT", bound="BaseZitadelClaims")
UserT = TypeVar("UserT", bound="BaseZitadelUser[Any]")


class BaseZitadelClaims(BaseModel):
    """Base model for standard JWT and OpenID claims"""

    # Standard JWT claims
    aud: str | list[str]
    exp: int
    iat: int
    iss: str
    sub: str
    nbf: int | None = None
    jti: str | None = None

    # Standard OpenID claims
    email: str | None = None
    email_verified: bool | None = None
    preferred_username: str | None = None
    name: str | None = None


class BaseZitadelUser(BaseModel, Generic[ClaimsT]):
    """Base authenticated user with claims and token"""

    claims: ClaimsT
    access_token: str

    def __str__(self):
        """Return user but redact token"""
        return f"{self.__class__.__name__}({self.model_dump_json(exclude={'access_token'})})"


class DefaultZitadelClaims(BaseZitadelClaims):
    """Default Zitadel claims implementation with project roles"""

    project_roles: dict[str, dict[str, str]] = Field(
        default_factory=dict,
    )

    @model_validator(mode="before")
    @classmethod
    def extract_project_roles(cls, values: dict) -> dict:
        """Extract project-specific role claim into project_roles field"""
        for key in values.keys():
            if key.startswith("urn:zitadel:iam:org:project:") and key.endswith(
                ":roles"
            ):
                values["project_roles"] = values[key]
                break
        return values


class DefaultZitadelUser(BaseZitadelUser[DefaultZitadelClaims]):
    """Default Zitadel user implementation"""

    claims: DefaultZitadelClaims
