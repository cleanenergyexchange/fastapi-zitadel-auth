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
    """Base model for JWT access token claims in Zitadel
    as per RFC 7519 and Zitadel
    """

    aud: str | list[str] = Field(
        description="The audience of the token (e.g. client_id and project_id)"
    )
    client_id: str = Field(
        description="Client id of the client who requested the token"
    )
    exp: int = Field(description="Time the token expires (as unix time)")
    iat: int = Field(description="Time of the token was issued at (as unix time)")
    iss: str = Field(description="Issuing domain of a token")
    sub: str = Field(description="Subject ID of the user")
    nbf: int = Field(
        description="Time the token must not be used before (as unix time)"
    )
    jti: str = Field(description="Unique id of the token")


class BaseZitadelUser(BaseModel, Generic[ClaimsT]):
    """Base authenticated user with claims and token"""

    claims: ClaimsT
    access_token: str


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
