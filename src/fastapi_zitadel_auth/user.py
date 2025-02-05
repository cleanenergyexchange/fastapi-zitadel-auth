from pydantic import BaseModel, Field, model_validator


class ZitadelClaims(BaseModel):
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

    # Zitadel-specific claims
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


class ZitadelUser(BaseModel):
    """Authenticated user with claims and token"""

    claims: ZitadelClaims
    access_token: str

    def __str__(self):
        """Return user but redact token"""
        return f"ZitadelUser({self.model_dump_json(exclude={'access_token'})})"
