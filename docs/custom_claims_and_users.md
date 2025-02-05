# Custom Claims and Users

This package supports customizing both claims and user models to accommodate additional JWT claims or custom business logic.
This is done by extending the base models provided by the package.

## Basic Custom Implementation

Here's a basic example of extending the default models:

```python
from pydantic import Field
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import BaseZitadelClaims, BaseZitadelUser

class CustomZitadelClaims(BaseZitadelClaims):
    """Custom claims model with additional fields"""

    # Inherit standard JWT claims from BaseZitadelClaims
    # (aud, exp, iat, iss, sub, etc.)

    # Add your custom claims
    organizations: list[str] = Field(
        default_factory=list,
        alias="myfield:xyz:orgs"
    )

class CustomZitadelUser(BaseZitadelUser[CustomZitadelClaims]):
    """Custom user model implementation"""
    claims: CustomZitadelClaims

    # Add custom methods if needed
    def get_organizations(self) -> list[str]:
        return self.claims.organizations

# Initialize auth with custom models
auth = ZitadelAuth[CustomZitadelClaims, CustomZitadelUser](
    issuer="https://example.zitadel.cloud",
    project_id="project123",
    client_id="client123",
    scopes={"email": "Email access"},
    claims_model=CustomZitadelClaims,
    user_model=CustomZitadelUser
)
```

## Important Notes

1. `BaseZitadelClaims` includes standard JWT claims (aud, exp, iat, etc.) and OpenID claims (email, name, etc.)
2. If you need Zitadel project roles, remember to include the project_roles field and validator, or extend the default implementation.
