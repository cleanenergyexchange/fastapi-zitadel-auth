# Custom Claims and Users

The package supports customizing claims and user models for additional JWT claims or custom business logic.

## Basic Usage

```python
from pydantic import Field
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import BaseZitadelClaims, BaseZitadelUser

class CustomClaims(BaseZitadelClaims):
    """Custom claims with additional fields"""
    organizations: list[str] = Field(
        default_factory=list,
        alias="custom:org:list"
    )

class CustomUser(BaseZitadelUser[CustomClaims]): # always specify claims type when extending `BaseZitadelUser`
    """Custom user implementation"""
    claims: CustomClaims

    def get_organizations(self) -> list[str]:
        """Custom business logic"""
        return self.claims.organizations

# Initialize with custom models
auth = ZitadelAuth(
    issuer_url="https://example.zitadel.cloud",
    project_id="123",
    app_client_id="456",
    allowed_scopes={"openid": "OpenID Connect"},
    claims_model=CustomClaims,
    user_model=CustomUser
)
```


> [!IMPORTANT]
> If you check Zitadel project roles during authentication (as the default implementation does),
> you should check the `DefaultZitadelClaims` implementation for the `project_roles` attribute
> and Pydantic `model_validator` to load it from the JWT claims, see `user.py`.
