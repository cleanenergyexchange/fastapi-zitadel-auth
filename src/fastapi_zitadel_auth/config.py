from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, computed_field


class AuthConfig(BaseModel):
    """Configuration for Zitadel authentication"""

    model_config = ConfigDict(frozen=True)

    client_id: str = Field(..., description="OAuth2 client ID")
    project_id: str = Field(..., description="Zitadel project ID")
    zitadel_host: AnyHttpUrl = Field(..., description="Zitadel instance URL")
    algorithm: str = Field(default="RS256", description="JWT signing algorithm")
    scopes: dict[str, str] | None = Field(
        default=None, description="OAuth2 scope descriptions"
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def issuer(self) -> str:
        """Base URL without trailing slash for JWT issuer validation"""
        return str(self.zitadel_host).rstrip("/")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def jwks_url(self) -> str:
        """JWKS endpoint URL"""
        return f"{self.zitadel_host}oauth/v2/keys"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authorization_url(self) -> str:
        """OAuth2 authorization endpoint URL"""
        return f"{self.zitadel_host}oauth/v2/authorize"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def token_url(self) -> str:
        """OAuth2 token endpoint URL"""
        return f"{self.zitadel_host}oauth/v2/token"
