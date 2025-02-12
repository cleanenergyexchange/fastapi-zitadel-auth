"""
Exceptions based on fastapi.exceptions.HTTPException and RFC 6750
"""

from fastapi import HTTPException, status


class InvalidRequestException(HTTPException):
    """Exception raised when request is malformed or invalid."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request", "message": detail},
        )


class UnauthorizedException(HTTPException):
    """Exception raised when authentication fails (no valid credentials)."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )


class ForbiddenException(HTTPException):
    """Exception raised when user lacks required permissions."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "insufficient_scope", "message": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )
