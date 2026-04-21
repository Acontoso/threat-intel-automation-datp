"""Azure AD token validation and FastAPI auth dependency."""
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable

from collections.abc import Awaitable, Callable as AwaitableCallable

import jwt
from fastapi import Depends, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
AZURE_ALLOWED_AUDIENCES: set[str] = {
    value.strip()
    for value in os.getenv("AZURE_ALLOWED_AUDIENCES", AZURE_CLIENT_ID).split(",")
    if value.strip()
}

@dataclass
class AuthContext:
    """Validated token claims and extracted identity for use in route handlers."""

    token: dict[str, Any]
    actor_id: str   # Entra object ID (oid), defines actor ID in memory
    scopes: set[str]


def validate_required_scopes(scopes: set[str], required_scopes: set[str]) -> None:
    if required_scopes and not required_scopes.issubset(scopes):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "User does not have required permissions.",
            },
        )


def _ensure_auth_configuration() -> None:
    if not AZURE_TENANT_ID or not AZURE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Azure AD authentication is not configured.",
        )


@lru_cache(maxsize=1)
def _jwks_client() -> jwt.PyJWKClient:
    _ensure_auth_configuration()
    jwks_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/discovery/v2.0/keys"
    return jwt.PyJWKClient(jwks_url, cache_keys=True)


def _expected_issuer() -> str:
    return f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0"


def _extract_scopes(claims: dict[str, Any]) -> set[str]:
    """Extract scopes from both 'scp' and 'roles' claims to support both delegated and application permissions."""
    scopes = set(str(claims.get("scp", "")).split())
    roles = claims.get("roles", [])
    if isinstance(roles, list):
        scopes.update(str(role) for role in roles)
    return {value for value in scopes if value}


def _validate_audience(claims: dict[str, Any]) -> None:
    audience_claim = claims.get("aud")
    if isinstance(audience_claim, str):
        audiences = {audience_claim}
    elif isinstance(audience_claim, list):
        audiences = {str(v) for v in audience_claim}
    else:
        audiences = set()

    if not audiences.intersection(AZURE_ALLOWED_AUDIENCES):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token audience is invalid.",
        )


def _validate_access_token(raw_token: str) -> AuthContext:
    _ensure_auth_configuration()

    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(raw_token)
        claims = jwt.decode(
            raw_token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=_expected_issuer(),
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired."
        ) from exc
    except jwt.InvalidIssuerError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token issuer is invalid."
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token validation failed."
        ) from exc

    _validate_audience(claims)
    scopes = _extract_scopes(claims)

    actor_id = str(claims.get("oid") or claims.get("sub") or "")
    if not actor_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token does not contain a subject.",
        )

    return AuthContext(token=claims, actor_id=actor_id, scopes=scopes)


def require_auth(request: Request) -> AuthContext:
    """
        FastAPI dependency that reads the validated AuthContext from request state.
        The AuthMiddleware must be registered to populate request.state.auth.
    """
    auth = getattr(request.state, "auth", None)
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token."
        )
    return auth


def require_scopes(required_scopes: set[str]) -> Callable[..., AuthContext]:
    """Return a FastAPI dependency that enforces required scopes/roles."""
    # dependency function that will be used in route handlers to enforce scope requirements, it depends on require_auth to first validate the token and extract scopes, then checks if required scopes are present
    # require_auth is executed first as defined in the Depends, and its output (AuthContext) is passed to this function for scope validation
    def _dependency(auth: AuthContext = Depends(require_auth)) -> AuthContext:
        validate_required_scopes(auth.scopes, required_scopes)
        return auth

    return _dependency


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: AwaitableCallable[[Request], Awaitable[Response]]) -> Response:
        authorization = request.headers.get("Authorization", "")
        if not authorization.lower().startswith("bearer "):
            return JSONResponse(status_code=401, content={"detail": "Missing bearer token."})

        raw_token = authorization[len("bearer "):]
        try:
            auth_context = _validate_access_token(raw_token)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

        request.state.auth = auth_context
        return await call_next(request)
