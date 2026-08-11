"""Authplane implementation of ``TokenVerifier``.

The only module in this package that imports ``authplane``. The import is
deferred into ``create()`` so that ``import mysql_mcp_server`` works when the
``[auth]`` extra is not installed and auth is switched off.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .protocol import (
    AuthenticationError,
    AuthorizationError,
    Identity,
    RequestContext,
    VerifierConfigError,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .settings import AuthSettings

logger = logging.getLogger(__name__)

_INSTALL_HINT = (
    "MCP_AUTH_MODE=authplane requires the auth extra. "
    "Install with: pip install mysql_mcp_server[auth]"
)


class AuthplaneVerifier:
    """Verifies Authplane-issued RFC 9068 JWTs.

    Audience validation is delegated to the SDK, which checks ``aud`` against
    the resource URI this verifier was constructed with. That check is what
    stops a token minted for a *different* resource from being replayed here,
    so the resource URI must match the value registered at the authorization
    server byte-for-byte — a trailing slash is enough to break it.
    """

    def __init__(self, client: Any, resource: Any, settings: "AuthSettings") -> None:
        self._client = client
        self._resource = resource
        self._settings = settings
        self._closed = False

    @classmethod
    async def create(cls, settings: "AuthSettings") -> "AuthplaneVerifier":
        """Discover AS metadata and prime the JWKS cache.

        Deliberately done at startup rather than lazily on the first request:
        a wrong issuer then fails loudly at boot instead of turning into a 401
        storm later. The trade-off is that the authorization server must be
        reachable when this server starts.
        """
        try:
            from authplane import AuthplaneClient
        except ImportError as exc:  # pragma: no cover - depends on install shape
            raise VerifierConfigError(_INSTALL_HINT) from exc

        create_kwargs: dict = {"dev_mode": settings.dev_mode}
        if settings.revocation_check:
            from authplane import ASCredentials

            # Introspection is an authenticated call; the resource server needs
            # its own client credentials at the AS to make it.
            create_kwargs["auth"] = ASCredentials(
                settings.client_id, settings.client_secret
            )

        try:
            client = await AuthplaneClient.create(settings.issuer, **create_kwargs)
        except Exception as exc:
            raise VerifierConfigError(
                f"Could not reach the authorization server at {settings.issuer}: {exc}. "
                "Start it before this server, or unset MCP_AUTH_MODE."
            ) from exc

        resource_kwargs: dict = {
            "allowed_algorithms": list(settings.allowed_algorithms),
            "clock_skew_seconds": settings.clock_skew_seconds,
        }
        if settings.dpop != "off":
            from authplane import InboundDPoPOptions

            # Passing the options object at all is what makes the PRM document
            # advertise DPoP support, which is how a client discovers it can use
            # sender-constrained tokens here. `required` promotes that from
            # "supported" to "mandatory" -- and mandatory locks out every client
            # that cannot produce a proof, which is why it is not the default.
            resource_kwargs["inbound_dpop"] = InboundDPoPOptions(
                required=settings.dpop == "required",
                allowed_proof_algorithms=list(settings.allowed_algorithms),
                clock_skew_seconds=settings.clock_skew_seconds,
            )

        if settings.revocation_check:
            from authplane import IntrospectionRevocation

            resource_kwargs["revocation_checker"] = IntrospectionRevocation()
            # The SDK's default is fail-*open*: its own docstring describes
            # `IntrospectionRevocation` as "fail-open introspection checking", so
            # an introspection error would let the token through. For a tool that
            # runs SQL, an unanswerable "is this token still valid?" must mean no.
            resource_kwargs["fail_closed"] = True

        try:
            resource = client.resource(
                settings.resource, list(settings.scopes), **resource_kwargs
            )
        except Exception:
            await client.aclose()
            raise

        logger.info(
            "Authplane verifier ready. Issuer: %s. Expected 'aud': %s. Algorithms: %s. "
            "Revocation checking: %s. DPoP: %s.",
            settings.issuer,
            settings.resource,
            ", ".join(settings.allowed_algorithms),
            "on (fail-closed)" if settings.revocation_check else "off (tokens live until exp)",
            {
                "off": "off (bearer tokens; a stolen token is usable)",
                "optional": "advertised and verified when presented",
                "required": "required (clients without DPoP support cannot connect)",
            }[settings.dpop],
        )
        return cls(client, resource, settings)

    async def verify(self, token: str, request: "RequestContext | None" = None) -> Identity:
        try:
            # RequestContext exposes method/url/proof, which is exactly the
            # DPoPRequestContext protocol the SDK reads, so it is passed straight
            # through. When DPoP is off the SDK ignores it.
            if request is not None:
                claims = await self._resource.verify(token, dpop_request=request)
            else:
                claims = await self._resource.verify(token)
        except Exception as exc:
            # Translate into this package's two error types so the middleware
            # never sees a provider-specific exception. The SDK's own status
            # mapping decides 401-vs-403, so insufficient_scope stays a 403.
            raise self._translate(exc) from exc

        return Identity(
            subject=getattr(claims, "sub", "") or "",
            scopes=frozenset(self._scopes_of(claims)),
            client_id=getattr(claims, "client_id", "") or "",
            token_id=getattr(claims, "jti", "") or "",
            expires_at=int(getattr(claims, "expires_at", 0) or 0),
            raw=dict(getattr(claims, "raw", {}) or {}),
        )

    @staticmethod
    def _scopes_of(claims: Any) -> frozenset[str]:
        """Read granted scopes, tolerating either shape the claim can take.

        RFC 8693 §4.2 makes ``scope`` a space-delimited string, but SDKs
        commonly expose a pre-split sequence. Accept both rather than assume.
        """
        value = getattr(claims, "scopes", None)
        if value is None:
            raw = getattr(claims, "raw", {}) or {}
            value = raw.get("scope") or raw.get("scp") or ""
        if isinstance(value, str):
            return frozenset(v for v in value.split() if v)
        try:
            return frozenset(str(v) for v in value)
        except TypeError:
            return frozenset()

    def _translate(self, exc: Exception) -> Exception:
        """Map an SDK exception onto AuthenticationError / AuthorizationError."""
        try:
            from authplane import AuthplaneError, InsufficientScopeError, http_status

            if isinstance(exc, InsufficientScopeError):
                return AuthorizationError(str(exc), required=tuple(self._settings.scopes))
            if isinstance(exc, AuthplaneError):
                status = http_status(exc)
                if status == 403:
                    return AuthorizationError(str(exc))
                return AuthenticationError(str(exc), error=getattr(exc, "error", "invalid_token"))
        except ImportError:  # pragma: no cover - only if the extra vanished mid-run
            pass
        # Unknown failure: fail closed, and do not echo the detail to the caller.
        logger.warning("Token verification failed: %s: %s", type(exc).__name__, exc)
        return AuthenticationError("Token verification failed")

    def protected_resource_metadata(self) -> dict:
        return dict(self._resource.prm_response())

    def metadata_url(self) -> str:
        return str(self._resource.prm_url())

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._client.aclose()
