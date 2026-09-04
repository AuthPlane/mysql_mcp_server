"""Opt-in OAuth 2.1 resource-server authentication for the SSE transport.

Off unless ``MCP_AUTH_MODE`` is set. With it unset, nothing here runs and no
optional dependency is imported, so the base install is unaffected.

Layout:

    protocol.py    the TokenVerifier seam -- the only thing middleware knows
    authplane.py   the Authplane implementation of that seam
    middleware.py  authentication + per-tool scope enforcement
    settings.py    environment parsing, with startup-time validation
"""

from __future__ import annotations

from .middleware import PRM_PATH, PROTECTED_PREFIXES, PUBLIC_PATHS, AuthMiddleware
from .protocol import (
    AuthenticationError,
    AuthorizationError,
    Identity,
    TokenVerifier,
    VerifierConfigError,
    VerifierUnavailableError,
)
from .settings import CANONICAL_MODE, AuthSettings

__all__ = [
    "PRM_PATH",
    "PROTECTED_PREFIXES",
    "PUBLIC_PATHS",
    "AuthMiddleware",
    "AuthSettings",
    "AuthenticationError",
    "AuthorizationError",
    "Identity",
    "TokenVerifier",
    "VerifierConfigError",
    "VerifierUnavailableError",
    "build_verifier",
]


async def build_verifier(settings: AuthSettings) -> TokenVerifier:
    """Construct the verifier for ``settings.mode``.

    The single place a mode name maps to an implementation, and the only place
    in the configuration path that names a provider at all. Adding a backend
    means adding a branch here and a class satisfying ``TokenVerifier``;
    nothing in ``middleware.py`` changes.

    ``MCP_AUTH_MODE=oauth`` selects Authplane because it is the backend that
    ships, not because the mode means Authplane. A second backend would be
    chosen here -- by a new mode value, or by discovery against the configured
    issuer -- without touching a single operator-facing variable.
    """
    if settings.mode == CANONICAL_MODE:
        from .authplane import AuthplaneVerifier

        return await AuthplaneVerifier.create(settings)

    raise VerifierConfigError(f"No verifier is registered for MCP_AUTH_MODE={settings.mode!r}.")
