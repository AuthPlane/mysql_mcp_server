"""The verifier seam.

Everything in this package that handles requests depends on ``TokenVerifier``
and nothing else. The Authplane implementation in ``authplane.py`` is one
implementer; the middleware never imports it, never names it, and never
branches on it.

That is the whole point of this file. Swapping in a different OAuth 2.1
authorization server means writing a class that satisfies ``TokenVerifier``
and returning it from ``build_verifier()`` in ``__init__.py`` for a new
``MCP_AUTH_MODE`` value. No other file changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class AuthenticationError(Exception):
    """Token is absent, malformed, expired, or not trustworthy — HTTP 401.

    ``error`` is the RFC 6750 §3 code that belongs in the
    ``WWW-Authenticate`` challenge, not prose for humans.
    """

    status = 401

    def __init__(self, message: str, *, error: str = "invalid_token") -> None:
        super().__init__(message)
        self.error = error


class AuthorizationError(Exception):
    """Token is valid but lacks the required scope — HTTP 403.

    Distinct from ``AuthenticationError`` on purpose: retrying with the same
    token is futile, so telling the client "unauthenticated" would send it into
    a pointless re-authentication loop. RFC 6750 §3.1 reserves
    ``insufficient_scope`` for exactly this.
    """

    status = 403

    def __init__(self, message: str, *, required: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.error = "insufficient_scope"
        self.required = required


class VerifierUnavailableError(Exception):
    """Validation could not be completed — HTTP 503 or 500.

    Not an authentication failure, and the distinction is operational rather
    than pedantic. When the authorization server is unreachable or the SDK's
    circuit breaker is open, the token in hand may be perfectly good; nobody
    can currently say. Reporting that as ``401 invalid_token`` tells a
    conforming client its credential is bad, so it discards a working token and
    re-authenticates against the authorization server that is already down —
    turning an AS outage into a stampede against the AS.

    Two consequences follow from that, and both are enforced by the middleware
    rather than left to the caller:

    * **No ``WWW-Authenticate`` challenge.** The challenge is what invites a
      client to go get a new token. RFC 6750 §3 defines it for authentication
      failures; this is not one.
    * **No failure-throttle penalty.** Throttling exists to make brute force
      expensive. Penalising clients for the server's own outage would refuse
      them service for the whole throttle window *after* the AS recovers.

    ``status`` is 503 when the authorization server is temporarily unable to
    participate (fetch failures, open circuit) and 500 when the fault is
    internal to this server or the verifier. ``error`` carries the matching
    OAuth 2.0 code from RFC 6749 §5.2.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int = 503,
        error: str = "temporarily_unavailable",
        retry_after: int = 0,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.error = error
        self.retry_after = retry_after


class VerifierConfigError(RuntimeError):
    """Auth is switched on but unusable. Raised at startup, never per-request.

    A server that boots "with auth enabled" but cannot actually verify anything
    is worse than one that refuses to boot, because the failure surfaces as
    mysterious 401s under load instead of a message at startup.
    """


@dataclass(frozen=True)
class Identity:
    """The provider-agnostic subset of token claims this server acts on.

    Deliberately small. A verifier may learn far more about a token than this;
    only what the server actually uses to make decisions belongs here, so that
    a new verifier implementation is not obliged to synthesise fields nobody
    reads. ``raw`` is the escape hatch for provider-specific claims.
    """

    subject: str
    scopes: frozenset[str] = frozenset()
    client_id: str = ""
    token_id: str = ""
    expires_at: int = 0
    raw: dict = field(default_factory=dict)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def describe(self) -> str:
        """A short, log-safe identity string. Never includes the token."""
        who = self.subject or "<no-sub>"
        if self.client_id and self.client_id != self.subject:
            who = f"{who} (client {self.client_id})"
        return who


@dataclass(frozen=True)
class RequestContext:
    """The parts of an HTTP request a verifier may need beyond the token itself.

    Exists for sender-constrained tokens (DPoP, RFC 9449), where the proof is
    signed over the method and target URI, so verifying it requires knowing what
    request the token arrived on. A verifier that only checks bearer tokens
    ignores this entirely.

    ``url`` is the target URI **without query or fragment** — RFC 9449 §4.2
    defines ``htu`` that way, and on this transport the query string carries a
    per-session id that would otherwise make every proof fail.

    The field names match what the Authplane SDK's ``DPoPRequestContext``
    protocol reads, so an instance can be handed to it directly. That is a
    convenience, not a coupling: any verifier can read these three attributes.
    """

    method: str
    url: str
    proof: str | None = None


@runtime_checkable
class TokenVerifier(Protocol):
    """What the middleware requires of an authentication backend.

    Four members. An implementation is responsible for *all* of token
    validation — signature, algorithm allow-list, ``exp``/``nbf``, ``iss``, and
    critically ``aud``. The middleware does not second-guess any of it, so an
    implementation that skips audience validation silently reintroduces the
    confused-deputy problem: a token minted for a different resource would be
    accepted here.
    """

    async def verify(self, token: str, request: RequestContext | None = None) -> Identity:
        """Validate ``token`` and return its identity.

        ``request`` describes the HTTP request the token arrived on. It is
        required only for sender-constrained tokens, where the proof is signed
        over the method and URI; an implementation that only handles bearer
        tokens may ignore it.

        Raises ``AuthenticationError`` for anything untrustworthy,
        ``AuthorizationError`` for a valid token lacking scope, and
        ``VerifierUnavailableError`` when validation could not be *attempted* —
        the authorization server being unreachable is not the same answer as
        the token being bad, and collapsing the two makes an outage look like a
        credential problem to every client at once.

        Must not raise provider-specific exception types: the middleware maps
        only the three error classes in this module, and anything else is
        treated as an internal fault (500).
        """
        ...

    def protected_resource_metadata(self) -> dict:
        """The RFC 9728 document served at the well-known path.

        Must advertise ``resource`` and ``authorization_servers`` so a client
        that receives a 401 can discover where to get a token without any
        hand-configured endpoints.
        """
        ...

    def metadata_url(self) -> str:
        """Absolute URL of the document above, for the 401 challenge."""
        ...

    async def aclose(self) -> None:
        """Release background work (JWKS refresh tasks, HTTP clients)."""
        ...
