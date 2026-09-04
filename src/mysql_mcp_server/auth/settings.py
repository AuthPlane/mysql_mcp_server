"""Environment-driven auth configuration.

``MCP_AUTH_MODE`` is this repo's own on/off switch and stays in the existing
``MCP_*`` namespace. Everything else uses the names the Authplane SDK
documents, so an operator following those docs finds what they expect.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .protocol import VerifierConfigError

logger = logging.getLogger(__name__)

_OFF_VALUES = ("", "none", "off", "false", "0")
KNOWN_MODES = ("authplane",)

# Default scope names. Both are configurable because a deployment with an
# existing scope taxonomy should not have to adopt ours.
DEFAULT_READ_SCOPE = "mysql:read"
DEFAULT_WRITE_SCOPE = "mysql:write"


def auth_enabled_in_env() -> bool:
    """Whether MCP_AUTH_MODE asks for authentication, without validating the rest.

    ``AuthSettings.from_env()`` raises on a half-configured auth setup, which is
    the right behaviour where auth is about to be wired up -- but the startup
    read-path check only needs the yes/no, and must not turn "auth is off" into
    an exception for an operator running stdio with a stray AUTHPLANE_* variable
    exported. Reads the one variable that decides it and nothing else.
    """
    return os.getenv("MCP_AUTH_MODE", "none").strip().lower() not in _OFF_VALUES


def canonical_resource(raw: str) -> str:
    """Normalise trailing-slash form without breaking the root path.

    RFC 3986 treats an empty path as equivalent to ``/`` for an http(s) URI, so
    any URL library a client uses to build a ``resource=`` parameter
    re-serialises ``http://host:port`` as ``http://host:port/``. An empty path
    is therefore canonicalised to ``/`` rather than a trailing slash being
    stripped: stripping it yields a value no conforming client ever sends for a
    root resource, so this server's PRM document and its own ``aud`` check would
    say ``http://localhost:8000`` while a real OAuth client says
    ``http://localhost:8000/``, and the authorization server answers "Unknown
    Resource" to the mismatch. Only the ``authorization_code`` path exercises
    this: the ``client_credentials`` grant asks for its audience directly and
    never asks a URL library to build the request, so nothing there re-adds the
    slash.

    A non-root path is left untouched, trailing slash and all: there the slash
    is part of the path rather than an artefact of an empty one, and
    ``http://host/mcp`` and ``http://host/mcp/`` name different resources.

    Not applied to ``AUTHPLANE_ISSUER``: the ``iss`` claim's source of truth is
    whatever the authorization server itself puts in the token, which by
    Authplane's own convention is the bare origin with no trailing slash --
    adding one here would create the same mismatch this fixes, against the
    other side of the comparison.
    """
    if not raw:
        return raw
    parts = urlsplit(raw)
    if not parts.path:
        parts = parts._replace(path="/")
    return urlunsplit(parts)


@dataclass(frozen=True)
class AuthSettings:
    enabled: bool
    mode: str = "none"
    issuer: str = ""
    resource: str = ""
    scopes: tuple[str, ...] = ()
    read_scope: str = DEFAULT_READ_SCOPE
    write_scope: str = DEFAULT_WRITE_SCOPE
    enforce_scopes: bool = True
    bind_session_to_subject: bool = True
    revocation_check: bool = False
    client_id: str = ""
    client_secret: str = ""
    audit: bool = True
    audit_file: str = ""
    throttle_failures: int = 0
    throttle_window_seconds: float = 60.0
    dpop: str = "off"
    allowed_algorithms: tuple[str, ...] = ("ES256", "RS256")
    # Algorithms a DPoP *proof* may be signed with. Defaults to
    # allowed_algorithms; see from_env() on why they are separable.
    dpop_algorithms: tuple[str, ...] = ()
    clock_skew_seconds: int = 30
    dev_mode: bool = False
    realm: str = "mysql_mcp_server"
    # ``Retry-After`` on a 503 raised because the authorization server could not
    # be reached. A hint, not a promise: it exists so a client that respects it
    # backs off instead of retrying in a tight loop against an AS that is
    # already struggling. Deliberately short -- an AS restart is usually
    # seconds, and the SDK's circuit breaker will answer instantly meanwhile.
    unavailable_retry_after: int = 5

    def __post_init__(self) -> None:
        """Canonicalise the resource URI on *every* construction path.

        ``from_env`` is not the only way settings are built: anything that
        constructs them by hand -- the test harness, an embedding application --
        has the same need, and settings that disagreed with the running server
        about what the audience is would be exactly the kind of mismatch
        ``canonical_resource`` exists to prevent.
        """
        object.__setattr__(self, "resource", canonical_resource(self.resource))

    @property
    def effective_dpop_algorithms(self) -> tuple[str, ...]:
        """Proof algorithms, falling back to the token algorithms.

        A property rather than a default in ``from_env`` alone, for the same
        reason ``__post_init__`` canonicalises the resource: settings built by
        hand -- tests, an embedding application -- must not disagree with
        settings built from the environment about what the effective value is.
        """
        return self.dpop_algorithms or self.allowed_algorithms

    @classmethod
    def from_env(cls) -> "AuthSettings":
        mode = os.getenv("MCP_AUTH_MODE", "none").strip().lower()
        if mode in _OFF_VALUES:
            return cls(enabled=False)
        if mode not in KNOWN_MODES:
            raise VerifierConfigError(
                f"MCP_AUTH_MODE={mode!r} is not recognised. "
                f"Supported: {', '.join(KNOWN_MODES)}, or 'none' to disable."
            )

        issuer = os.getenv("AUTHPLANE_ISSUER", "").strip().rstrip("/")
        resource = canonical_resource(os.getenv("AUTHPLANE_RESOURCE", "").strip())
        missing = [
            name
            for name, value in (
                ("AUTHPLANE_ISSUER", issuer),
                ("AUTHPLANE_RESOURCE", resource),
            )
            if not value
        ]
        if missing:
            raise VerifierConfigError(
                f"MCP_AUTH_MODE={mode} requires {' and '.join(missing)}. "
                "AUTHPLANE_ISSUER is the authorization server's base URL "
                "(e.g. http://localhost:9000). AUTHPLANE_RESOURCE is this server's "
                "canonical URI and must equal the token's 'aud' claim byte-for-byte."
            )

        dev_mode = _flag("AUTHPLANE_DEV_MODE", False)
        if issuer.startswith("http://") and not dev_mode:
            logger.warning(
                "AUTHPLANE_ISSUER uses http:// (%s). Bearer tokens and JWKS travel "
                "unencrypted; use https:// outside local development.",
                issuer,
            )

        read_scope = os.getenv("MYSQL_SCOPE_READ", DEFAULT_READ_SCOPE).strip()
        write_scope = os.getenv("MYSQL_SCOPE_WRITE", DEFAULT_WRITE_SCOPE).strip()
        if not read_scope or not write_scope:
            raise VerifierConfigError(
                "MYSQL_SCOPE_READ and MYSQL_SCOPE_WRITE must be non-empty."
            )
        if read_scope == write_scope:
            raise VerifierConfigError(
                f"MYSQL_SCOPE_READ and MYSQL_SCOPE_WRITE are both {read_scope!r}. "
                "Identical values collapse the read/write split into no split at all."
            )

        declared = os.getenv("AUTHPLANE_SCOPES", "")
        scopes = tuple(s.strip() for s in declared.split(",") if s.strip())
        if not scopes:
            # Advertise what this server actually uses rather than nothing.
            scopes = (read_scope, write_scope)

        algorithms = tuple(
            a.strip()
            for a in os.getenv("AUTHPLANE_ALLOWED_ALGORITHMS", "ES256,RS256").split(",")
            if a.strip()
        )
        if not algorithms:
            raise VerifierConfigError("AUTHPLANE_ALLOWED_ALGORITHMS resolved to an empty list.")
        if any(a.lower() == "none" for a in algorithms):
            # 'alg: none' means unsigned: anyone can mint a token for any subject.
            raise VerifierConfigError("Algorithm 'none' is never acceptable for access tokens.")

        # Proof algorithms are configured separately from token algorithms, and
        # default to them. The two lists constrain different parties: the token
        # list says what the *authorization server* may sign with, the proof list
        # what a *client* may sign with. One variable for both meant proofs could
        # not be restricted to ES256 while RS256-signed tokens stayed acceptable
        # -- a reasonable posture, since the AS's algorithm is a deployment fact
        # and the client's is a policy choice.
        proof_env = os.getenv("MCP_AUTH_DPOP_ALGORITHMS", "").strip()
        if proof_env:
            proof_algorithms = tuple(a.strip() for a in proof_env.split(",") if a.strip())
            if not proof_algorithms:
                raise VerifierConfigError(
                    "MCP_AUTH_DPOP_ALGORITHMS resolved to an empty list."
                )
            if any(a.lower() == "none" for a in proof_algorithms):
                raise VerifierConfigError(
                    "Algorithm 'none' is never acceptable for DPoP proofs."
                )
        else:
            proof_algorithms = algorithms

        try:
            skew = int(os.getenv("AUTHPLANE_CLOCK_SKEW_SECONDS", "30"))
        except ValueError as exc:
            raise VerifierConfigError("AUTHPLANE_CLOCK_SKEW_SECONDS must be an integer.") from exc
        if skew < 0:
            raise VerifierConfigError("AUTHPLANE_CLOCK_SKEW_SECONDS must not be negative.")
        if skew > 300:
            logger.warning(
                "AUTHPLANE_CLOCK_SKEW_SECONDS=%d is large; it widens the window in which "
                "an expired token is still accepted.",
                skew,
            )

        # Revocation checking. Off by default, and that default is a real
        # trade-off rather than an oversight: a JWT is validated locally, so
        # revoking a token at the authorization server has no effect here until
        # the token expires -- up to an hour with default lifetimes. Turning this
        # on makes every request ask the AS whether the token is still live
        # (RFC 7662 introspection), which restores immediate revocation at the
        # cost of a network round trip per request and a hard dependency on the
        # AS being reachable.
        revocation_check = _flag("MCP_AUTH_REVOCATION_CHECK", False)
        client_id = os.getenv("AUTHPLANE_CLIENT_ID", "").strip()
        client_secret = os.getenv("AUTHPLANE_CLIENT_SECRET", "").strip()
        if revocation_check and not (client_id and client_secret):
            # The introspection endpoint does not accept unauthenticated callers,
            # so without credentials every check would fail -- and with
            # fail-closed semantics that means rejecting every request.
            raise VerifierConfigError(
                "MCP_AUTH_REVOCATION_CHECK=true requires AUTHPLANE_CLIENT_ID and "
                "AUTHPLANE_CLIENT_SECRET: this server must authenticate to the "
                "authorization server's introspection endpoint."
            )
        if not revocation_check:
            logger.info(
                "Revocation checking is off: access tokens remain valid here until "
                "their own expiry, even if revoked at the authorization server. "
                "Set MCP_AUTH_REVOCATION_CHECK=true for immediate revocation."
            )

        # Failure throttling. Off by default (0 = disabled) because the only key
        # available is the socket peer address: behind a reverse proxy every
        # caller shares one bucket, which makes the throttle either useless or a
        # self-inflicted outage. Safe to enable only when you know how the server
        # is exposed. See throttle.py.
        try:
            throttle_failures = int(os.getenv("MCP_AUTH_MAX_AUTH_FAILURES", "0"))
        except ValueError as exc:
            raise VerifierConfigError(
                "MCP_AUTH_MAX_AUTH_FAILURES must be an integer (0 disables throttling)."
            ) from exc
        if throttle_failures < 0:
            raise VerifierConfigError("MCP_AUTH_MAX_AUTH_FAILURES must not be negative.")
        try:
            throttle_window = float(os.getenv("MCP_AUTH_FAILURE_WINDOW_SECONDS", "60"))
        except ValueError as exc:
            raise VerifierConfigError(
                "MCP_AUTH_FAILURE_WINDOW_SECONDS must be a number."
            ) from exc
        if throttle_window <= 0:
            raise VerifierConfigError("MCP_AUTH_FAILURE_WINDOW_SECONDS must be positive.")

        # DPoP (RFC 9449) turns a bearer token into a sender-constrained one: the
        # token is bound to a key the client holds, so a stolen token alone is
        # useless. Three settings rather than a boolean, because the middle one is
        # the only safe way to adopt it:
        #
        #   off       bearer only. A leaked token is usable by anyone.
        #   optional  advertised in the PRM document and verified when a proof is
        #             presented. Clients that support DPoP get the protection;
        #             clients that do not keep working.
        #   required  no proof, no access. Locks out every client without DPoP
        #             support -- which today includes most MCP clients.
        dpop = os.getenv("MCP_AUTH_DPOP", "off").strip().lower()
        if dpop in ("", "false", "0", "no"):
            dpop = "off"
        if dpop in ("true", "1", "yes"):
            dpop = "optional"
        if dpop not in ("off", "optional", "required"):
            raise VerifierConfigError(
                f"MCP_AUTH_DPOP={dpop!r} is not recognised. Use 'off', 'optional', or "
                "'required'. 'optional' is the safe way to adopt it: clients that "
                "support DPoP are protected, clients that do not keep working."
            )
        if dpop == "required":
            logger.warning(
                "MCP_AUTH_DPOP=required: clients that cannot produce a DPoP proof "
                "will be refused. Confirm every client supports RFC 9449 first."
            )

        return cls(
            enabled=True,
            mode=mode,
            dpop=dpop,
            audit=_flag("MCP_AUTH_AUDIT", True),
            audit_file=os.getenv("MCP_AUTH_AUDIT_FILE", "").strip(),
            throttle_failures=throttle_failures,
            throttle_window_seconds=throttle_window,
            revocation_check=revocation_check,
            client_id=client_id,
            client_secret=client_secret,
            issuer=issuer,
            resource=resource,
            scopes=scopes,
            read_scope=read_scope,
            write_scope=write_scope,
            enforce_scopes=_flag("MCP_AUTH_ENFORCE_SCOPES", True),
            bind_session_to_subject=_flag("MCP_AUTH_BIND_SESSION", True),
            allowed_algorithms=algorithms,
            dpop_algorithms=proof_algorithms,
            clock_skew_seconds=skew,
            dev_mode=dev_mode,
            realm=os.getenv("AUTHPLANE_REALM", "mysql_mcp_server").strip() or "mysql_mcp_server",
        )


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
