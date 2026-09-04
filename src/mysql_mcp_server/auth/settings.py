"""Environment-driven auth configuration.

Every variable lives in this repo's own ``MCP_*`` namespace: ``MCP_AUTH_MODE``
is the on/off switch, and the OAuth parameters an authorization server dictates
are ``MCP_OAUTH_*``. None of those values are provider-specific -- an issuer, a
resource identifier, a signing algorithm and a clock skew are what *any* OAuth
2.1 server hands an operator -- so no provider's name belongs on them.

The ``AUTHPLANE_*`` spellings these names carried during development are still
read as fallbacks, each warning and naming its replacement, so a deployment
configured against a pre-release checkout keeps booting. Authplane remains the
shipped backend, named once in ``build_verifier`` rather than on every setting.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .protocol import VerifierConfigError

logger = logging.getLogger(__name__)

_OFF_VALUES = ("", "none", "off", "false", "0")

# The documented mode name. It says what the mode *is* -- an OAuth 2.1
# protected resource -- rather than which backend implements it, so an operator
# reading it learns the protocol they are turning on.
CANONICAL_MODE = "oauth"
KNOWN_MODES = (CANONICAL_MODE,)

# ``authplane`` was the spelling used during development, from when the only
# backend was also the mode name. Still accepted: it costs one dict entry, and
# the mode is the single value deciding whether this server requires
# authentication at all -- refusing to boot on it would take a protected
# deployment down, and the operator's fastest way back up is a value that boots,
# which may well be ``none``.
_MODE_ALIASES = {"authplane": CANONICAL_MODE}

# Default scope names. Both are configurable because a deployment with an
# existing scope taxonomy should not have to adopt ours.
DEFAULT_READ_SCOPE = "mysql:read"
DEFAULT_WRITE_SCOPE = "mysql:write"


# Keys are the documented names, values the provider-prefixed spelling each
# carried during development; both are read, the documented one winning. Kept
# rather than dropped once the names settled, because the cost of the table is
# this dict and the cost of dropping it is a deployment configured against a
# pre-release checkout that stops booting with no hint why.
RENAMED_ENV_VARS = {
    "MCP_OAUTH_ISSUER": "AUTHPLANE_ISSUER",
    "MCP_OAUTH_RESOURCE": "AUTHPLANE_RESOURCE",
    "MCP_OAUTH_SCOPES": "AUTHPLANE_SCOPES",
    "MCP_OAUTH_CLIENT_ID": "AUTHPLANE_CLIENT_ID",
    "MCP_OAUTH_CLIENT_SECRET": "AUTHPLANE_CLIENT_SECRET",
    "MCP_OAUTH_DEV_MODE": "AUTHPLANE_DEV_MODE",
    "MCP_OAUTH_ALLOWED_ALGORITHMS": "AUTHPLANE_ALLOWED_ALGORITHMS",
    "MCP_OAUTH_CLOCK_SKEW_SECONDS": "AUTHPLANE_CLOCK_SKEW_SECONDS",
    "MCP_OAUTH_REALM": "AUTHPLANE_REALM",
}


def _raw(name: str) -> str | None:
    """Raw value for ``name``, falling back to the spelling it replaced.

    A blank counts as unset for the purpose of the fallback. An operator moving
    to the documented names has both spellings in the environment -- the new one
    empty from a fresh ``.env.example``, the old one carrying the real value --
    and treating the blank as an answer would fail a boot whose configuration is
    sitting right there. Names with no alternative spelling read exactly as
    ``os.getenv``.
    """
    raw = os.getenv(name)
    if raw is not None and raw.strip() != "":
        return raw
    legacy = RENAMED_ENV_VARS.get(name)
    if legacy is None:
        return raw
    legacy_raw = os.getenv(legacy)
    if legacy_raw is None or legacy_raw.strip() == "":
        return raw
    logger.warning(
        "%s has been renamed to %s and is still honoured; the value and its "
        "meaning are unchanged. Rename it to stop seeing this.",
        legacy,
        name,
    )
    return legacy_raw


def _env(name: str, default: str = "") -> str:
    """``os.getenv`` semantics over ``_raw``: a set-but-empty value is the answer."""
    raw = _raw(name)
    return default if raw is None else raw


def auth_enabled_in_env() -> bool:
    """Whether MCP_AUTH_MODE asks for authentication, without validating the rest.

    ``AuthSettings.from_env()`` raises on a half-configured auth setup, which is
    the right behaviour where auth is about to be wired up -- but the startup
    read-path check only needs the yes/no, and must not turn "auth is off" into
    an exception for an operator running stdio with a stray MCP_OAUTH_* variable
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

    Not applied to ``MCP_OAUTH_ISSUER``: the ``iss`` claim's source of truth is
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
        """Canonicalise the resource URI and the mode on *every* construction path.

        ``from_env`` is not the only way settings are built: anything that
        constructs them by hand -- the test harness, an embedding application --
        has the same need, and settings that disagreed with the running server
        about what the audience is would be exactly the kind of mismatch
        ``canonical_resource`` exists to prevent.

        The mode is folded through ``_MODE_ALIASES`` here for the same reason,
        so ``build_verifier`` dispatches on one spelling however the settings
        were built.
        """
        object.__setattr__(self, "resource", canonical_resource(self.resource))
        object.__setattr__(self, "mode", _MODE_ALIASES.get(self.mode, self.mode))

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
        mode = _MODE_ALIASES.get(mode, mode)
        if mode not in KNOWN_MODES:
            raise VerifierConfigError(
                f"MCP_AUTH_MODE={mode!r} is not recognised. "
                f"Supported: {', '.join(KNOWN_MODES)}, or 'none' to disable."
            )

        issuer = _env("MCP_OAUTH_ISSUER", "").strip().rstrip("/")
        resource = canonical_resource(_env("MCP_OAUTH_RESOURCE", "").strip())
        missing = [
            name
            for name, value in (
                ("MCP_OAUTH_ISSUER", issuer),
                ("MCP_OAUTH_RESOURCE", resource),
            )
            if not value
        ]
        if missing:
            raise VerifierConfigError(
                f"MCP_AUTH_MODE={mode} requires {' and '.join(missing)}. "
                "MCP_OAUTH_ISSUER is the authorization server's base URL "
                "(e.g. http://localhost:9000). MCP_OAUTH_RESOURCE is this server's "
                "canonical URI and must equal the token's 'aud' claim byte-for-byte."
            )

        dev_mode = _flag("MCP_OAUTH_DEV_MODE", False)
        if issuer.startswith("http://") and not dev_mode:
            logger.warning(
                "MCP_OAUTH_ISSUER uses http:// (%s). Bearer tokens and JWKS travel "
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

        declared = _env("MCP_OAUTH_SCOPES", "")
        scopes = tuple(s.strip() for s in declared.split(",") if s.strip())
        if not scopes:
            # Advertise what this server actually uses rather than nothing.
            scopes = (read_scope, write_scope)

        algorithms = tuple(
            a.strip()
            for a in _env("MCP_OAUTH_ALLOWED_ALGORITHMS", "ES256,RS256").split(",")
            if a.strip()
        )
        if not algorithms:
            raise VerifierConfigError("MCP_OAUTH_ALLOWED_ALGORITHMS resolved to an empty list.")
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
            skew = int(_env("MCP_OAUTH_CLOCK_SKEW_SECONDS", "30"))
        except ValueError as exc:
            raise VerifierConfigError("MCP_OAUTH_CLOCK_SKEW_SECONDS must be an integer.") from exc
        if skew < 0:
            raise VerifierConfigError("MCP_OAUTH_CLOCK_SKEW_SECONDS must not be negative.")
        if skew > 300:
            logger.warning(
                "MCP_OAUTH_CLOCK_SKEW_SECONDS=%d is large; it widens the window in which "
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
        client_id = _env("MCP_OAUTH_CLIENT_ID", "").strip()
        client_secret = _env("MCP_OAUTH_CLIENT_SECRET", "").strip()
        if revocation_check and not (client_id and client_secret):
            # The introspection endpoint does not accept unauthenticated callers,
            # so without credentials every check would fail -- and with
            # fail-closed semantics that means rejecting every request.
            raise VerifierConfigError(
                "MCP_AUTH_REVOCATION_CHECK=true requires MCP_OAUTH_CLIENT_ID and "
                "MCP_OAUTH_CLIENT_SECRET: this server must authenticate to the "
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
            realm=_env("MCP_OAUTH_REALM", "mysql_mcp_server").strip() or "mysql_mcp_server",
        )


def _flag(name: str, default: bool) -> bool:
    raw = _raw(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
