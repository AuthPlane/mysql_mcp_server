"""Raw ASGI middleware enforcing authentication and per-tool scopes.

Two structural facts about the legacy SSE transport drive this design, and
neither is obvious from reading the transport's code:

**1. Both endpoints carry traffic.** ``GET /sse`` opens the stream and *hands
the caller its session id in the response body*; ``POST /messages/`` is where
every tool call actually arrives. Protecting only ``/sse`` protects nothing —
a caller can POST straight to ``/messages/`` and never open a stream.

**2. Tool calls do not execute in the request's task.** ``POST /messages/``
writes the JSON-RPC payload into a memory stream; the MCP server consumes it
from the task that is running ``app.run()`` on behalf of the *stream*. So a
``contextvar`` set here never reaches the tool handler — the handler runs in a
different task, belonging to a different request. Per-tool authorization
therefore cannot live in the tool handler, and is done here instead, by
inspecting the JSON-RPC method and tool name in the request body. That keeps
authorization per-request rather than per-session, which is the property you
actually want.

``BaseHTTPMiddleware`` is unusable here: it pumps responses through an internal
queue, which buffers and stalls a long-lived ``text/event-stream`` body.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Mapping

from . import audit, current
from .protocol import (
    AuthenticationError,
    AuthorizationError,
    Identity,
    RequestContext,
    TokenVerifier,
    VerifierUnavailableError,
)
from .throttle import FailureThrottle

logger = logging.getLogger(__name__)

# The well-known path for a resource whose URI has no path component. Correct
# for every deployment at the server root, and the default when no resource URI
# is known -- but it is *not* the path in general. RFC 9728 §3 forms the URL by
# inserting the well-known segment between the host and the resource's path, so
# a resource of `https://host/mysql` is discovered at
# `/.well-known/oauth-protected-resource/mysql`.
#
# Kept as a module constant because the tests and the SSE server both reference
# the root form, but anything that must be right for a path-bearing resource
# derives the value from the verifier instead. See `prm_path_for()`.
PRM_PATH = "/.well-known/oauth-protected-resource"


def prm_path_for(metadata_url: str) -> str:
    """The route path serving the PRM document advertised by ``metadata_url``.

    Derived from the verifier's own `metadata_url()` rather than assumed,
    because that URL is what a 401 sends clients to. Registering the route at a
    fixed `PRM_PATH` while the challenge pointed at the RFC 9728 §3 suffix form
    meant that with `MCP_OAUTH_RESOURCE=https://host/mysql` the challenge named
    `/.well-known/oauth-protected-resource/mysql`, which no route served:
    discovery 404'd with nothing in the log to explain it. Invisible at the root,
    which is every deployment we had run.
    """
    from urllib.parse import urlsplit

    path = urlsplit(metadata_url).path
    return path or PRM_PATH


# Reachable without a token, and both for a reason.
#   "/"  container orchestrators probe it before any credential exists.
#   PRM  a client cannot obtain a token without first discovering where to get
#        one; gating the discovery document deadlocks the handshake.
#
# The PRM entry is per-instance rather than a constant, because the path depends
# on the resource URI. A middleware that kept the root form here while the server
# registered the suffix form would authenticate the discovery route -- the same
# deadlock, arrived at from the other side.
PUBLIC_PATHS = ("/", PRM_PATH)

# Paths carrying MCP traffic. Both, per fact 1 above.
PROTECTED_PREFIXES = ("/sse", "/messages/")

# Cap on a buffered ``POST /messages/`` body. The body must be read in full
# before the tool name can be checked, so an unbounded read would let an
# authenticated caller pin memory. MCP JSON-RPC frames are kilobytes.
MAX_BODY_BYTES = 1 * 1024 * 1024

# Bound on the session -> subject table, so a caller holding one valid token
# cannot grow it without limit by opening streams.
MAX_TRACKED_SESSIONS = 4096


def is_protected(path: str, public_paths: Iterable[str] = PUBLIC_PATHS) -> bool:
    """Whether ``path`` requires a token.

    ``public_paths`` is a parameter because the PRM route moves with the
    resource URI; the default is the root form.

    Prefix matching is sound here because Starlette routes on the exact path
    with no dot-segment normalisation: ``/foo/../sse`` does not reach the
    ``/sse`` handler, it 404s. Middleware and router therefore see the same
    string, and there is no path that this function skips but the router
    resolves to a protected endpoint. ``tests/test_path_normalisation.py`` pins
    that invariant with raw sockets, because it is an assumption about
    Starlette's behaviour rather than about this code.
    """
    if path in tuple(public_paths):
        return False
    return any(path == p.rstrip("/") or path.startswith(p) for p in PROTECTED_PREFIXES)


ACCEPTED_SCHEMES = ("bearer", "dpop")


def bearer_token(
    headers: Iterable[tuple[bytes, bytes]],
) -> tuple[str | None, str, str | None]:
    """Extract the access token from ``Authorization``.

    Returns ``(token, scheme, error)``. The scheme is lowercased and returned
    alongside the token because RFC 9449 §7.1 makes it load-bearing rather than
    decorative: a DPoP-bound token has to arrive under the ``DPoP`` scheme, so
    the caller has to be able to tell which one was used.

    Only this header is consulted. A token in the query string would be copied
    into proxy access logs and ``Referer`` headers, which is why the PRM
    document advertises ``bearer_methods_supported: ["header"]``.

    Two schemes are accepted. RFC 9449 §7.1 requires a DPoP-bound access token to
    be presented as ``Authorization: DPoP <token>``, not as ``Bearer``, so
    refusing that scheme rejects every conforming DPoP client before its proof is
    ever looked at -- which made the DPoP support unusable over HTTP even though
    the proof handling below was correct.

    Accepting ``DPoP`` here does not weaken anything: the scheme only says how
    the token was presented. Whether a proof is required, and whether it matches,
    is decided by the verifier from the token's own ``cnf`` claim.

    ASGI lowercases header names; the scheme is compared case-insensitively per
    RFC 7235 §2.1, so ``BEARER`` and ``bearer`` are both accepted.
    """
    raw: bytes | None = None
    for name, value in headers:
        if name == b"authorization":
            raw = value
            break
    if raw is None:
        return None, "", "Missing Authorization header"
    try:
        decoded = raw.decode("latin-1").strip()
    except UnicodeDecodeError:
        return None, "", "Malformed Authorization header"

    scheme, _, token = decoded.partition(" ")
    normalised = scheme.lower()
    if normalised not in ACCEPTED_SCHEMES:
        safe = "".join(c for c in scheme if c.isprintable())[:20]
        return None, normalised, f"Unsupported authorization scheme {safe!r}; use Bearer or DPoP"
    if not token.strip():
        return None, normalised, "Access token is empty"
    return token.strip(), normalised, None


class SessionBinding:
    """Remembers which subject opened each SSE session.

    Why this exists: authentication is per-request, so without a binding a
    valid token belonging to user B is accepted on a session opened by user A.
    Both requests authenticate correctly in isolation; nothing ties them
    together. On a tool that runs SQL, that is a cross-tenant hole.

    The policy implemented here is *reject the mismatch*: a session belongs to
    the subject that opened it, for its lifetime. The alternative — allowing any
    valid token on any session — is only safe in a single-tenant deployment, so
    it is not the default. Set ``MCP_AUTH_BIND_SESSION=false`` to opt out.
    """

    def __init__(self, limit: int = MAX_TRACKED_SESSIONS) -> None:
        self._subjects: dict[str, str] = {}
        self._limit = limit

    def remember(self, session_id: str, subject: str) -> None:
        if not session_id:
            return
        if len(self._subjects) >= self._limit:
            # Drop the oldest insertion. dicts preserve insertion order, and a
            # dropped entry degrades to "unbound", never to "bound to someone
            # else", so eviction cannot grant access it should not.
            oldest = next(iter(self._subjects), None)
            if oldest is not None:
                self._subjects.pop(oldest, None)
            logger.warning(
                "Session binding table full (%d entries); evicting oldest. "
                "Sessions evicted here are no longer subject-checked.",
                self._limit,
            )
        self._subjects[session_id] = subject

    def owner(self, session_id: str) -> str | None:
        return self._subjects.get(session_id)

    def forget(self, session_id: str) -> None:
        self._subjects.pop(session_id, None)

    def __len__(self) -> int:  # pragma: no cover - diagnostics
        return len(self._subjects)


class AuthMiddleware:
    """Authenticates every MCP request and authorizes tool calls by scope.

    Depends only on ``TokenVerifier``; it never imports or names a specific
    provider.
    """

    def __init__(
        self,
        app: Any,
        *,
        verifier: TokenVerifier,
        realm: str = "mysql_mcp_server",
        tool_scopes: Mapping[str, tuple[str, ...]] | None = None,
        enforce_scopes: bool = True,
        bind_session_to_subject: bool = True,
        audit: bool = True,
        throttle: "FailureThrottle | None" = None,
        resource_url: str = "",
        deny_at_http_layer: bool = False,
        dpop: str = "off",
        dpop_algorithms: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.realm = realm
        # Which challenges to advertise on a 401. A client that cannot see a
        # `DPoP` challenge has no reason to think sender-constrained tokens are
        # accepted here, which in `required` mode leaves it guessing.
        self.dpop = dpop
        self.dpop_algorithms = tuple(dpop_algorithms)
        # Origin this server is reached at, used to reconstruct the URL a DPoP
        # proof is bound to. Falls back to the PRM document's `resource`, which is
        # the same canonical value by definition.
        self.resource_url = (resource_url or "").rstrip("/")
        if not self.resource_url:
            try:
                self.resource_url = str(
                    verifier.protected_resource_metadata().get("resource", "")
                ).rstrip("/")
            except Exception:  # pragma: no cover - defensive
                self.resource_url = ""
        self.tool_scopes = dict(tool_scopes or {})
        self.enforce_scopes = enforce_scopes
        # Whether a scope or statement refusal is answered as an HTTP status here.
        # Off by default: a conforming MCP client ignores the POST's status and
        # waits on the stream, so an HTTP-only denial makes it hang. The tool layer
        # raises instead, producing a JSON-RPC error the client receives. Kept as a
        # switch because the HTTP path is easier to assert against in tests.
        self.deny_at_http_layer = deny_at_http_layer
        self.bind_session_to_subject = bind_session_to_subject
        self.audit = audit
        self.throttle = throttle
        self.sessions = SessionBinding()
        self._metadata_url = verifier.metadata_url()
        # Derived, not assumed: the discovery route has to be public at whatever
        # path the challenge actually names, or a client cannot bootstrap.
        self.public_paths = ("/", prm_path_for(self._metadata_url))

    def _audit(self, event: str, scope: Mapping[str, Any], **fields: Any) -> None:
        if self.audit:
            audit.record(event, scope, **fields)

    def _request_context(self, scope: Mapping[str, Any]) -> RequestContext:
        """Describe this request for sender-constrained token verification.

        The URL is built from the **configured** resource base plus the path, not
        from the ``Host`` header. Two reasons, both load-bearing:

        * ``Host`` is caller-controlled, so deriving the URL a proof is checked
          against from it would let a caller choose what their own proof has to
          match.
        * Behind a proxy the ``Host`` and scheme the server sees differ from what
          the client signed, so every proof would fail.

        The query string is excluded because RFC 9449 §4.2 defines ``htu`` without
        query or fragment — which is fortunate here, since ``/messages/`` carries a
        per-session id that would otherwise change the URL on every request.

        The path comes from ``scope["raw_path"]``, not ``scope["path"]``. ASGI
        populates the latter percent-*decoded*, while the client signs ``htu``
        over the on-wire target: a path containing ``%2F`` would be reconstructed
        here as ``/`` and the proof would fail to match, while verifying fine
        against the TypeScript sibling. The Authplane SDK's own adapter reads
        ``raw_path`` for this reason (``authplane/_dpop_adapter.py``); that
        adapter is Starlette-``Request``-shaped and unusable from raw ASGI, so
        the rule is reproduced rather than imported. Latent while the only paths
        are ``/sse`` and ``/messages/``, but wrong is wrong.
        """
        proof = None
        for name, value in scope.get("headers", []):
            if name == b"dpop":
                try:
                    proof = value.decode("latin-1").strip()
                except UnicodeDecodeError:
                    proof = None
                break
        return RequestContext(
            method=scope.get("method", ""),
            url=f"{self.resource_url}{_raw_path(scope)}",
            proof=proof,
        )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or not is_protected(
            scope.get("path", ""), self.public_paths
        ):
            await self.app(scope, receive, send)
            return

        # A CORS preflight carries no credentials (browsers strip them) and
        # reaches no handler that touches the database, so rejecting it would
        # break browser clients without protecting anything.
        method = scope.get("method", "").upper()
        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        # Throttle check comes before token verification, which is the only
        # ordering that saves anything: the cost being avoided *is* the signature
        # verification.
        throttle_key = ""
        if self.throttle is not None:
            throttle_key = self.throttle.client_key(scope)
            if self.throttle.is_throttled(throttle_key):
                self._audit(
                    audit.EVENT_THROTTLED,
                    scope,
                    outcome="throttled",
                    reason="too many recent authentication failures",
                )
                await self._fail(
                    send,
                    429,
                    "invalid_request",
                    "Too many failed authentication attempts",
                    scope,
                    retry_after=self.throttle.retry_after_seconds(throttle_key),
                )
                return

        request_context = self._request_context(scope)

        token, auth_scheme, header_error = bearer_token(scope.get("headers", []))
        # Recorded before any decision is taken, so a refusal is auditable with
        # the same detail as an acceptance: what scheme was tried, and whether a
        # proof came with it.
        scope["auth_scheme"] = auth_scheme
        scope["auth_dpop_proof"] = request_context.proof is not None
        if header_error is None and request_context.proof and auth_scheme != "dpop":
            # RFC 9449 §7.1: a proof accompanies a DPoP-bound token, and such a
            # token must be presented under the DPoP scheme. Accepting the pair
            # under `Bearer` would let a client present a sender-constrained
            # token as though it were an ordinary one, which is the ambiguity the
            # scheme exists to remove. The binding itself is enforced by the
            # verifier from `cnf.jkt`, so this is about the presentation, not a
            # second line of defence.
            header_error = "A DPoP proof requires the DPoP authorization scheme"
        if header_error is not None:
            if self.throttle is not None:
                self.throttle.record_failure(throttle_key)
            self._audit(
                audit.EVENT_AUTH_FAILED, scope, outcome="denied", reason=header_error
            )
            await self._fail(send, 401, "invalid_request", header_error, scope)
            return

        try:
            identity = await self.verifier.verify(token, request_context)  # type: ignore[arg-type]
        except AuthorizationError as exc:
            logger.info("Authorization refused: %s", exc)
            self._audit(
                audit.EVENT_AUTH_FAILED, scope, outcome="denied", reason="insufficient scope"
            )
            await self._fail(send, 403, exc.error, _safe_description(exc.error), scope)
            return
        except AuthenticationError as exc:
            # The verifier's own message goes to the log, never to the caller: it
            # is written by the provider implementation and can name the issuer,
            # the key id, or other internals. An unauthenticated caller gets a
            # fixed description for the error code instead.
            logger.info("Authentication refused: %s", exc)
            if self.throttle is not None:
                self.throttle.record_failure(throttle_key)
            self._audit(audit.EVENT_AUTH_FAILED, scope, outcome="denied", reason=exc.error)
            await self._fail(send, 401, exc.error, _safe_description(exc.error), scope)
            return
        except VerifierUnavailableError as exc:
            # Validation could not be *attempted*. The request still fails
            # closed, but it fails as a server problem, which is what it is.
            #
            # Two deliberate omissions, both in the client's interest:
            #   * no failure recorded against the throttle -- a client that did
            #     nothing wrong must not be locked out for the duration of the
            #     window once the authorization server comes back;
            #   * no WWW-Authenticate challenge -- the challenge is an
            #     invitation to go get a new token, and a client that accepts it
            #     discards a working one to re-authenticate against a server
            #     that is already down.
            logger.error(
                "Verification unavailable (%d): %s: %s",
                exc.status, type(exc).__name__, exc,
            )
            self._audit(
                audit.EVENT_UNAVAILABLE,
                scope,
                outcome="unavailable",
                reason=exc.error,
            )
            await self._fail(
                send,
                exc.status,
                exc.error,
                _SAFE_DESCRIPTIONS.get(exc.error, "Token verification is unavailable"),
                scope,
                challenge=False,
                retry_after=exc.retry_after,
            )
            return
        except Exception as exc:
            # A verifier that raises something outside the taxonomy is a bug in
            # this server or in the verifier, not a statement about the caller's
            # token. Fail closed, do not leak internals, and do not throttle a
            # caller for our own fault.
            logger.error("Verifier raised %s: %s", type(exc).__name__, exc)
            self._audit(
                audit.EVENT_UNAVAILABLE, scope, outcome="unavailable", reason="verifier error"
            )
            await self._fail(
                send,
                500,
                "server_error",
                "Token verification failed",
                scope,
                challenge=False,
            )
            return

        if self.throttle is not None:
            # A caller that authenticates leaves no penalty behind: a legitimate
            # client that briefly misconfigured itself should recover at once.
            self.throttle.record_success(throttle_key)

        # Available to downstream handlers for audit logging. Note it cannot be
        # read from a tool handler — see the module docstring, fact 2.
        scope["auth_identity"] = identity

        if method == "POST":
            await self._handle_post(scope, receive, send, identity)
            return

        await self._handle_stream(scope, receive, send, identity)

    async def _handle_stream(
        self, scope: dict, receive: Callable, send: Callable, identity: Identity
    ) -> None:
        """Pass a ``GET /sse`` through, recording the session it is granted.

        The session id is minted by the transport and appears only in the
        response body (``event: endpoint``), so the only place to observe it is
        the outbound stream. ``send`` is wrapped just long enough to read it;
        after the id is seen the wrapper stops inspecting and forwards
        untouched, leaving the long-lived stream alone.
        """
        # Bind the identity for the life of this stream. The tool handlers run in
        # this task (see current.py), so this is how per-tool authorization can
        # raise a JSON-RPC error the client actually receives instead of an HTTP
        # status it never reads.
        token = current.set_identity(identity)
        try:
            await self._stream_with_binding(scope, receive, send, identity)
        finally:
            current.reset_identity(token)

    async def _stream_with_binding(
        self, scope: dict, receive: Callable, send: Callable, identity: Identity
    ) -> None:
        seen = False
        bound_session = ""

        async def sniffing_send(message: Mapping[str, Any]) -> None:
            nonlocal seen, bound_session
            if not seen and message.get("type") == "http.response.body":
                body = message.get("body", b"") or b""
                session_id = _session_id_from_endpoint_event(body)
                if session_id:
                    seen = True
                    bound_session = session_id
                    if self.bind_session_to_subject:
                        self.sessions.remember(session_id, identity.subject)
                        logger.debug(
                            "Bound session %s to %s", session_id, identity.describe()
                        )
                    # The only record of a *successful* authentication. Every
                    # other audit event fires on a denial or on a tool call, so
                    # without this the trail shows who was refused and who ran
                    # SQL, but never who merely connected -- and a session id
                    # that appears in later records with no origin.
                    self._audit(
                        audit.EVENT_STREAM_OPENED,
                        scope,
                        identity=identity,
                        session_id=session_id,
                        outcome="authenticated",
                    )
            await send(message)

        # The sniffer runs whether or not binding is on: it is also what
        # observes the session id for the audit record above, and reading one
        # line out of the first body chunk costs nothing on a stream that then
        # runs untouched.
        try:
            await self.app(scope, receive, sniffing_send)
        finally:
            # Release the binding when the stream ends. Without this the table
            # only ever grew, so a long-lived deployment drifted towards the
            # 4,096 cap and then started evicting *live* sessions -- and an
            # evicted session is no longer subject-checked, which is the one
            # outcome this table exists to prevent. The transport drops its own
            # session state at exactly this point (`mcp/server/sse.py`, the
            # `finally` in `connect_sse`), so the two now have the same lifetime.
            if bound_session:
                self.sessions.forget(bound_session)

    async def _handle_post(
        self, scope: dict, receive: Callable, send: Callable, identity: Identity
    ) -> None:
        """Authorize a ``POST /messages/`` by session owner and tool scope."""
        session_id = _query_param(scope.get("query_string", b""), "session_id")

        if self.bind_session_to_subject and session_id:
            owner = self.sessions.owner(session_id)
            if owner is not None and owner != identity.subject:
                # Both tokens are individually valid; only the pairing is wrong.
                logger.warning(
                    "Rejected cross-subject reuse of session %s: opened by %s, "
                    "used by %s",
                    session_id,
                    owner,
                    identity.describe(),
                )
                self._audit(
                    audit.EVENT_DENIED_SESSION,
                    scope,
                    identity=identity,
                    session_id=session_id,
                    outcome="denied",
                    reason=f"session opened by {owner}",
                )
                await self._fail(
                    send,
                    403,
                    "insufficient_scope",
                    "This session belongs to a different subject",
                    scope,
                )
                return

        body, disconnect = await _read_body(receive)
        if disconnect is not None:
            return
        if body is None:
            await self._fail(
                send, 413, "invalid_request", "Request body exceeds the size limit", scope
            )
            return

        call = _tool_call(body)

        if call is not None and self.enforce_scopes and self.deny_at_http_layer:
            required = self.tool_scopes.get(call.name, self.tool_scopes.get("*", ()))
            missing = [s for s in required if not identity.has_scope(s)]
            if missing:
                logger.info(
                    "Denied %s: missing scope(s) %s (granted: %s)",
                    identity.describe(),
                    ", ".join(missing),
                    ", ".join(sorted(identity.scopes)) or "none",
                )
                self._audit(
                    audit.EVENT_DENIED_SCOPE,
                    scope,
                    identity=identity,
                    tool=call.name,
                    statement=call.query,
                    session_id=session_id,
                    outcome="denied",
                    reason=f"missing scope: {' '.join(missing)}",
                )
                await self._fail(
                    send,
                    403,
                    "insufficient_scope",
                    f"Requires scope: {' '.join(required)}",
                    scope,
                    scope_hint=required,
                )
                return

        if call is not None:
            # The auditable event: this subject was permitted to run this
            # statement through this tool. See audit.py on why the *outcome* is
            # not part of the same record.
            self._audit(
                audit.EVENT_AUTHORIZED,
                scope,
                identity=identity,
                tool=call.name,
                statement=call.query,
                session_id=session_id,
                outcome="authorized",
            )

        # Publish this request's identity for the tool layer, keyed on the
        # JSON-RPC id. The handler runs in the *stream's* task and so cannot see
        # anything set here through a contextvar, but it can see the request id --
        # which is what makes the scope check read the token that sent the call
        # rather than the one that opened the stream.
        #
        # Registered before the frame is forwarded, and deliberately *not*
        # cleared when this returns. The POST answers 202 as soon as the
        # transport accepts the frame, which is strictly before the handler that
        # needs this entry has run -- clearing it here would make the lookup miss
        # and silently fall back to the stream owner, i.e. the exact behaviour
        # this replaces, intermittently. The tool layer clears its own entry when
        # the call completes; `remember_request` caps the table for the frames
        # that never reach a handler at all.
        if call is not None and call.request_id is not None:
            current.remember_request(call.request_id, identity)

        await self.app(scope, _replay_body(body), send)

    async def _fail(
        self,
        send: Callable,
        status: int,
        error: str,
        description: str,
        scope: Mapping[str, Any],
        *,
        scope_hint: tuple[str, ...] = (),
        retry_after: int = 0,
        challenge: bool = True,
    ) -> None:
        common = [
            f'error="{error}"',
            f'error_description="{_header_safe(description)}"',
            f'resource_metadata="{self._metadata_url}"',
        ]
        if scope_hint:
            common.append(f'scope="{" ".join(scope_hint)}"')

        # One challenge per acceptable scheme, as separate header values rather
        # than one comma-joined string: a comma is also the separator *inside* a
        # challenge, so two schemes in one value cannot be parsed unambiguously.
        # ``challenge=False`` on a 5xx: nothing is being asserted about the
        # credential, so there is nothing to challenge. RFC 6750 §3 defines the
        # challenge for authentication failures, and emitting one here is
        # precisely what sends a client off to discard a working token and
        # re-authenticate against an authorization server that is already down.
        challenges: list[str] = []
        if challenge:
            if self.dpop != "required":
                challenges.append(", ".join([f'Bearer realm="{self.realm}"'] + common))
            if self.dpop != "off":
                dpop_parts = [f'DPoP realm="{self.realm}"'] + common
                if self.dpop_algorithms:
                    # RFC 9449 §5.1: tells the client which proof algorithms to
                    # sign with, so it does not have to guess and retry.
                    dpop_parts.append(f'algs="{" ".join(self.dpop_algorithms)}"')
                challenges.append(", ".join(dpop_parts))

        logger.info(
            "Rejected %s %s -> %d %s: %s",
            scope.get("method", ""),
            scope.get("path", ""),
            status,
            error,
            description,
        )
        payload = json.dumps({"error": error, "error_description": description}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ]
        headers.extend(
            (b"www-authenticate", challenge.encode("latin-1", "replace"))
            for challenge in challenges
        )
        if retry_after > 0:
            # Tell a legitimate-but-misconfigured client when to come back,
            # rather than leaving it to hammer and stay throttled.
            headers.append((b"retry-after", str(retry_after).encode()))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": payload})


@dataclass(frozen=True)
class ToolCall:
    name: str
    query: str
    # The JSON-RPC id, so the tool layer can find the identity of *this*
    # request's token rather than the stream owner's. `None` for a notification.
    request_id: object = None


def _tool_call(body: bytes) -> ToolCall | None:
    """The tool named by a ``tools/call`` frame, or None if the body is not one.

    A body that cannot be parsed yields None: validating JSON-RPC is the
    transport's job, and an unparseable body cannot name a tool, so nothing
    privileged is reachable through it. The scope check that follows still
    required a valid token to get this far.
    """
    if not body:
        return None
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        return None
    params = payload.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    if not isinstance(name, str):
        return None
    arguments = params.get("arguments")
    query = ""
    if isinstance(arguments, dict):
        candidate = arguments.get("query")
        if isinstance(candidate, str):
            query = candidate
    return ToolCall(name=name, query=query, request_id=payload.get("id"))


# Fixed, caller-safe descriptions per RFC 6750 error code.
#
# Why not the verifier's message: that string is written by a provider
# implementation and may contain the issuer URL, a key id, or internal state. It
# is useful in a log and inappropriate in a response to a caller who has not
# authenticated. These say enough for a legitimate client to act -- retry, refresh,
# or fix its audience -- without describing the server's configuration.
_SAFE_DESCRIPTIONS = {
    "invalid_token": "The access token is missing, expired, or not valid for this resource",
    "invalid_request": "The request is not a valid bearer-token request",
    "insufficient_scope": "The access token does not carry the scope this operation requires",
    "invalid_client": "The access token was not accepted",
    # 5xx. Phrased so a client can tell "come back later, your token is fine"
    # apart from "your token is bad", because the correct reaction differs.
    "temporarily_unavailable": (
        "The authorization server is temporarily unreachable, so this token "
        "could not be validated. Retry; do not discard your token"
    ),
    "server_error": "Token validation failed for an internal reason",
}


def _safe_description(error: str) -> str:
    return _SAFE_DESCRIPTIONS.get(error, "The access token was not accepted")


def _header_safe(text: str) -> str:
    """Strip what would break a quoted-string in a header value.

    RFC 7230 forbids CR/LF in field values; a token-derived string reaching a
    header unescaped is a response-splitting vector, and the double quote would
    terminate the quoted-string early.
    """
    cleaned = "".join(c for c in text if c.isprintable() and c not in '"\\')
    return cleaned[:200]


def _raw_path(scope: Mapping[str, Any]) -> str:
    """The request path as it arrived on the wire, percent-encoding intact.

    ``scope["raw_path"]`` is the ASGI server's copy of the on-wire target and is
    what a DPoP ``htu`` is signed over. It is optional in the ASGI spec, so the
    decoded ``scope["path"]`` is the fallback -- identical for any path with
    nothing to escape, which is every path this server serves today.
    """
    raw = scope.get("raw_path")
    if isinstance(raw, (bytes, bytearray)):
        # `raw_path` may carry the query string on some servers; `htu` excludes
        # it (RFC 9449 §4.2), and on this transport it holds the session id.
        return bytes(raw).partition(b"?")[0].decode("latin-1")
    return str(scope.get("path", ""))


def _query_param(query_string: bytes, key: str) -> str:
    from urllib.parse import parse_qs

    try:
        values = parse_qs(query_string.decode("latin-1")).get(key, [])
    except Exception:  # pragma: no cover - defensive
        return ""
    return values[0] if values else ""


def _session_id_from_endpoint_event(body: bytes) -> str:
    """Pull ``session_id`` out of the transport's ``event: endpoint`` frame."""
    if b"session_id=" not in body:
        return ""
    try:
        text = body.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return ""
    _, _, rest = text.partition("session_id=")
    session_id = ""
    for ch in rest:
        if ch.isalnum() or ch in "-_":
            session_id += ch
        else:
            break
    return session_id


async def _read_body(receive: Callable) -> tuple[bytes | None, Mapping | None]:
    """Buffer the request body. ``(None, None)`` means it exceeded the cap."""
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return b"", message
        chunks.append(message.get("body", b"") or b"")
        total += len(chunks[-1])
        if total > MAX_BODY_BYTES:
            return None, None
        if not message.get("more_body", False):
            break
    return b"".join(chunks), None


def _replay_body(body: bytes) -> Callable[[], Awaitable[Mapping[str, Any]]]:
    """A fresh ``receive`` yielding an already-consumed body exactly once."""
    delivered = False

    async def receive() -> Mapping[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive
