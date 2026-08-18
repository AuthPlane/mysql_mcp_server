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
)
from .throttle import FailureThrottle

logger = logging.getLogger(__name__)

PRM_PATH = "/.well-known/oauth-protected-resource"

# Reachable without a token, and both for a reason.
#   "/"  container orchestrators probe it before any credential exists.
#   PRM  a client cannot obtain a token without first discovering where to get
#        one; gating the discovery document deadlocks the handshake.
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


def is_protected(path: str) -> bool:
    """Whether ``path`` requires a token.

    Prefix matching is sound here because Starlette routes on the exact path
    with no dot-segment normalisation: ``/foo/../sse`` does not reach the
    ``/sse`` handler, it 404s. Middleware and router therefore see the same
    string, and there is no path that this function skips but the router
    resolves to a protected endpoint. ``tests/test_auth.py`` pins that
    invariant with raw sockets, because it is an assumption about Starlette's
    behaviour rather than about this code.
    """
    if path in PUBLIC_PATHS:
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
        read_only_tools: Iterable[str] = (),
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
        self.read_only_tools = frozenset(read_only_tools)
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
            url=f"{self.resource_url}{scope.get('path', '')}",
            proof=proof,
        )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or not is_protected(scope.get("path", "")):
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
        except Exception as exc:
            # A verifier that raises something unexpected must still fail
            # closed, and must not leak internals to an unauthenticated caller.
            logger.error("Verifier raised %s: %s", type(exc).__name__, exc)
            if self.throttle is not None:
                self.throttle.record_failure(throttle_key)
            self._audit(
                audit.EVENT_AUTH_FAILED, scope, outcome="denied", reason="verifier error"
            )
            await self._fail(send, 401, "invalid_token", "Token verification failed", scope)
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

        async def sniffing_send(message: Mapping[str, Any]) -> None:
            nonlocal seen
            if not seen and message.get("type") == "http.response.body":
                body = message.get("body", b"") or b""
                session_id = _session_id_from_endpoint_event(body)
                if session_id:
                    seen = True
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
        await self.app(scope, receive, sniffing_send)

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

        # Refuse a write sent to a read-only tool here, while there is still an
        # HTTP response to put a status on. Once the transport answers 202 the
        # tool executes in the *stream's* task, and a refusal can only come back
        # as a JSON-RPC error — correct, but harder for a caller to act on.
        #
        # The same check also runs inside the tool, and must: the stdio
        # transport has no HTTP layer, so this middleware never sees it.
        if (
            call is not None
            and self.read_only_tools
            and self.deny_at_http_layer
            and call.name in self.read_only_tools
        ):
            refusal = self._classify_refusal(call.query)
            if refusal is not None:
                logger.info(
                    "Denied %s: %s called with a non-read statement: %s",
                    identity.describe(),
                    call.name,
                    refusal,
                )
                self._audit(
                    audit.EVENT_DENIED_STATEMENT,
                    scope,
                    identity=identity,
                    tool=call.name,
                    statement=call.query,
                    session_id=session_id,
                    outcome="denied",
                    reason=refusal,
                )
                await self._fail(send, 403, "invalid_request", refusal, scope)
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

        await self.app(scope, _replay_body(body), send)

    @staticmethod
    def _classify_refusal(query: str) -> str | None:
        """Reason to refuse ``query`` on a read-only tool, or None to allow.

        Imported lazily so this module keeps depending on nothing but the
        verifier seam and the standard library.
        """
        if not query:
            return None
        from ..sqlguard import Kind, classify

        verdict = classify(query, read_only=True)
        if verdict.kind is Kind.WRITE or verdict.refusal:
            return verdict.refusal or "This tool accepts read-only statements"
        return None

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
        challenges: list[str] = []
        if self.dpop != "required":
            challenges.append(", ".join([f'Bearer realm="{self.realm}"'] + common))
        if self.dpop != "off":
            dpop_parts = [f'DPoP realm="{self.realm}"'] + common
            if self.dpop_algorithms:
                # RFC 9449 §5.1: tells the client which proof algorithms to sign
                # with, so it does not have to guess and retry.
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
    return ToolCall(name=name, query=query)


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
