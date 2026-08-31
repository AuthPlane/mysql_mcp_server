"""Carries the stream owner's identity into tool handlers.

Why this is possible, when the module docstring in ``middleware.py`` says a
context variable set during ``POST /messages/`` cannot reach a tool handler:

``handle_sse`` awaits ``app.run(...)`` for the whole life of the stream, and the
MCP server dispatches tool calls from inside that await. So the stream's request
and every tool call it carries run in the **same task**. A context variable set by
the middleware before it calls the downstream app is therefore visible in every
tool handler for that stream — for ``GET /sse`` only. The POST's task remains
separate, which is why this holds the identity of the subject that *opened the
stream* rather than the one that sent a particular call.

That distinction is safe precisely because session binding is on by default: a
POST carrying a different subject's token is refused before it reaches the
transport, so the stream owner is the only subject whose calls can arrive. With
``MCP_AUTH_BIND_SESSION=false`` that guarantee is gone, and scope checks then
describe the stream owner rather than the caller — which is why the setting warns.

The reason to bother: a denial raised inside a tool becomes a JSON-RPC error the
client actually receives. A denial returned as an HTTP status from middleware does
not — a conforming MCP client ignores the POST's status code and waits on the
stream for a response that never comes, and hangs. That was observed with the
official MCP client library, not theorised.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .protocol import Identity

_current_identity: ContextVar["Identity | None"] = ContextVar(
    "mysql_mcp_server_current_identity", default=None
)


def set_identity(identity: "Identity | None") -> Token:
    """Bind ``identity`` for the current task. Returns a token for resetting."""
    return _current_identity.set(identity)


def reset_identity(token: Token) -> None:
    _current_identity.reset(token)


def get_identity() -> "Identity | None":
    """The identity to authorize the call in flight against.

    Prefers the identity of the token on the **request** that carried this tool
    call, falling back to the stream owner's.

    Why both. The stream owner's token is bound to this task (see the module
    docstring) and is the only identity available for anything that is not a
    JSON-RPC request. But it is the token that *opened the stream*, not
    necessarily the one that sent this call — and an OAuth client may legitimately
    hold several tokens for the same subject with different scopes, since
    requesting a narrower token needs no revocation of the wider one. Authorizing
    a call against the wider one defeats down-scoping: hand a sub-agent a
    read-only token and it writes anyway, as long as it shares a session with a
    read-write one.

    It also made the audit trail inconsistent with itself. The middleware records
    ``tool_call_authorized`` with the POST's ``jti`` while the scope decision used
    the stream's, so the two fields described different tokens.

    ``None`` means "no authenticated context", which happens legitimately in two
    cases: the stdio transport (no HTTP layer, so no token at all) and auth
    switched off. Callers must treat it as "authorization does not apply here"
    rather than "denied" — otherwise enabling auth would be the only way to use
    the server at all.
    """
    identity = get_request_identity()
    if identity is not None:
        return identity
    return _current_identity.get()


def get_request_identity() -> "Identity | None":
    """The identity of the token on the request carrying the call in flight.

    Resolved through the MCP request id, which is the only thing shared between
    the POST that delivered the frame and the task that executes it. The POST
    writes into a memory stream; the handler runs in the *stream's* task, so no
    contextvar crosses over — but ``mcp.server.lowlevel.server`` sets a
    ``request_ctx`` contextvar in the handler's task, and its ``request_id`` is
    the JSON-RPC ``id`` the middleware already parsed out of the body.

    Returns ``None`` outside a request (stdio, auth off, or a notification with
    no id), and the caller falls back to the stream owner.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
    except ImportError:  # pragma: no cover - mcp is a hard dependency
        return None
    try:
        context = request_ctx.get()
    except LookupError:
        # No MCP request in flight: not an error, just nothing to resolve.
        return None
    return _by_request.get(_request_key(getattr(context, "request_id", None)))


# Identity per in-flight MCP request id, written by the middleware when it parses
# the POST body and cleared by the tool layer when the call completes.
#
# It cannot be cleared when the POST returns: the transport answers 202 as soon
# as it accepts the frame, which is before the handler runs. So the entry has to
# outlive its request, and the table is bounded by a cap instead.
#
# Eviction is safe in the only direction that matters. A missing entry falls back
# to the stream owner, which session binding has already constrained to the same
# subject -- so eviction degrades to the previous behaviour, never to authorizing
# against someone else's token. The cap only has to be larger than the number of
# calls genuinely in flight on one process.
MAX_TRACKED_REQUESTS = 1024

_by_request: dict[str, "Identity"] = {}


def _request_key(request_id: object) -> str:
    """JSON-RPC ids may be strings or numbers; the table keys on one form.

    ``1`` and ``"1"`` are distinct ids per the spec, so the type is kept in the
    key rather than normalised away.
    """
    return f"{type(request_id).__name__}:{request_id}"


def remember_request(request_id: object, identity: "Identity") -> None:
    if request_id is None:
        return
    if len(_by_request) >= MAX_TRACKED_REQUESTS:
        # Oldest first; dicts preserve insertion order. Reached only if frames
        # are arriving that never reach a handler, since a completed call
        # removes its own entry.
        oldest = next(iter(_by_request), None)
        if oldest is not None:
            _by_request.pop(oldest, None)
    _by_request[_request_key(request_id)] = identity


def forget_request(request_id: object) -> None:
    if request_id is None:
        return
    _by_request.pop(_request_key(request_id), None)


def release_request_identity() -> None:
    """Drop the entry for the MCP request in flight, if any.

    Called from the tool layer's ``finally``, which is the first moment at which
    nothing can still need it.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
    except ImportError:  # pragma: no cover - mcp is a hard dependency
        return
    try:
        context = request_ctx.get()
    except LookupError:
        return
    forget_request(getattr(context, "request_id", None))
