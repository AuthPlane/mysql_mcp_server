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
    """The stream owner's identity, or ``None``.

    ``None`` means "no authenticated context", which happens legitimately in two
    cases: the stdio transport (no HTTP layer, so no token at all) and auth
    switched off. Callers must treat it as "authorization does not apply here"
    rather than "denied" — otherwise enabling auth would be the only way to use
    the server at all.
    """
    return _current_identity.get()
