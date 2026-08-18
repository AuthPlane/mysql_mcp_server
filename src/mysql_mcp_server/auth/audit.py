"""Structured audit records for authenticated MCP traffic.

The point of this file, stated plainly: a reverse proxy with HTTP Basic Auth can
tell you *that* someone authenticated. It cannot tell you **who ran which
statement**, because it has no identity to pass on and no idea what an MCP tool
call is. This server has both, on every request, and writing them down is what
turns "we added auth" into "we can answer who did that".

Records go to the ``mysql_mcp_server.audit`` logger as single-line JSON, so an
operator can route them somewhere durable without touching this code:

    logging.getLogger("mysql_mcp_server.audit").addHandler(my_handler)

One line per event, and never any secrets: no token, no proof, no password. The
token identifier (``jti``) is recorded instead of the token, which is what lets a
specific credential be traced or revoked without the record itself being a
credential.

**Known limitation.** Records are written at the point of *authorization*, not
completion — "subject X was permitted to call write_query with this statement",
not "and it affected 4 rows". On the legacy SSE transport the tool executes in a
different task from the request that authorized it (see ``middleware.py``), so no
identity is available where the outcome is known. Correlating the two would need
a request id threaded through the transport's memory stream, which is not
reachable from here.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Mapping

#: Deliberately a separate logger from the module loggers. Audit records are a
#: different kind of output from diagnostics -- an operator will want them
#: shipped somewhere durable, and probably not interleaved with debug chatter.
audit_logger = logging.getLogger("mysql_mcp_server.audit")

#: Statements are truncated before being recorded. An audit trail should say what
#: was attempted, not archive a caller's data: a 2 MB INSERT would otherwise put
#: the values themselves into the log, which is both a storage problem and a way
#: for data to leak into a system with different access controls than the
#: database it came from.
MAX_STATEMENT_CHARS = 2000

EVENT_AUTHORIZED = "tool_call_authorized"
EVENT_DENIED_SCOPE = "tool_call_denied_scope"
EVENT_DENIED_STATEMENT = "tool_call_denied_statement"
EVENT_DENIED_SESSION = "session_subject_mismatch"
EVENT_AUTH_FAILED = "authentication_failed"
EVENT_STREAM_OPENED = "stream_opened"
EVENT_THROTTLED = "authentication_throttled"


def to_file(path: str) -> None:
    """Also write audit records to ``path``, one JSON object per line.

    Without this the records land on whatever handler the root logger has, which
    in this server means stderr, interleaved with uvicorn's access log and every
    diagnostic. That is fine for a glance and useless for anything else: an
    operator wanting the trail wants *only* the trail, in a file something else
    can read.

    Propagation is left on, so the records still appear on stderr. The file
    handler formats the message alone -- the record is already a complete JSON
    object, and prefixing it with a timestamp and a level would stop it being
    one.
    """
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)


def _client_address(scope: Mapping[str, Any]) -> str:
    """Best-effort peer address.

    Deliberately reports what the socket says and nothing else. ``X-Forwarded-For``
    is caller-controlled and trusting it without a configured proxy allowlist
    would let anyone write any address into the audit trail -- worse than having
    no address, because it looks authoritative.
    """
    client = scope.get("client")
    if isinstance(client, (tuple, list)) and client:
        return str(client[0])
    return ""


def _truncate(statement: str) -> str:
    if len(statement) <= MAX_STATEMENT_CHARS:
        return statement
    return statement[:MAX_STATEMENT_CHARS] + f"... [truncated, {len(statement)} chars]"


def record(
    event: str,
    scope: Mapping[str, Any],
    *,
    identity: Any = None,
    tool: str = "",
    statement: str = "",
    outcome: str = "",
    reason: str = "",
    session_id: str = "",
    extra: Mapping[str, Any] | None = None,
) -> None:
    """Emit one audit record. Never raises.

    Auditing must not be able to break the request it is auditing: a bug here
    would turn a working server into a failing one, and a failure to *log* is
    less bad than a failure to *serve*. It is logged at ERROR level instead, so
    the gap is visible rather than silent.
    """
    try:
        entry: dict[str, Any] = {
            "ts": time.time(),
            "event": event,
            "method": scope.get("method", ""),
            "path": scope.get("path", ""),
            "client": _client_address(scope),
        }
        # How the credential was presented, not just that it was accepted.
        # Written by the middleware onto the ASGI scope as soon as the
        # Authorization header is parsed, so a 401 carries it too. Without this
        # a record cannot distinguish a bearer token from a sender-constrained
        # one -- which makes "is DPoP actually in effect here?" unanswerable
        # from the trail, the one place it should be obvious.
        scheme = scope.get("auth_scheme")
        if scheme:
            entry["scheme"] = scheme
        if "auth_dpop_proof" in scope:
            entry["dpop_proof"] = bool(scope.get("auth_dpop_proof"))
        if identity is not None:
            entry["sub"] = getattr(identity, "subject", "") or ""
            entry["client_id"] = getattr(identity, "client_id", "") or ""
            entry["jti"] = getattr(identity, "token_id", "") or ""
            scopes = getattr(identity, "scopes", None)
            if scopes:
                entry["scopes"] = sorted(scopes)
        if tool:
            entry["tool"] = tool
        if statement:
            entry["statement"] = _truncate(statement)
        if session_id:
            entry["session_id"] = session_id
        if outcome:
            entry["outcome"] = outcome
        if reason:
            entry["reason"] = reason
        if extra:
            entry.update(extra)

        audit_logger.info(json.dumps(entry, default=str, separators=(",", ":")))
    except Exception as exc:  # pragma: no cover - defensive by intent
        logging.getLogger(__name__).error("Failed to write audit record: %s", exc)
