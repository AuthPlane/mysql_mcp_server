"""The authorization policy: which scope a tool needs, which connection it gets.

Everything here is behaviour this fork adds. It lives in the auth package rather
than in ``server.py`` for two reasons:

* **It is one subsystem, not scattered rules.** "Which scope does this tool
  need", "which MySQL account does that scope reach", and "what does the trail
  record when either answer is a refusal" are the same decision seen from three
  angles, and they were three unrelated-looking blocks between the connection
  helpers and the tool handlers.
* **It keeps ``server.py`` reviewable.** The upstream file is a MySQL tool
  server; the smaller its diff, the easier it is to see that this fork does not
  change what a call does, only who is allowed to make it. What is left there
  are call-outs to this module.

No optional dependency is imported here, so the base install is unaffected --
the same property the rest of this package has.

**The scope names are kept by role, not by tool.** ``REQUIRED_SCOPES`` answers
"which scope does *this tool name* need"; ``connection_for`` and
``require_read_scope`` need "what is the read scope called", which is a different
question and has an answer even where no tool by that name exists. Deriving one
from the other couples them to a tool name, and a missing key in that map fails
*open*: an empty required-scope tuple means every check passes.
"""

from __future__ import annotations

import logging

from . import audit
from ..sqlguard import StatementDenied

logger = logging.getLogger("mysql_mcp_server")

#: Scope required per tool name. Empty means authentication is off.
REQUIRED_SCOPES: dict = {}

#: The configured scope names by role: ``{"read": ..., "write": ...}``.
#: Empty means authentication is off, exactly as an empty REQUIRED_SCOPES does.
SCOPE_NAMES: dict = {}

#: Whether this layer writes audit records. Set at startup alongside the maps,
#: for the same reason: the tool layer enforces authorization but has no access
#: to auth settings, and it must not start auditing merely because an identity
#: happens to be present.
AUDIT_ENABLED = False


def tool_scope_map(read_scope: str, write_scope: str) -> dict:
    """Which scope each tool requires.

    ``execute_sql`` is deliberately empty, and is the one entry that is not an
    AND-list of required scopes. It accepts arbitrary SQL, so it is authorized by
    *which database account runs it* rather than by a scope gate here: a caller
    holding only the read scope gets the SELECT-only connection and MySQL refuses
    anything else. ``connection_for()`` makes that choice and denies a caller
    holding neither scope, which is why this entry being empty is not a hole.

    The ``"*"`` entry is the fallback for any tool name not listed, so a tool
    added later is refused rather than exposed unprotected.
    """
    return {
        "get_schema_info": (read_scope,),
        "get_table_sample": (read_scope,),
        "execute_sql": (),
        "*": (write_scope,),
    }


def scope_name_map(read_scope: str, write_scope: str) -> dict:
    """The configured scope names by role. Populates ``SCOPE_NAMES``."""
    return {"read": read_scope, "write": write_scope}


def configure(read_scope: str, write_scope: str, *, audit_enabled: bool) -> None:
    """Install the policy for a run. Called once, from the SSE startup path.

    Mutates the module-level maps rather than replacing them so that a caller
    holding a reference -- ``server.py`` does -- sees the configured values.
    """
    REQUIRED_SCOPES.clear()
    REQUIRED_SCOPES.update(tool_scope_map(read_scope, write_scope))
    SCOPE_NAMES.clear()
    SCOPE_NAMES.update(scope_name_map(read_scope, write_scope))
    global AUDIT_ENABLED
    AUDIT_ENABLED = audit_enabled
    reset_warnings()


def record_denial(event: str, identity, tool: str, arguments: dict, reason: str) -> None:
    """Audit a tool call this layer refused.

    The middleware records ``tool_call_authorized`` once a request clears
    authentication and the HTTP-layer checks, but the per-tool decisions happen
    *here* -- and until now a refusal left no audit record at all, only a log
    line. The trail therefore said "authorized" for calls that were then refused
    on scope, which is the one direction an audit trail must never err in.
    Observed three separate times against a real client before this was added.

    No ASGI scope is available in this task, so ``method``, ``path`` and
    ``client`` are absent from these records rather than guessed. The stream's
    own request carries them, and it is already audited as ``stream_opened``;
    the ``session_id`` there is what ties the two together.
    """
    if not AUDIT_ENABLED:
        return
    statement = ""
    if isinstance(arguments, dict):
        candidate = arguments.get("query")
        if isinstance(candidate, str):
            statement = candidate
    audit.record(
        event,
        {},
        identity=identity,
        tool=tool,
        statement=statement,
        outcome="denied",
        reason=reason,
    )


def missing_scopes(identity, tool: str) -> list[str]:
    """Which required scopes this identity lacks for ``tool``. Empty if none.

    ``identity is None`` yields nothing missing: authorization does not apply --
    stdio has no HTTP layer and therefore no token, and auth may be switched off.
    Treating that as a denial would make enabling auth the only way to use the
    server.
    """
    if identity is None:
        return []
    required = REQUIRED_SCOPES.get(tool, REQUIRED_SCOPES.get("*", ()))
    return [s for s in required if not identity.has_scope(s)]


def scope_denial(identity, tool: str, missing: list[str]) -> StatementDenied:
    """The refusal for a tool whose scope gate the caller did not clear."""
    required = REQUIRED_SCOPES.get(tool, REQUIRED_SCOPES.get("*", ()))
    logger.info(
        "Denied %s for %s: missing scope(s) %s",
        tool, identity.describe(), ", ".join(missing),
    )
    return StatementDenied(
        f"'{tool}' requires the {' '.join(required)} scope. This token "
        f"grants: {' '.join(sorted(identity.scopes)) or 'nothing'}."
    )


def require_read_scope(operation: str, identity) -> None:
    """Refuse ``operation`` unless the caller holds the read scope.

    MCP exposes data through two independent primitives, and both reach the same
    tables: ``tools/call`` (``execute_sql``, ``get_table_sample``) and
    ``resources/read`` (``mysql://<table>/data``). Only the first goes through
    ``call_tool``, so without this the resource primitive is a way to read any
    table while holding neither scope -- authenticated, but not authorized.
    Reading a table must cost the same scope whichever door is used.

    ``None`` means authorization does not apply, exactly as in ``missing_scopes``.
    """
    if identity is None:
        return
    read_scope = SCOPE_NAMES.get("read", "")
    if not read_scope:
        # Scope names not populated: auth is off. Same reasoning as identity None.
        return
    if identity.has_scope(read_scope):
        return
    logger.info(
        "Denied %s for %s: missing scope %s",
        operation, identity.describe(), read_scope,
    )
    record_denial(
        audit.EVENT_DENIED_SCOPE, identity, operation, {}, "missing read scope"
    )
    raise StatementDenied(
        f"{operation} requires the {read_scope} scope. This token "
        f"grants: {' '.join(sorted(identity.scopes)) or 'nothing'}."
    )


# Whether the "read scope ran with write privileges" warning has already been
# logged. The condition is a property of the *configuration*, not of the call, so
# it is identical for every request and logging it per query would bury the audit
# records that carry the same fact. Logged once; audited every time.
_UNENFORCED_READ_WARNED = False


def reset_warnings() -> None:
    """Forget the once-per-process warnings. For startup and for tests."""
    global _UNENFORCED_READ_WARNED
    _UNENFORCED_READ_WARNED = False


def _warn_unenforced_read_once() -> None:
    global _UNENFORCED_READ_WARNED
    if _UNENFORCED_READ_WARNED:
        return
    _UNENFORCED_READ_WARNED = True
    logger.warning(
        "A caller holding only the %s scope ran SQL on the read-write account, "
        "because MYSQL_RO_USER is not configured. The read scope is not being "
        "enforced against the database for these calls -- a DROP DATABASE from a "
        "read-scoped token would succeed. Each such call is audited as %s. "
        "Configure the read-only account to close this: CREATE USER "
        "'mcp_ro'@'%%' IDENTIFIED BY '<password>'; GRANT SELECT ON <database>.* "
        "TO 'mcp_ro'@'%%';",
        SCOPE_NAMES.get("read", "read"),
        audit.EVENT_UNENFORCED_READ_SCOPE,
    )


def connection_for(
    identity,
    *,
    readonly_available: bool,
    tool: str = "execute_sql",
    statement: str = "",
) -> bool:
    """Which connection an arbitrary-SQL call runs on. Returns ``read_only``.

    The scope on the caller's token picks the MySQL account, and the account's
    grants are what actually enforce the split -- so a tool that accepts
    arbitrary SQL can still be authorized precisely, without this process having
    to understand the statement. That is the reverse of classifying SQL and
    hoping the classifier is complete.

    * write scope -> the read-write account.
    * read scope only -> the SELECT-only account.
    * read scope only, no read-only account -> the read-write account, warned
      once and audited per call. The one deliberate fail-open: failing closed
      would refuse every read-scoped token until an operator provisions the
      account. The read scope then has nothing enforcing it, so it must not pass
      silently.
    * neither -> refused, because "no scope" must not silently resolve to the
      read connection.

    ``readonly_available`` is passed in rather than read from the environment
    here: how the database credentials are discovered belongs to the caller, and
    this module should not have to import the connection layer to make a policy
    decision.

    ``identity is None`` means authorization does not apply -- stdio, or auth
    switched off. It keeps the read-write connection, which is the behaviour that
    predates this feature; over stdio the process boundary is the security
    boundary.
    """
    if identity is None:
        return False

    read_scope = SCOPE_NAMES.get("read", "")
    write_scope = SCOPE_NAMES.get("write", "")

    if not read_scope and not write_scope:
        # Scope names not populated: auth is off. Same reasoning as identity None.
        return False

    if write_scope and identity.has_scope(write_scope):
        return False

    if read_scope and identity.has_scope(read_scope):
        if readonly_available:
            return True
        # Fail-open. Loud in the log once, and in the audit trail every time:
        # the trail must not record this as an ordinary authorized read when the
        # statement ran with write privileges.
        _warn_unenforced_read_once()
        if AUDIT_ENABLED:
            audit.record(
                audit.EVENT_UNENFORCED_READ_SCOPE,
                {},
                identity=identity,
                tool=tool,
                statement=statement,
                outcome="allowed",
                reason=(
                    "no MYSQL_RO_USER configured; read scope ran on the "
                    "read-write account"
                ),
                extra={"connection": "read-write", "read_scope_enforced": False},
            )
        return False

    raise StatementDenied(
        f"'{tool}' requires the "
        f"{' or '.join(sorted({s for s in (read_scope, write_scope) if s}))} scope. "
        f"This token grants: {' '.join(sorted(identity.scopes)) or 'nothing'}."
    )
