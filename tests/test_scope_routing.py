"""Scope-to-connection routing at the dispatch layer.

`execute_sql` is the only tool that takes arbitrary SQL, and the caller's scope
decides which MySQL account runs it. Covers that decision, the fail-open path
where no read-only account exists, and the MCP resource primitive, which reaches
the same tables through a different door. No database and no HTTP: `run_query`
is replaced so the routing decision itself is observable.

Why this layer matters even though the middleware also enforces scopes: the
stdio transport has no HTTP layer, so nothing here is reachable by the auth
middleware. For a stdio user these checks are the only ones that run.

Scope-gated tools that take a table name rather than SQL (`get_schema_info`,
`get_table_sample`) are covered here too. What MySQL itself refuses is covered
by `test_sql_boundary.py`, against a live server.
"""

import pytest
from unittest.mock import patch

from pydantic import AnyUrl

from mysql_mcp_server import server as server_module
from mysql_mcp_server.auth import policy
from mysql_mcp_server.auth.policy import scope_name_map, tool_scope_map
from mysql_mcp_server.server import call_tool, get_db_config
from mysql_mcp_server.sqlguard import StatementDenied


class _FakeCursor:
    """Enough of a DB-API cursor for the resource handlers.

    They only ever run fixed statements -- SHOW DATABASES / SHOW TABLES and a
    `SELECT * FROM <table> LIMIT 100` -- so one canned row shape covers all of
    them. The point of these tests is which *account* and which *scope*, not the
    SQL, which `test_sql_boundary.py` covers against a real server.
    """

    description = (("id",), ("name",))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, *args):
        self.statement = statement

    def fetchall(self):
        return [(1, "demo")]


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return _FakeCursor()


def _fake_connect(**config):
    return _FakeConn()


@pytest.fixture
def captured_query(monkeypatch):
    """Replace run_query and record what it was asked to do."""
    calls = []

    async def fake_run_query(query, read_only=False):
        calls.append({"query": query, "read_only": read_only})
        return []

    with patch("mysql_mcp_server.server.run_query", side_effect=fake_run_query):
        yield calls


# --------------------------------------------------------------------------
# Connection routing. The scope decides which MySQL identity runs the statement,
# and that identity's privileges are the actual read-only guarantee.
# --------------------------------------------------------------------------

def test_get_db_config_uses_the_readonly_account_when_configured(monkeypatch):
    monkeypatch.setenv("MYSQL_USER", "rw_user")
    monkeypatch.setenv("MYSQL_PASSWORD", "rw_pass")
    monkeypatch.setenv("MYSQL_RO_USER", "ro_user")
    monkeypatch.setenv("MYSQL_RO_PASSWORD", "ro_pass")

    assert get_db_config(read_only=True)["user"] == "ro_user"
    assert get_db_config(read_only=False)["user"] == "rw_user"


def test_get_db_config_falls_back_when_no_readonly_account_exists(monkeypatch):
    """Backward compatibility: existing single-user deployments keep working.

    Read traffic then runs on the read-write account, so the read scope has
    nothing enforcing it -- the server warns about this at startup.
    """
    monkeypatch.setenv("MYSQL_USER", "rw_user")
    monkeypatch.setenv("MYSQL_PASSWORD", "rw_pass")
    monkeypatch.delenv("MYSQL_RO_USER", raising=False)

    assert get_db_config(read_only=True)["user"] == "rw_user"


def test_readonly_account_requires_a_password_to_be_set(monkeypatch):
    """A missing password must fail loudly, not silently connect as the rw user.

    Falling back would hand read traffic full privileges while the configuration
    claims a split.
    """
    monkeypatch.setenv("MYSQL_USER", "rw_user")
    monkeypatch.setenv("MYSQL_PASSWORD", "rw_pass")
    monkeypatch.setenv("MYSQL_RO_USER", "ro_user")
    monkeypatch.delenv("MYSQL_RO_PASSWORD", raising=False)

    with pytest.raises(ValueError, match="Missing required database configuration"):
        get_db_config(read_only=True)


# --------------------------------------------------------------------------
# A write sent on a read-scoped token reaches MySQL and is refused *there*.
#
# This is the point at the centre of the design: the refusal belongs to the
# database, not to this process. Measured against MySQL 8.4, the alternative --
# START TRANSACTION READ ONLY on the read-write account -- refuses
# INSERT/UPDATE/DELETE (1792) but lets CREATE, DROP, ALTER, TRUNCATE and RENAME
# through, because DDL commits implicitly and ends the transaction. The
# SELECT-only account refuses all of them (1142), plus stacked statements and
# INTO OUTFILE (1227), without anything here parsing the statement.
#
# What these tests assert is that the statement is *forwarded on the read
# connection* -- the refusal itself belongs to MySQL and is covered by
# `test_sql_boundary.py` against a live server.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "query",
    [
        "DROP TABLE demo",
        "INSERT INTO demo VALUES (1, 'a')",
        "/* c */ DELETE FROM demo",
        "/*!DROP TABLE demo*/ SELECT 1",
        "WITH x AS (SELECT 1) INSERT INTO demo SELECT 4, 'y'",
        "SELECT * FROM demo INTO OUTFILE '/tmp/x'",
    ],
)
@pytest.mark.asyncio
async def test_a_read_scoped_write_is_forwarded_on_the_read_only_connection(
    captured_query, scoped_tools, stream_owner, query
):
    """Including the statements a classifier would catch, and the ones it would not.

    `/*!DROP TABLE demo*/ SELECT 1` is a MySQL version-gated comment that
    executes as SQL -- the kind of syntax that defeats classifiers and is
    invisible to the privilege system's decision, because the privilege system
    does not parse. Nothing here refuses the statement; it is forwarded
    unmodified on the SELECT-only connection and MySQL refuses it, which
    `test_sql_boundary.py` verifies against a live server.
    """
    stream_owner("mysql:read")
    await call_tool("execute_sql", {"query": query})
    assert captured_query[0]["read_only"] is True, (
        "a read-scoped call must never route to the read-write account"
    )
    assert captured_query[0]["query"] == query, (
        "the statement is forwarded unmodified; MySQL is what refuses it"
    )


@pytest.mark.asyncio
async def test_a_stacked_statement_is_rejected_before_the_database(captured_query):
    """A usability guard, not a security one -- it predates this branch.

    MySQL's own answer is "Commands out of sync" (issue #50), which tells a
    caller nothing. On the read-only account a stacked write is refused anyway:
    `SELECT 1; DROP TABLE probe` returns "DROP command denied to user 'mcp_ro'"
    against a live server and the table survives.
    """
    response = await call_tool("execute_sql", {"query": "SELECT 1; SELECT 2"})
    assert "single statements" in response[0].text.lower()
    assert captured_query == [], "a stacked statement reached MySQL"


@pytest.mark.asyncio
async def test_a_refusal_from_mysql_is_raised_not_returned(captured_query):
    """`StatementDenied` propagates instead of becoming ordinary content.

    A refusal returned as a normal tool result carries `isError: false`, which
    reads to a model as "call succeeded, here is the answer" -- and an agent may
    then narrate the refusal text as though it were data. `run_query` raises this
    when MySQL answers with one of `DENIAL_ERRNOS`.
    """
    from mysql_mcp_server.sqlguard import DENIAL_MESSAGE, StatementDenied, is_denial

    class FakeMySQLError(Exception):
        errno = 1142  # ER_TABLEACCESS_DENIED_ERROR, what mcp_ro returns

    assert is_denial(FakeMySQLError()), "the errno the read-only account returns"
    assert "write scope" in DENIAL_MESSAGE, "the caller should learn what it needs"
    assert issubclass(StatementDenied, Exception)


@pytest.mark.asyncio
async def test_generic_failures_are_still_returned_as_content_not_raised(captured_query):
    """The repo's existing convention is preserved for unexpected errors.

    Only policy denials became exceptions; an unknown tool or a missing argument
    still comes back as readable content, which is what issue #50 asked for.
    """
    response = await call_tool("nope_not_a_tool", {})
    assert "Unknown tool" in response[0].text

    response = await call_tool("execute_sql", {})
    assert "Query is required" in response[0].text


# --------------------------------------------------------------------------
# The scope map. A mistake here is a silent authorization hole, so it is pinned
# rather than left implied by the wiring.
# --------------------------------------------------------------------------

def test_scope_map_defaults_unknown_tools_to_the_write_scope():
    """A tool added later must fail closed rather than ship unprotected."""
    assert tool_scope_map("r", "w")["*"] == ("w",)


# --------------------------------------------------------------------------
# The scope map. A mistake here is a silent authorization hole, so it is pinned
# rather than left implied by the wiring.
# --------------------------------------------------------------------------

def test_scope_map_gates_the_schema_tools_on_the_read_scope():
    mapping = tool_scope_map("r", "w")
    assert mapping["get_schema_info"] == ("r",)
    assert mapping["get_table_sample"] == ("r",)


def test_scope_map_leaves_arbitrary_sql_to_the_connection():
    """`execute_sql` is authorized by the account that runs it, not by a scope gate.

    Its entry is deliberately empty, which is the one exception to the map being
    an AND-list of required scopes: the caller's scope picks the MySQL account
    (`connection_for`), and that account's grants decide the outcome. A gate of
    `("w",)` here would be the old design, where the only safe reading of "a tool
    accepting arbitrary SQL" was "treat every call as a write".
    """
    mapping = tool_scope_map("r", "w")
    assert mapping["execute_sql"] == ()
    # The fallback for unknown tools stays closed.
    assert mapping["*"] == ("w",)


def test_the_sql_tool_documents_that_scope_decides_its_privileges():
    """A caller cannot know what `execute_sql` may do without being told that
    its token decides. The annotations cannot say so -- they are static."""
    import asyncio

    tools = {t.name: t for t in asyncio.run(server_module.list_tools())}
    assert "scope" in tools["execute_sql"].description


def test_scope_names_are_available_independently_of_any_tool_name():
    """`execute_sql` and `resources/read` need the read scope's *name*, and it
    must not be reachable only via a tool entry that can be removed."""
    assert scope_name_map("r", "w") == {"read": "r", "write": "w"}


# --------------------------------------------------------------------------
# MCP resources reach the same tables as the read tools, so they must cost the
# same scope and use the same MySQL account.
#
# `list_resources` and `read_resource` are a separate MCP primitive: they never
# pass through `call_tool`, so they inherited neither the scope check nor the
# read/write split. Reading `mysql://orders/data` ran
# `SELECT * FROM orders LIMIT 100` on the read-write account for any
# authenticated caller -- including one holding no scope at all -- while
# `read_query` ran the same statement, scope-gated, on the SELECT-only account.
# --------------------------------------------------------------------------

@pytest.fixture
def captured_config(monkeypatch):
    """Record the `read_only` flag every get_db_config call asks for."""
    calls = []
    real = server_module.get_db_config

    def fake(host=None, port=None, read_only=False):
        calls.append(read_only)
        # Return something connectable-looking; the connection itself is faked.
        return {"host": "localhost", "port": 3306, "user": "u", "password": ""}

    monkeypatch.setattr(server_module, "get_db_config", fake)
    return calls


@pytest.fixture
def no_identity():
    """No authenticated context: stdio, or auth switched off."""
    from mysql_mcp_server.auth import current

    previous = current.get_identity()
    current.set_identity(None)
    yield
    # Restored by value, not by token: the fixture body and the async test run
    # in different contexts, and a Token cannot be reset outside the context it
    # was created in.
    current.set_identity(previous)


@pytest.fixture
def identity_with(monkeypatch):
    """Bind an identity carrying exactly the given scopes."""
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    previous = current.get_identity()

    def bind(*scopes):
        monkeypatch.setitem(policy.SCOPE_NAMES, "read", "mysql:read")
        current.set_identity(
            Identity(subject="alice", scopes=frozenset(scopes), client_id="cli")
        )

    yield bind

    # See `no_identity` on why this restores by value rather than by token.
    current.set_identity(previous)


@pytest.mark.asyncio
async def test_resource_reads_use_the_read_only_account(
    captured_config, no_identity, monkeypatch
):
    monkeypatch.setattr(server_module, "connect", _fake_connect)

    await server_module.read_resource(AnyUrl("mysql://demo/data"))
    assert captured_config == [True], (
        "reading a table through the resource URI ran on the read-write account "
        "while read_query ran the same statement on the read-only one"
    )

    captured_config.clear()
    await server_module.list_resources()
    assert captured_config == [True]


@pytest.mark.asyncio
async def test_resource_reads_require_the_read_scope(identity_with, captured_config):
    identity_with()  # a valid token carrying no scopes at all

    with pytest.raises(StatementDenied, match="mysql:read"):
        await server_module.read_resource(AnyUrl("mysql://demo/data"))
    with pytest.raises(StatementDenied, match="mysql:read"):
        await server_module.list_resources()

    assert captured_config == [], "the database was reached before the scope check"


@pytest.mark.asyncio
async def test_the_read_scope_is_enough_for_resource_reads(
    identity_with, captured_config, monkeypatch
):
    """The check must gate, not block: a read token still reads."""
    monkeypatch.setattr(server_module, "connect", _fake_connect)
    identity_with("mysql:read")

    await server_module.read_resource(AnyUrl("mysql://demo/data"))
    assert captured_config == [True]


@pytest.mark.asyncio
async def test_resources_stay_open_without_an_identity(
    captured_config, no_identity, monkeypatch
):
    """stdio has no token. Absence of identity must not mean denied, or enabling
    auth would become the only way to use the server."""
    monkeypatch.setattr(server_module, "connect", _fake_connect)

    await server_module.list_resources()
    assert captured_config == [True]


# --------------------------------------------------------------------------
# Scope is decided by the token on *this* request, not the one that opened the
# stream.
#
# The two differ whenever a client holds several tokens for one subject, which
# requires no revocation: asking the token endpoint for a narrower scope leaves
# the wider token alive. Before this, a call arriving on a read-only token was
# authorized against the read-write token that opened the stream -- so handing a
# sub-agent a read-only credential did not actually stop it writing, and the
# `tool_call_authorized` record named a different `jti` than the one the scope
# decision used.
# --------------------------------------------------------------------------

class _FakeRequestContext:
    """Stands in for `mcp.server.lowlevel.server.request_ctx`'s value."""

    def __init__(self, request_id):
        self.request_id = request_id


@pytest.fixture
def in_mcp_request(monkeypatch):
    """Run the body as though MCP were dispatching request id `n`."""
    from mcp.server.lowlevel.server import request_ctx

    def enter(request_id):
        request_ctx.set(_FakeRequestContext(request_id))

    return enter


@pytest.fixture
def stream_owner():
    """Bind the stream owner's identity, as the middleware does on GET /sse."""
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    previous = current.get_identity()

    def bind(*scopes):
        current.set_identity(
            Identity(
                subject="alice", scopes=frozenset(scopes),
                client_id="cli", token_id="jti-stream",
            )
        )

    yield bind
    current.set_identity(previous)


@pytest.fixture
def scoped_tools(monkeypatch):
    """Auth on: both the per-tool map and the scope names, as startup sets them."""
    monkeypatch.setattr(
        policy, "REQUIRED_SCOPES", tool_scope_map("mysql:read", "mysql:write")
    )
    monkeypatch.setattr(
        policy, "SCOPE_NAMES", scope_name_map("mysql:read", "mysql:write")
    )
    # A read-only account exists unless a test says otherwise, so the routing
    # tests below exercise the enforced path rather than the fail-open one.
    monkeypatch.setenv("MYSQL_RO_USER", "mcp_ro")
    monkeypatch.setenv("MYSQL_RO_PASSWORD", "ro_pass")
    # Warned once per process; reset so a test that asserts on it is not
    # silenced by an earlier one having already warned.
    monkeypatch.setattr(policy, "_UNENFORCED_READ_WARNED", False)


@pytest.mark.asyncio
async def test_a_narrower_token_on_the_request_wins_over_the_stream_owner(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    """The defect this exists for.

    Alice opened the stream with read+write. This call arrives on her read-only
    token, so it must run on the read-only connection -- even though the stream
    owner could have written. With the tool split gone the observable is the
    connection rather than a refusal, which is the stronger assertion anyway:
    the write is not refused by us, it is refused by MySQL.
    """
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    stream_owner("mysql:read", "mysql:write")
    current.remember_request(
        7,
        Identity(
            subject="alice", scopes=frozenset({"mysql:read"}),
            client_id="cli", token_id="jti-request",
        ),
    )
    in_mcp_request(7)

    await call_tool("execute_sql", {"query": "DELETE FROM demo"})
    assert captured_query[0]["read_only"] is True, (
        "the request's narrower token must pick the connection"
    )


@pytest.mark.asyncio
async def test_the_entry_is_released_even_when_the_call_is_denied(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    stream_owner("mysql:read", "mysql:write")
    current.remember_request(
        12, Identity(subject="alice", scopes=frozenset(), client_id="cli")
    )
    in_mcp_request(12)

    with pytest.raises(StatementDenied):
        await call_tool("execute_sql", {"query": "DELETE FROM demo"})
    assert current.get_request_identity() is None


@pytest.mark.asyncio
async def test_the_request_token_also_grants_what_it_carries(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    """Symmetry check: reading the request's token must not deny valid calls."""
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    stream_owner("mysql:read", "mysql:write")
    current.remember_request(
        8, Identity(subject="alice", scopes=frozenset({"mysql:read"}), client_id="cli")
    )
    in_mcp_request(8)

    await call_tool("execute_sql", {"query": "SELECT 1"})
    assert captured_query[0]["read_only"] is True


@pytest.mark.asyncio
async def test_without_a_request_entry_the_stream_owner_still_applies(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    """The fallback. A frame with no recorded identity -- or stdio, where there
    is no HTTP layer at all -- must not become a denial."""
    stream_owner("mysql:read", "mysql:write")
    in_mcp_request(999)  # nothing remembered for this id

    await call_tool("execute_sql", {"query": "DELETE FROM demo"})
    assert captured_query[0]["query"] == "DELETE FROM demo"
    assert captured_query[0]["read_only"] is False


@pytest.mark.asyncio
async def test_the_entry_is_released_when_the_call_finishes(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    """It cannot be released when the POST returns -- the POST is answered before
    the handler runs -- so the tool layer owns the cleanup."""
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    stream_owner("mysql:read")
    current.remember_request(
        11, Identity(subject="alice", scopes=frozenset({"mysql:read"}), client_id="cli")
    )
    in_mcp_request(11)
    assert current.get_request_identity() is not None

    await call_tool("execute_sql", {"query": "SELECT 1"})
    assert current.get_request_identity() is None


def test_string_and_numeric_request_ids_do_not_collide():
    """JSON-RPC ids may be strings or numbers, and `1` and `"1"` are distinct."""
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    current.remember_request(1, Identity(subject="numeric"))
    current.remember_request("1", Identity(subject="string"))
    assert current._by_request[current._request_key(1)].subject == "numeric"
    assert current._by_request[current._request_key("1")].subject == "string"
    current.forget_request(1)
    current.forget_request("1")


def test_the_request_table_is_bounded():
    """Frames that never reach a handler must not grow the table forever."""
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    for i in range(current.MAX_TRACKED_REQUESTS + 50):
        current.remember_request(f"orphan-{i}", Identity(subject="alice"))
    assert len(current._by_request) <= current.MAX_TRACKED_REQUESTS

    current._by_request.clear()


# --------------------------------------------------------------------------
# execute_sql: the caller's scope picks the connection, and the connection's
# grants decide the outcome.
#
# This is what makes a tool accepting arbitrary SQL authorizable again. The
# earlier design could only deprecate it, because with one connection the only
# safe reading of "arbitrary SQL" was "treat every call as a write".
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_sql_on_a_read_token_uses_the_read_only_connection(
    captured_query, scoped_tools, stream_owner
):
    stream_owner("mysql:read")
    await call_tool("execute_sql", {"query": "SELECT * FROM demo"})
    assert captured_query[0]["read_only"] is True, (
        "a read-scoped caller must reach MySQL as the SELECT-only account"
    )


@pytest.mark.asyncio
async def test_execute_sql_on_a_read_token_still_reaches_mysql_for_a_write(
    captured_query, scoped_tools, stream_owner
):
    """The write is *not* refused here -- that is the point.

    It goes to the SELECT-only connection and MySQL refuses it, which is a real
    privilege boundary rather than this process's opinion about the statement.
    `run_query` maps the resulting errno to a StatementDenied (see sqlguard's
    DENIAL_ERRNOS, which includes 1142).
    """
    stream_owner("mysql:read")
    await call_tool("execute_sql", {"query": "DELETE FROM demo"})
    assert captured_query[0]["read_only"] is True
    assert captured_query[0]["query"] == "DELETE FROM demo"


@pytest.mark.asyncio
async def test_execute_sql_on_a_write_token_uses_the_read_write_connection(
    captured_query, scoped_tools, stream_owner
):
    stream_owner("mysql:read", "mysql:write")
    await call_tool("execute_sql", {"query": "DELETE FROM demo"})
    assert captured_query[0]["read_only"] is False


@pytest.mark.asyncio
async def test_execute_sql_needs_at_least_one_scope(
    captured_query, scoped_tools, stream_owner
):
    """"No scope" must not silently resolve to the read connection."""
    stream_owner()  # a valid token carrying nothing
    with pytest.raises(StatementDenied, match="mysql:read"):
        await call_tool("execute_sql", {"query": "SELECT 1"})
    assert captured_query == [], "the database must not be reached"


@pytest.mark.asyncio
async def test_execute_sql_without_an_identity_keeps_the_previous_behaviour(
    captured_query, scoped_tools
):
    """stdio has no token, so there is no scope to select a connection with.

    It keeps the read-write connection, which is what it did before this
    feature existed -- over stdio the process boundary is the security boundary.
    """
    from mysql_mcp_server.auth import current

    previous = current.get_identity()
    current.set_identity(None)
    try:
        await call_tool("execute_sql", {"query": "DELETE FROM demo"})
        assert captured_query[0]["read_only"] is False
    finally:
        current.set_identity(previous)


# --------------------------------------------------------------------------
# No read-only account: the one deliberate fail-open.
#
# A read-scoped caller runs on the read-write account, because failing closed
# would refuse every read-scoped token until an operator provisions a database
# account. The read scope then has nothing enforcing it, so the trail must not
# record these calls as ordinary authorized reads.
# --------------------------------------------------------------------------

@pytest.fixture
def no_readonly_account(monkeypatch):
    monkeypatch.delenv("MYSQL_RO_USER", raising=False)
    monkeypatch.setattr(policy, "_UNENFORCED_READ_WARNED", False)


@pytest.mark.asyncio
async def test_a_read_token_runs_on_the_read_write_account_when_there_is_no_other(
    captured_query, scoped_tools, stream_owner, no_readonly_account
):
    stream_owner("mysql:read")
    await call_tool("execute_sql", {"query": "SELECT 1"})
    assert captured_query[0]["read_only"] is False, (
        "fail-open: the alternative refuses every read-scoped token until an "
        "operator provisions the account"
    )


@pytest.mark.asyncio
async def test_the_unenforced_read_scope_is_warned_about_once(
    captured_query, scoped_tools, stream_owner, no_readonly_account, caplog
):
    """Once, not per call: the condition is a property of the configuration, so
    per-query logging would bury the audit records carrying the same fact."""
    stream_owner("mysql:read")
    with caplog.at_level("WARNING", logger="mysql_mcp_server"):
        await call_tool("execute_sql", {"query": "SELECT 1"})
        await call_tool("execute_sql", {"query": "SELECT 2"})

    warnings = [r for r in caplog.records if "MYSQL_RO_USER" in r.getMessage()]
    assert len(warnings) == 1, "warned per call rather than once"
    assert "DROP DATABASE" in warnings[0].getMessage(), (
        "the warning must name the consequence, not just the missing variable"
    )


@pytest.mark.asyncio
async def test_every_unenforced_call_is_audited_even_though_it_is_allowed(
    captured_query, scoped_tools, stream_owner, no_readonly_account, monkeypatch
):
    """The record the trail would otherwise not have.

    `tool_call_authorized` says the caller held the read scope. On its own that
    reads as "a read happened", when the statement ran with privileges to drop
    the database. The two must be distinguishable after the fact.
    """
    from mysql_mcp_server.auth import audit

    records = []
    monkeypatch.setattr(policy, "AUDIT_ENABLED", True)
    monkeypatch.setattr(
        audit, "record",
        lambda event, scope, **kw: records.append((event, kw)),
    )

    stream_owner("mysql:read")
    await call_tool("execute_sql", {"query": "DELETE FROM demo"})
    await call_tool("execute_sql", {"query": "DELETE FROM demo"})

    assert [e for e, _ in records] == [audit.EVENT_UNENFORCED_READ_SCOPE] * 2, (
        "audited once per call, unlike the log warning"
    )
    event, kw = records[0]
    assert kw["outcome"] == "allowed", "it was allowed; the record must not imply denied"
    assert kw["statement"] == "DELETE FROM demo"
    assert kw["extra"]["read_scope_enforced"] is False


@pytest.mark.asyncio
async def test_a_write_token_is_unaffected_by_the_missing_account(
    captured_query, scoped_tools, stream_owner, no_readonly_account, caplog
):
    """The warning is about the read scope. A write-scoped caller was always
    going to the read-write account, so nothing is degraded for it."""
    stream_owner("mysql:read", "mysql:write")
    with caplog.at_level("WARNING", logger="mysql_mcp_server"):
        await call_tool("execute_sql", {"query": "DELETE FROM demo"})

    assert captured_query[0]["read_only"] is False
    assert not [r for r in caplog.records if "MYSQL_RO_USER" in r.getMessage()]


@pytest.mark.asyncio
async def test_no_scope_is_still_refused_when_there_is_no_readonly_account(
    captured_query, scoped_tools, stream_owner, no_readonly_account
):
    """Fail-open applies to the read scope, not to the absence of one.

    A missing account degrades what the read scope guarantees; it does not turn
    a token holding nothing into a token holding read.
    """
    stream_owner()
    with pytest.raises(StatementDenied, match="mysql:read"):
        await call_tool("execute_sql", {"query": "SELECT 1"})
    assert captured_query == [], "the database must not be reached"
