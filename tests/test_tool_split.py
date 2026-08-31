"""The read/write tool split at the dispatch layer.

Covers what `call_tool` does with each tool name, and how connections are
routed. No database and no HTTP: `run_query` is replaced so the routing decision
itself is observable.

Why this layer matters even though the middleware also enforces the split: the
stdio transport has no HTTP layer, so nothing here is reachable by the auth
middleware. For a stdio user these checks are the only ones that run.
"""

import pytest
from unittest.mock import patch

from pydantic import AnyUrl

from mysql_mcp_server import server as server_module
from mysql_mcp_server.server import call_tool, get_db_config, tool_scope_map
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

@pytest.mark.asyncio
async def test_read_tools_request_the_read_only_connection(captured_query):
    for tool, args in [
        ("read_query", {"query": "SELECT 1"}),
        ("get_schema_info", {"table_name": "demo"}),
        ("get_table_sample", {"table_name": "demo"}),
    ]:
        captured_query.clear()
        await call_tool(tool, args)
        assert captured_query, f"{tool} did not reach run_query"
        assert captured_query[0]["read_only"] is True, (
            f"{tool} ran on the read-write connection; the read-only account is "
            "what makes the split a guarantee rather than a convention"
        )


@pytest.mark.asyncio
async def test_write_tools_request_the_read_write_connection(captured_query):
    for tool in ("write_query", "execute_sql"):
        captured_query.clear()
        await call_tool(tool, {"query": "INSERT INTO demo VALUES (7, 'g')"})
        assert captured_query[0]["read_only"] is False


def test_get_db_config_uses_the_readonly_account_when_configured(monkeypatch):
    monkeypatch.setenv("MYSQL_USER", "rw_user")
    monkeypatch.setenv("MYSQL_PASSWORD", "rw_pass")
    monkeypatch.setenv("MYSQL_RO_USER", "ro_user")
    monkeypatch.setenv("MYSQL_RO_PASSWORD", "ro_pass")

    assert get_db_config(read_only=True)["user"] == "ro_user"
    assert get_db_config(read_only=False)["user"] == "rw_user"


def test_get_db_config_falls_back_when_no_readonly_account_exists(monkeypatch):
    """Backward compatibility: existing single-user deployments keep working.

    The read path then relies on READ ONLY transactions plus classification,
    which is weaker -- the server warns about this at startup.
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
# A write sent to the read tool is denied, and denied in a way the caller can
# distinguish from a successful answer.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "query",
    [
        "DROP TABLE demo",
        "INSERT INTO demo VALUES (1, 'a')",
        "/* c */ DELETE FROM demo",
        "SELECT 1; DROP TABLE demo",
        "/*!DROP TABLE demo*/ SELECT 1",
        "WITH x AS (SELECT 1) INSERT INTO demo SELECT 4, 'y'",
        "SELECT * FROM demo INTO OUTFILE '/tmp/x'",
        "SELECT LOAD_FILE('/etc/passwd')",
    ],
)
@pytest.mark.asyncio
async def test_read_tool_denies_writes_before_touching_the_database(captured_query, query):
    with pytest.raises(StatementDenied):
        await call_tool("read_query", {"query": query})
    assert captured_query == [], "the statement must not reach MySQL at all"


@pytest.mark.asyncio
async def test_denial_is_raised_so_the_result_is_marked_as_an_error(captured_query):
    """`StatementDenied` propagates instead of becoming ordinary content.

    A refusal returned as a normal tool result carries `isError: false`, which
    reads to a model as "call succeeded, here is the answer" -- and an agent may
    then narrate the refusal text as though it were data.
    """
    with pytest.raises(StatementDenied) as caught:
        await call_tool("read_query", {"query": "DROP TABLE demo"})
    assert "write_query" in str(caught.value), "the caller should learn what to use instead"


@pytest.mark.asyncio
async def test_generic_failures_are_still_returned_as_content_not_raised(captured_query):
    """The repo's existing convention is preserved for unexpected errors.

    Only policy denials became exceptions; an unknown tool or a missing argument
    still comes back as readable content, which is what issue #50 asked for.
    """
    response = await call_tool("nope_not_a_tool", {})
    assert "Unknown tool" in response[0].text

    response = await call_tool("read_query", {})
    assert "Query is required" in response[0].text


@pytest.mark.asyncio
async def test_read_tool_allows_legitimate_reads(captured_query):
    await call_tool("read_query", {"query": "SELECT * FROM demo WHERE id = 1"})
    assert captured_query[0]["query"] == "SELECT * FROM demo WHERE id = 1"
    assert captured_query[0]["read_only"] is True


@pytest.mark.asyncio
async def test_write_tool_is_not_subject_to_read_path_refusals(captured_query):
    """The split must not make writes impossible."""
    await call_tool("write_query", {"query": "DROP TABLE demo"})
    assert captured_query[0]["query"] == "DROP TABLE demo"


@pytest.mark.asyncio
async def test_multi_statement_is_rejected_for_every_query_tool(captured_query):
    for tool in ("read_query", "write_query", "execute_sql"):
        captured_query.clear()
        try:
            response = await call_tool(tool, {"query": "SELECT 1; SELECT 2"})
            assert "single statements" in response[0].text.lower()
        except StatementDenied:
            pass  # read_query refuses it as a denial, which is also correct
        assert captured_query == [], f"{tool} passed a stacked statement to MySQL"


# --------------------------------------------------------------------------
# The scope map. A mistake here is a silent authorization hole, so it is pinned
# rather than left implied by the wiring.
# --------------------------------------------------------------------------

def test_scope_map_assigns_read_scope_only_to_read_tools():
    mapping = tool_scope_map("r", "w")
    assert mapping["read_query"] == ("r",)
    assert mapping["get_schema_info"] == ("r",)
    assert mapping["get_table_sample"] == ("r",)


def test_scope_map_puts_arbitrary_sql_behind_the_write_scope():
    """`execute_sql` accepts any statement, so the read scope must not reach it.

    This is the reason the tool was split: under the read scope it would
    authorize `DROP TABLE` for a read-only caller.
    """
    mapping = tool_scope_map("r", "w")
    assert mapping["execute_sql"] == ("w",)
    assert mapping["write_query"] == ("w",)


def test_scope_map_defaults_unknown_tools_to_the_write_scope():
    """A tool added later must fail closed rather than ship unprotected."""
    assert tool_scope_map("r", "w")["*"] == ("w",)


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
        monkeypatch.setitem(server_module.REQUIRED_SCOPES, "read_query", ("mysql:read",))
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
    monkeypatch.setattr(
        server_module, "REQUIRED_SCOPES", tool_scope_map("mysql:read", "mysql:write")
    )


@pytest.mark.asyncio
async def test_a_narrower_token_on_the_request_wins_over_the_stream_owner(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    """The defect this exists for.

    Alice opened the stream with read+write. This call arrives on her read-only
    token, so the write must be refused -- even though the stream owner could
    have made it.
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

    with pytest.raises(StatementDenied, match="mysql:write"):
        await call_tool("write_query", {"query": "DELETE FROM demo"})
    assert captured_query == [], "the write must not reach MySQL"


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

    await call_tool("read_query", {"query": "SELECT 1"})
    assert captured_query[0]["read_only"] is True


@pytest.mark.asyncio
async def test_without_a_request_entry_the_stream_owner_still_applies(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    """The fallback. A frame with no recorded identity -- or stdio, where there
    is no HTTP layer at all -- must not become a denial."""
    stream_owner("mysql:read", "mysql:write")
    in_mcp_request(999)  # nothing remembered for this id

    await call_tool("write_query", {"query": "DELETE FROM demo"})
    assert captured_query[0]["query"] == "DELETE FROM demo"


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

    await call_tool("read_query", {"query": "SELECT 1"})
    assert current.get_request_identity() is None


@pytest.mark.asyncio
async def test_the_entry_is_released_even_when_the_call_is_denied(
    captured_query, scoped_tools, stream_owner, in_mcp_request
):
    from mysql_mcp_server.auth import current
    from mysql_mcp_server.auth.protocol import Identity

    stream_owner("mysql:read", "mysql:write")
    current.remember_request(
        12, Identity(subject="alice", scopes=frozenset({"mysql:read"}), client_id="cli")
    )
    in_mcp_request(12)

    with pytest.raises(StatementDenied):
        await call_tool("write_query", {"query": "DELETE FROM demo"})
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
