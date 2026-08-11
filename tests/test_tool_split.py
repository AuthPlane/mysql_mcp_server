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

from mysql_mcp_server.server import call_tool, get_db_config, tool_scope_map
from mysql_mcp_server.sqlguard import StatementDenied


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
