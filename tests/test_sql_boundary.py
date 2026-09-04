"""The real read-only boundary: MySQL's own privilege system.

Every statement here is sent *directly to MySQL* over the read-only connection,
with nothing in this process inspecting it first, and asserted to be refused by
the server.

That is the whole design. No statement classifier stands between a read-scoped
token and `DROP TABLE` -- these assertions are what does, so if they fail there
is nothing behind them.

Requires a live MySQL with two accounts:

    MYSQL_USER / MYSQL_PASSWORD        read-write
    MYSQL_RO_USER / MYSQL_RO_PASSWORD  SELECT only

Skipped when either is unavailable, so the suite still runs without a database.
"""

import os

import pytest
from mysql.connector import Error, connect

from mysql_mcp_server.sqlguard import DENIAL_ERRNOS, is_denial

TABLE = "boundary_probe"


def _config(read_only: bool) -> dict:
    user = os.getenv("MYSQL_RO_USER") if read_only else os.getenv("MYSQL_USER")
    password = os.getenv("MYSQL_RO_PASSWORD") if read_only else os.getenv("MYSQL_PASSWORD")
    return {
        "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": user,
        "password": password,
        "database": os.getenv("MYSQL_DATABASE", "testdb"),
    }


def _available() -> bool:
    if not os.getenv("MYSQL_RO_USER") or not os.getenv("MYSQL_USER"):
        return False
    try:
        with connect(**_config(read_only=True)) as conn:
            return conn.is_connected()
    except Error:
        return False


pytestmark = pytest.mark.skipif(
    not _available(),
    reason="needs a live MySQL plus MYSQL_RO_USER/MYSQL_RO_PASSWORD (a SELECT-only account)",
)


@pytest.fixture(scope="module")
def seeded_table():
    """A table owned by the read-write account, for the read account to fail on."""
    with connect(**_config(read_only=False)) as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE TABLE IF NOT EXISTS {TABLE} (id INT PRIMARY KEY, name VARCHAR(50))")
            cursor.execute(f"REPLACE INTO {TABLE} VALUES (1, 'alpha'), (2, 'beta')")
        conn.commit()
    yield TABLE
    with connect(**_config(read_only=False)) as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {TABLE}")
        conn.commit()


def run_as_readonly(statement: str):
    """Execute on the read-only connection. Returns the exception, or None."""
    try:
        with connect(**_config(read_only=True)) as conn:
            with conn.cursor() as cursor:
                cursor.execute(statement)
                try:
                    cursor.fetchall()
                except Error:
                    pass
        return None
    except Error as exc:
        return exc


# --------------------------------------------------------------------------
# The account must be able to read. A "read-only" account that cannot read is
# a broken deployment, not a secure one.
# --------------------------------------------------------------------------

def test_readonly_account_can_read(seeded_table):
    assert run_as_readonly(f"SELECT * FROM {seeded_table}") is None


def test_readonly_account_can_inspect_schema(seeded_table):
    assert run_as_readonly(f"DESCRIBE {seeded_table}") is None
    assert run_as_readonly("SHOW TABLES") is None


# --------------------------------------------------------------------------
# MySQL refuses every write, regardless of what this process thinks. Nothing in
# this process inspects any of these.
# --------------------------------------------------------------------------

WRITES_THE_DATABASE_MUST_REFUSE = [
    "INSERT INTO {t} VALUES (99, 'x')",
    "UPDATE {t} SET name = 'x' WHERE id = 1",
    "DELETE FROM {t} WHERE id = 1",
    "REPLACE INTO {t} VALUES (1, 'z')",
    "TRUNCATE TABLE {t}",
    "DROP TABLE {t}",
    "ALTER TABLE {t} ADD COLUMN extra INT",
    "CREATE TABLE should_not_exist (id INT)",
    "RENAME TABLE {t} TO {t}_moved",
    "CREATE INDEX idx_probe ON {t} (name)",
]


@pytest.mark.parametrize("template", WRITES_THE_DATABASE_MUST_REFUSE)
def test_database_refuses_writes_from_the_readonly_account(seeded_table, template):
    """Sent straight to MySQL, with no classification in the way.

    This is the assertion that makes the read/write split a guarantee instead of
    a convention.
    """
    statement = template.format(t=seeded_table)
    exc = run_as_readonly(statement)
    assert exc is not None, f"MySQL accepted {statement!r} from the read-only account"
    assert is_denial(exc), (
        f"{statement!r} failed with errno {getattr(exc, 'errno', None)}, which is not a "
        f"privilege denial. Expected one of {sorted(DENIAL_ERRNOS)} -- the statement may "
        "have failed for an unrelated reason, which would not prove anything."
    )


def test_data_is_unchanged_after_every_refused_write(seeded_table):
    """Refusal must mean nothing happened, not that the error came after the write."""
    with connect(**_config(read_only=False)) as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT id, name FROM {seeded_table} ORDER BY id")
            rows = cursor.fetchall()
    assert rows == [(1, "alpha"), (2, "beta")]


# --------------------------------------------------------------------------
# Filesystem reach. A SELECT-only grant permits these statements *syntactically*
# -- they are refused only because the account lacks FILE, which is why the
# grant, and not the syntax, is what these assert.
# --------------------------------------------------------------------------

def test_database_refuses_into_outfile(seeded_table):
    """Writes a file on the database server. Not a table write; a filesystem write."""
    exc = run_as_readonly(f"SELECT * FROM {seeded_table} INTO OUTFILE '/tmp/boundary_probe.csv'")
    assert exc is not None and is_denial(exc)


def test_database_refuses_load_file():
    """Reads a file from the database server and returns it as a value."""
    exc = run_as_readonly("SELECT LOAD_FILE('/etc/passwd')")
    # LOAD_FILE without FILE privilege may be denied outright or return NULL
    # rather than erroring. Either is acceptable; returning file contents is not.
    if exc is None:
        with connect(**_config(read_only=True)) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT LOAD_FILE('/etc/passwd')")
                value = cursor.fetchone()[0]
        assert not value, "LOAD_FILE returned file contents to a read-only account"
    else:
        assert is_denial(exc)


# --------------------------------------------------------------------------
# Resource consumption a SELECT-only grant still permits, and what bounds it.
#
# SLEEP(), BENCHMARK() and GET_LOCK() all run -- they consume rather than
# violate a privilege, so no grant refuses them. SLEEP and BENCHMARK are bounded
# by MYSQL_STATEMENT_TIMEOUT_MS because the consumption *is* the statement.
#
# GET_LOCK is not: a named lock belongs to the MySQL session, so the statement
# timeout cannot release it. What releases it is `run_query` opening its own
# connection per call and closing it on return -- the shape `run_as_readonly`
# reproduces. That makes the per-call connection a security property, and this
# is the test that says so: a pooled or long-lived connection would let a
# read-scoped caller hold a named lock and stall any writer coordinating on it.
# --------------------------------------------------------------------------

def test_a_named_lock_does_not_outlive_the_call_that_took_it():
    """The lock must be gone once the statement's connection closes."""
    lock = "boundary_probe_lock"

    assert run_as_readonly(f"SELECT GET_LOCK('{lock}', 5)") is None, (
        "GET_LOCK is not a privilege violation; a SELECT-only account can call it"
    )

    # Observe from a connection that did not take the lock. IS_USED_LOCK returns
    # the holder's connection id, or NULL when nobody holds it.
    with connect(**_config(read_only=True)) as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT IS_USED_LOCK('{lock}')")
            holder = cursor.fetchone()[0]

    assert holder is None, (
        f"'{lock}' is still held by connection {holder} after the call that took "
        "it returned. A read-scoped caller can now stall any writer coordinating "
        "on that name -- check that run_query still opens and closes its own "
        "connection per call rather than reusing a pooled one."
    )


def test_readonly_account_holds_no_forbidden_privileges():
    """Assert the grant set directly, so a misconfigured account fails loudly.

    Without this, a deployment where both connections point at the same
    privileged user looks identical to a correctly split one until something
    goes wrong.
    """
    from mysql_mcp_server.server import FORBIDDEN_RO_PRIVILEGES

    with connect(**_config(read_only=True)) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
            grants = [row[0].upper() for row in cursor.fetchall()]

    for grant in grants:
        privileges = grant.split(" ON ")[0]
        for privilege in FORBIDDEN_RO_PRIVILEGES:
            assert privilege not in privileges, (
                f"the read-only account holds {privilege}: {grant}"
            )


def test_startup_check_agrees_with_the_database():
    """`verify_readonly_account()` must reach the same verdict as the assertions above."""
    from mysql_mcp_server.server import verify_readonly_account

    assert verify_readonly_account() == []


# --------------------------------------------------------------------------
# Why the account, and not a transaction mode, is the boundary.
#
# These two are the live measurement behind the table in AUTHENTICATION.md. A
# READ ONLY transaction on the read-write account stops DML -- and only DML: the
# DDL cases in WRITES_THE_DATABASE_MUST_REFUSE above commit implicitly and end
# the transaction before they run. Nothing in the server opens such a
# transaction; these record what it would and would not buy.
# --------------------------------------------------------------------------

def test_read_only_transaction_refuses_dml_on_a_privileged_account(seeded_table):
    """DML is refused, which is the half a read-only transaction does cover.

    Runs as the *read-write* account, so the transaction mode is the only thing
    doing any work. Contrast the DDL cases, which it lets through -- that gap is
    why the read path connects as a `SELECT`-only account instead.
    """
    try:
        with connect(**_config(read_only=False)) as conn:
            with conn.cursor() as cursor:
                cursor.execute("START TRANSACTION READ ONLY")
                with pytest.raises(Error) as caught:
                    cursor.execute(f"INSERT INTO {seeded_table} VALUES (98, 'nope')")
                cursor.execute("ROLLBACK")
        assert caught.value.errno == 1792, (
            f"expected ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION, got {caught.value.errno}"
        )
        # Deliberately not asserted through `is_denial`: 1792 is not in
        # DENIAL_ERRNOS, because no code path opens a read-only transaction and
        # so nothing can raise it. This asserts MySQL's behaviour, not ours.
    finally:
        with connect(**_config(read_only=False)) as conn:
            with conn.cursor() as cursor:
                cursor.execute(f"DELETE FROM {seeded_table} WHERE id = 98")
            conn.commit()


def test_read_only_transaction_does_not_block_reads(seeded_table):
    with connect(**_config(read_only=False)) as conn:
        with conn.cursor() as cursor:
            cursor.execute("START TRANSACTION READ ONLY")
            cursor.execute(f"SELECT COUNT(*) FROM {seeded_table}")
            assert cursor.fetchone()[0] >= 2
            cursor.execute("ROLLBACK")


# --------------------------------------------------------------------------
# What the caller is told when the database refuses.
# --------------------------------------------------------------------------

def test_denial_errnos_are_classified_as_denials_not_faults():
    """Denial vs fault is decided by errno, not by message text.

    Message wording changes across MySQL versions and locales; errnos do not.
    """
    class FakeError:
        def __init__(self, errno):
            self.errno = errno

    for errno in DENIAL_ERRNOS:
        assert is_denial(FakeError(errno))
    for errno in (1064, 2003, 2013, 1146, 0):
        assert not is_denial(FakeError(errno)), (
            f"errno {errno} is a fault, not a policy denial; treating it as a denial "
            "would hide real breakage behind a permissions message"
        )


def test_mysql_denial_message_names_the_account_which_is_why_we_replace_it(seeded_table):
    """Documents the information-disclosure this code deliberately suppresses.

    MySQL's own text includes the user and host. If that string were forwarded to
    the caller, an unauthorized client would learn the database account name.
    """
    exc = run_as_readonly(f"DROP TABLE {seeded_table}")
    assert exc is not None
    raw = (getattr(exc, "msg", None) or str(exc))
    assert "@" in raw, "if MySQL stopped leaking user@host, the suppression could be revisited"

    from mysql_mcp_server.sqlguard import DENIAL_MESSAGE

    assert "@" not in DENIAL_MESSAGE
    assert os.getenv("MYSQL_RO_USER", "\0") not in DENIAL_MESSAGE


# --------------------------------------------------------------------------
# Two defects found by running the server rather than by any assertion below.
# Both needed a live MySQL to surface: the mocked cursors in test_server.py and
# test_formatting.py cannot reproduce either.
# --------------------------------------------------------------------------

def test_a_capped_result_set_returns_rows_instead_of_failing():
    """`MYSQL_MAX_ROWS` truncates rather than failing on the case it exists for.

    `fetchmany(max_rows + 1)` leaves the rest of the result set on the
    connection, and mysql-connector raises "Unread result found" when a cursor
    with pending rows is closed -- so a query that hits the cap must have its
    remainder drained, or it fails outright instead of returning a truncated
    answer. A query under the cap never exercises this.
    """
    import asyncio

    from mysql_mcp_server.server import run_query

    query = (
        "SELECT a.ORDINAL_POSITION FROM information_schema.columns a "
        "CROSS JOIN information_schema.columns b LIMIT 1500"
    )
    result = asyncio.run(run_query(query, read_only=True))
    body = result[0].text
    assert "Unread result found" not in body, "the cap must not turn into a failure"
    lines = body.splitlines()
    assert lines[-1].startswith("-- truncated at MYSQL_MAX_ROWS="), lines[-1]
    # header + capped rows + the truncation notice
    assert len(lines) == 1 + 1000 + 1, len(lines)


def test_rejected_server_credentials_are_not_reported_as_a_scope_problem():
    """`1045` reads like the other access-denied errnos and is not one of them.

    MySQL raises it when *credentials* are rejected, at connect time, with
    nothing to do with the statement. While it sat in `DENIAL_ERRNOS`, a wrong
    `MYSQL_PASSWORD` reached the caller as "this statement is not permitted ...
    a token carrying the write scope is required" -- pointing at an
    authorization problem that does not exist while never mentioning the real
    one. Its text also names the account and the host, which the caller cannot
    act on.
    """
    import asyncio

    from mysql_mcp_server import server as server_module
    from mysql_mcp_server.sqlguard import (
        CONNECT_DENIED_MESSAGE, DENIAL_ERRNOS, is_connect_denial,
    )

    assert 1045 not in DENIAL_ERRNOS, "1045 is a connection fault, not a refusal"

    class Rejected(Exception):
        errno = 1045
        msg = "Access denied for user 'mcp'@'10.0.0.1' (using password: YES)"

    assert is_connect_denial(Rejected())

    real_config = server_module.get_db_config

    def wrong_password(host=None, port=None, read_only=False):
        config = real_config(host, port, read_only=read_only)
        config["password"] = "definitely-not-the-password"
        return config

    server_module.get_db_config = wrong_password
    try:
        result = asyncio.run(server_module.run_query("SELECT 1", read_only=True))
    finally:
        server_module.get_db_config = real_config

    body = result[0].text
    assert body == CONNECT_DENIED_MESSAGE
    assert "@" not in body, "the account and host must not reach the caller"
    assert "scope" not in body.lower(), "there is no scope that fixes a bad password"
