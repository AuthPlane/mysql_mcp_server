# tests/conftest.py
import pytest
import os
import mysql.connector
from mysql.connector import Error

@pytest.fixture(scope="session")
def mysql_connection():
    """Create a test database connection."""
    try:
        connection = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", "testpassword"),
            database=os.getenv("MYSQL_DATABASE", "test_db")
        )
        
        if connection.is_connected():
            # Create a test table
            cursor = connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_table (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255),
                    value INT
                )
            """)
            connection.commit()
            
            yield connection
            
            # Cleanup
            cursor.execute("DROP TABLE IF EXISTS test_table")
            connection.commit()
            cursor.close()
            connection.close()
            
    except Error as e:
        pytest.fail(f"Failed to connect to MySQL: {e}")

@pytest.fixture(scope="session")
def mysql_cursor(mysql_connection):
    """Create a test cursor."""
    cursor = mysql_connection.cursor()
    yield cursor
    cursor.close()


@pytest.fixture(autouse=True)
def _isolate_auth_env(monkeypatch):
    """Give every test an auth configuration built only from what it sets.

    Importing the server calls ``load_dotenv()``, so a developer's own ``.env``
    becomes part of the environment `AuthSettings.from_env()` reads. The e2e
    fixture already pins the variables where that mattered to it; this does the
    same for the unit tests, which had been inheriting values silently. Two ways
    that bites:

      a test that sets a mode, an issuer and a resource and expects defaults
      elsewhere instead inherits ``MCP_AUTH_REVOCATION_CHECK=true`` and asserts
      against a posture it never asked for;

      a test that deletes ``MCP_OAUTH_CLIENT_ID`` to prove missing credentials
      are refused has the pre-rename ``AUTHPLANE_CLIENT_ID`` supplied to it by
      the compatibility fallback, and stops failing.

    Cleared: this repo's own ``MCP_AUTH_*`` and ``MCP_OAUTH_*`` namespaces, plus
    the pre-rename spellings they replaced. Left alone: ``MYSQL_*``, which the
    database fixtures need, and ``AUTHPLANE_TEST_*``, which is how a live
    authorization server is pointed at the ``live_auth`` tests.

    The compatibility fallback is exercised deliberately, by the tests that set
    a legacy name after this fixture has run.
    """
    legacy: tuple[str, ...] = ()
    try:
        from mysql_mcp_server.auth.settings import RENAMED_ENV_VARS

        legacy = tuple(RENAMED_ENV_VARS.values())
    except Exception:
        # The [auth] extra is optional; without it there is no table to read.
        pass

    for name in list(os.environ):
        if name.startswith(("MCP_AUTH_", "MCP_OAUTH_")):
            monkeypatch.delenv(name, raising=False)
    for name in legacy:
        monkeypatch.delenv(name, raising=False)