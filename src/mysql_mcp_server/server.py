import asyncio
import logging
import os
import sys
import re
import socket
import time
import subprocess
import traceback
from contextlib import contextmanager
from typing import List, Optional, Tuple, Any

import anyio
from mysql.connector import connect, Error
from mcp.server import Server
from mcp.types import (
    Resource, Tool, TextContent, ToolAnnotations, ResourceTemplate,
    Prompt, PromptArgument, PromptMessage, GetPromptResult,
)
from pydantic import AnyUrl
from dotenv import load_dotenv

from .auth.current import get_identity as current_identity
from .sqlguard import DENIAL_MESSAGE, Kind, StatementDenied, classify, is_denial

# Load environment variables from .env file if it exists.
# This allows for easy local configuration of database and SSH credentials.
load_dotenv()

# Configure logging to provide visibility into server operations.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mysql_mcp_server")

# System databases that are typically filtered out from resource listings.
SYSTEM_DATABASES = {'information_schema', 'mysql', 'performance_schema', 'sys'}

def validate_identifier(name: str) -> str:
    """
    Validate a MySQL identifier (table or database name) to prevent SQL injection.
    Only allows alphanumeric characters, underscores, and dollar signs.
    """
    if not re.match(r'^[a-zA-Z0-9_$]+$', name):
        raise ValueError(f"Invalid identifier '{name}': only alphanumeric, underscore, and $ are allowed")
    return name

def parse_table_arg(name: str) -> Tuple[Optional[str], str]:
    """Split an optional 'database.table' argument into (db, table) parts, validating each."""
    if "." in name:
        db, tbl = name.split(".", 1)
        return validate_identifier(db), validate_identifier(tbl)
    return None, validate_identifier(name)

@contextmanager
def maybe_ssh_tunnel():
    """
    Context manager that creates an SSH tunnel if MYSQL_SSH_ENABLE is set to true.
    Yields the (host, port) to use for the database connection.
    Contributed by GeorgeLeex (PR #64).
    """
    use_ssh = os.getenv("MYSQL_SSH_ENABLE", "false").lower() == "true"
    if not use_ssh:
        # Default connection parameters if SSH is disabled.
        yield os.getenv("MYSQL_HOST", "localhost"), int(os.getenv("MYSQL_PORT", "3306"))
        return

    # Load SSH configuration from environment variables.
    ssh_host = os.getenv("MYSQL_SSH_HOST")
    ssh_port = int(os.getenv("MYSQL_SSH_PORT", "22"))
    ssh_user = os.getenv("MYSQL_SSH_USER")
    ssh_key = os.getenv("MYSQL_SSH_KEY_PATH")
    remote_host = os.getenv("MYSQL_SSH_REMOTE_HOST", "localhost")
    remote_port = int(os.getenv("MYSQL_SSH_REMOTE_PORT", "3306"))
    local_port = int(os.getenv("MYSQL_LOCAL_PORT", "3330"))

    # Mask SSH key path in logs for security.
    safe_ssh_key = os.path.basename(ssh_key) if ssh_key else None
    logger.info(f"Starting SSH tunnel: {ssh_user}@{ssh_host}:{ssh_port} -> {local_port}:{remote_host}:{remote_port} (key: {safe_ssh_key})")

    # Build the system SSH command for tunneling.
    ssh_cmd = [
        'ssh',
        '-i', ssh_key,
        '-N', # Do not execute a remote command.
        '-o', 'ExitOnForwardFailure=yes', # Exit if tunnel cannot be established.
        '-o', 'BatchMode=yes',            # Non-interactive mode.
        '-L', f'{local_port}:{remote_host}:{remote_port}', # Local port forwarding.
        f'{ssh_user}@{ssh_host}',
        '-p', str(ssh_port)
    ]
    
    try:
        # Start the SSH process in the background.
        ssh_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)  # Give the tunnel a moment to establish.
        
        # Check if process died early.
        if ssh_proc.poll() is not None:
            stderr = ssh_proc.stderr.read().decode()
            raise RuntimeError(f"SSH tunnel process exited prematurely: {stderr}")
            
        yield "127.0.0.1", local_port
    except Exception as e:
        logger.error(f"Error starting SSH tunnel: {e}")
        raise
    finally:
        # Ensure the SSH process is terminated when the context is exited.
        logger.info("Terminating SSH tunnel process.")
        try:
            ssh_proc.terminate()
            ssh_proc.wait(timeout=5)
        except Exception as e:
            logger.error(f"Error terminating SSH tunnel: {e}")

def has_readonly_credentials() -> bool:
    """Whether a separate read-only MySQL account is configured.

    When it is, the read tools connect as that account and MySQL itself refuses
    writes, which is the only read-only guarantee that does not depend on this
    process classifying SQL correctly. Without it, the read path falls back to
    a READ ONLY transaction plus statement classification — weaker, and the
    default only for backward compatibility.
    """
    return bool(os.getenv("MYSQL_RO_USER"))


def get_db_config(host=None, port=None, read_only: bool = False):
    """
    Constructs the database connection configuration dictionary from environment variables.
    Validates that required credentials (USER and PASSWORD) are present.

    With ``read_only=True`` and MYSQL_RO_USER set, connects as the read-only
    account instead. Same host, port, and database — only the identity differs,
    because the privilege set attached to that identity is the control.
    """
    if read_only and has_readonly_credentials():
        user = os.getenv("MYSQL_RO_USER")
        password = os.getenv("MYSQL_RO_PASSWORD")
        if password is None:
            logger.error("MYSQL_RO_USER is set but MYSQL_RO_PASSWORD is not (use an empty string for no password)")
            raise ValueError("Missing required database configuration")
    else:
        user = os.getenv("MYSQL_USER")
        password = os.getenv("MYSQL_PASSWORD")
    database = os.getenv("MYSQL_DATABASE")

    if not user:
        logger.error("Missing required database configuration: MYSQL_USER is required")
        raise ValueError("Missing required database configuration")

    if password is None:
        logger.error("MYSQL_PASSWORD environment variable must be set (can be empty string for no password)")
        raise ValueError("Missing required database configuration")

    config = {
        "host": host or os.getenv("MYSQL_HOST", "localhost"),
        "port": port or int(os.getenv("MYSQL_PORT", "3306")),
        "user": user,
        "password": password,
        "charset": os.getenv("MYSQL_CHARSET", "utf8mb4"),
        "collation": os.getenv("MYSQL_COLLATION", "utf8mb4_unicode_ci"),
        "autocommit": True, # Ensure changes are committed immediately if supported.
        "sql_mode": os.getenv("MYSQL_SQL_MODE", "TRADITIONAL"),
        "connect_timeout": int(os.getenv("MYSQL_CONNECT_TIMEOUT", "10")),
        # Compatibility parameters for older MySQL versions (Issue #31)
        "auth_plugin": os.getenv("MYSQL_AUTH_PLUGIN"),
        "raise_on_warnings": os.getenv("MYSQL_RAISE_ON_WARNINGS", "false").lower() == "true",
    }

    # Remove None values
    config = {k: v for k, v in config.items() if v is not None}

    # Only set use_pure when explicitly requested. Passing use_pure=False
    # explicitly makes the connector raise ImportError if the C extension
    # is unavailable (e.g. built against a newer OpenSSL than the host has);
    # omitting the key lets it fall back to the pure-Python implementation.
    use_pure_env = os.getenv("MYSQL_USE_PURE")
    if use_pure_env is not None:
        config["use_pure"] = use_pure_env.lower() == "true"
    
    # Allow overriding collation/charset to be empty if needed for older versions.
    if config["charset"] == "": del config["charset"]
    if config["collation"] == "": del config["collation"]

    if database:
        config["database"] = database
        logger.info(f"Using default database: {database}")
    else:
        logger.info("No default database specified (multi-database mode).")

    # Configure SSL parameters based on the MYSQL_SSL_MODE environment variable.
    ssl_mode = os.getenv("MYSQL_SSL_MODE", "").upper()
    if ssl_mode == "DISABLED":
        config["ssl_disabled"] = True
    elif ssl_mode == "REQUIRED":
        config["ssl_verify_cert"] = True
    elif ssl_mode == "VERIFY_CA":
        config["ssl_verify_cert"] = True
        ssl_ca = os.getenv("MYSQL_SSL_CA")
        if ssl_ca:
            config["ssl_ca"] = ssl_ca
    elif ssl_mode == "VERIFY_IDENTITY":
        config["ssl_verify_cert"] = True
        config["ssl_verify_identity"] = True
        ssl_ca = os.getenv("MYSQL_SSL_CA")
        if ssl_ca:
            config["ssl_ca"] = ssl_ca

    return config

# Privileges that a read-only account must not hold. Checked at startup rather
# than trusted, because "the operator provisioned it correctly" is the kind of
# assumption that is wrong exactly when it matters.
FORBIDDEN_RO_PRIVILEGES = (
    "ALL PRIVILEGES", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
    "TRUNCATE", "FILE", "GRANT OPTION", "SUPER", "RELOAD", "PROCESS", "SHUTDOWN",
    "REFERENCES", "INDEX", "LOCK TABLES", "EXECUTE",
)


# Tools whose `query` argument must classify as read-only. Enforced inside the
# tool, which is also what covers the stdio transport -- stdio has no HTTP layer,
# so no middleware ever runs for it.
READ_ONLY_TOOLS = ("read_query",)

# Scope required per tool, resolved at import so the tool layer can enforce
# without reaching into auth settings. Populated from the configured scope names
# at startup; the defaults match the documented ones.
REQUIRED_SCOPES: dict = {}


def tool_scope_map(read_scope: str, write_scope: str) -> dict:
    """Which scope each tool requires.

    ``execute_sql`` demands the write scope because it accepts arbitrary SQL:
    granting it under the read scope would authorize ``DROP TABLE`` for a
    read-only caller. The ``"*"`` entry is the fallback for any tool name not
    listed, so a tool added later is refused rather than exposed unprotected.
    """
    return {
        "read_query": (read_scope,),
        "get_schema_info": (read_scope,),
        "get_table_sample": (read_scope,),
        "write_query": (write_scope,),
        "execute_sql": (write_scope,),
        "*": (write_scope,),
    }


def verify_readonly_account() -> list[str]:
    """Check that the read-only account cannot write. Returns a list of problems.

    Runs `SHOW GRANTS FOR CURRENT_USER()` on the read connection, so it reflects
    what MySQL will actually enforce rather than what the configuration intends.
    Returning problems instead of raising lets the caller decide whether a
    misconfiguration is fatal.
    """
    problems: list[str] = []
    if not has_readonly_credentials():
        return problems

    try:
        with maybe_ssh_tunnel() as (host, port):
            config = get_db_config(host, port, read_only=True)
            with connect(**config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
                    grants = [row[0].upper() for row in cursor.fetchall()]
    except Error as exc:
        return [f"could not verify read-only grants: {getattr(exc, 'msg', None) or exc}"]

    for grant in grants:
        # Only the privilege list matters, not the object it applies to: a
        # database name containing the word "INSERT" would otherwise trip this.
        privileges = grant.split(" ON ")[0]
        for privilege in FORBIDDEN_RO_PRIVILEGES:
            if re.search(rf"\b{re.escape(privilege)}\b", privileges):
                problems.append(
                    f"MYSQL_RO_USER holds {privilege}, so the read path is not read-only "
                    f"({grant})"
                )
    return problems


# Create the MCP Server instance.
app = Server("mysql_mcp_server")

@app.list_resources()
async def list_resources() -> list[Resource]:
    """
    Lists available MySQL tables (or databases if no default database is configured) as resources.
    This allows AI agents to discover what data is available.
    """
    def _sync_list():
        with maybe_ssh_tunnel() as (host, port):
            config = get_db_config(host, port)
            try:
                with connect(**config) as conn:
                    with conn.cursor() as cursor:
                        if "database" not in config:
                            # Multi-database mode: list available databases.
                            cursor.execute("SHOW DATABASES")
                            databases = cursor.fetchall()
                            return [
                                Resource(
                                    uri=f"mysql://database/{db[0]}",
                                    name=f"database_{db[0]}",
                                    mimeType="text/plain",
                                    description=f"MySQL database: {db[0]}"
                                )
                                for db in databases if db[0] not in SYSTEM_DATABASES
                            ]
                        else:
                            # Single-database mode: list tables in the configured database.
                            cursor.execute("SHOW TABLES")
                            tables = cursor.fetchall()
                            resources = []
                            for table in tables:
                                resources.append(
                                    Resource(
                                        uri=f"mysql://{table[0]}/data",
                                        name=f"table_{table[0]}",
                                        mimeType="text/plain",
                                        description=f"Data in table: {table[0]}"
                                    )
                                )
                            return resources
            except Error as e:
                error_msg = getattr(e, 'msg', None) or str(e) or 'Unknown MySQL error'
                logger.error(f"Failed to list resources: {error_msg}")
                return []
                
    return await anyio.to_thread.run_sync(_sync_list)

@app.list_resource_templates()
async def list_resource_templates() -> list[ResourceTemplate]:
    """
    Returns available resource templates. Currently returns an empty list,
    but implemented for better compatibility with tools like Visual Studio Code.
    """
    return []

@app.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    """
    Reads the content of a specific table or lists tables within a database based on the provided URI.
    """
    def _sync_read():
        with maybe_ssh_tunnel() as (host, port):
            config = get_db_config(host, port)
            uri_str = str(uri)
            if not uri_str.startswith("mysql://"):
                raise ValueError(f"Invalid URI scheme: {uri_str}")

            parts = uri_str[8:].split('/')

            # Handle requests to list tables in a specific database.
            if len(parts) >= 2 and parts[0] == "database":
                db_name = validate_identifier(parts[1])
                try:
                    with connect(**config) as conn:
                        with conn.cursor() as cursor:
                            cursor.execute(f"USE `{db_name}`")
                            cursor.execute("SHOW TABLES")
                            tables = cursor.fetchall()
                            result = [f"Tables in database '{db_name}':"]
                            result.extend([table[0] for table in tables])
                            return "\n".join(result)
                except Error as e:
                    error_msg = getattr(e, 'msg', None) or str(e) or 'Unknown MySQL error'
                    raise RuntimeError(f"Database error: {error_msg}")

            # Handle requests to read data from a specific table.
            table = validate_identifier(parts[0])
            try:
                with connect(**config) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(f"SELECT * FROM `{table}` LIMIT 100")
                        columns = [desc[0] for desc in cursor.description]
                        rows = cursor.fetchall()
                        # Format output as simple CSV-like text.
                        result = [",".join("" if v is None else str(v) for v in row) for row in rows]
                        return "\n".join([",".join(columns)] + result)
            except Error as e:
                error_msg = getattr(e, 'msg', None) or str(e) or 'Unknown MySQL error'
                raise RuntimeError(f"Database error: {error_msg}")

    return await anyio.to_thread.run_sync(_sync_read)

@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    Defines the tools available to AI agents via this MCP server.
    """
    return [
        Tool(
            name="read_query",
            description=(
                "Run a read-only SQL query (SELECT, SHOW, DESCRIBE, EXPLAIN). "
                "Rejects anything that writes data, changes schema, touches the filesystem, "
                "or takes locks. Supports cross-database queries using database.table notation. "
                "Single statements only — use fully qualified names instead of USE statements. "
                "Prefer this over execute_sql: it cannot modify anything."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "A read-only SQL statement. Single statements only."
                    }
                },
                "required": ["query"]
            },
            annotations=ToolAnnotations(
                title="Read Query",
                readOnlyHint=True,
                destructiveHint=False
            )
        ),
        Tool(
            name="write_query",
            description=(
                "Run a SQL statement that modifies data or schema "
                "(INSERT, UPDATE, DELETE, CREATE, ALTER, DROP). "
                "Single statements only. Use read_query for anything that only reads."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL statement to execute. Single statements only."
                    }
                },
                "required": ["query"]
            },
            annotations=ToolAnnotations(
                title="Write Query",
                readOnlyHint=False,
                destructiveHint=True
            )
        ),
        Tool(
            name="execute_sql",
            description=(
                "DEPRECATED — use read_query or write_query instead. "
                "Executes any single SQL statement, read or write, which makes it impossible "
                "to authorize precisely; it is treated as a write everywhere. "
                "Kept for backward compatibility with existing configurations."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL statement to execute. Single statements only."
                    }
                },
                "required": ["query"]
            },
            annotations=ToolAnnotations(
                title="Execute SQL (deprecated)",
                readOnlyHint=False,
                destructiveHint=True
            )
        ),
        Tool(
            name="get_schema_info",
            description=(
                "Get column metadata for a table or all tables in the configured database: "
                "column names, data types, nullability, default values, and comments. "
                "Call this before querying an unfamiliar table. "
                "Omit table_name to see all tables at once. "
                "Accepts bare table names (uses MYSQL_DATABASE) or database.table for cross-database lookups."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Optional: bare table name, or database.table for a cross-database lookup."
                    }
                }
            },
            annotations=ToolAnnotations(
                title="Get Schema Info",
                readOnlyHint=True,
                destructiveHint=False
            )
        ),
        Tool(
            name="get_table_sample",
            description=(
                "Fetch a small sample of rows from a table to understand its data format and content. "
                "Use alongside get_schema_info before writing complex queries. "
                "Accepts bare table names (uses MYSQL_DATABASE) or database.table for cross-database lookups."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Table to sample. Use database.table notation for cross-database queries."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of rows to return (default 5, max 20)."
                    }
                },
                "required": ["table_name"]
            },
            annotations=ToolAnnotations(
                title="Get Table Sample",
                readOnlyHint=True,
                destructiveHint=False
            )
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """
    Dispatches tool calls from AI agents to the appropriate implementation logic.
    """
    try:
        logger.info(f"Calling tool: {name} with arguments: {arguments}")

        # Scope check. Runs here rather than in the auth middleware because a
        # refusal raised here becomes a JSON-RPC error the client receives: a
        # conforming MCP client ignores the POST's HTTP status and waits on the
        # stream, so an HTTP-only 403 makes it hang. Observed with the official
        # MCP client library.
        #
        # No identity means authorization does not apply -- stdio (no HTTP layer,
        # no token) or auth switched off. It must not mean "denied", or enabling
        # auth would become the only way to use the server.
        identity = current_identity()
        if identity is not None:
            required = REQUIRED_SCOPES.get(name, REQUIRED_SCOPES.get("*", ()))
            missing = [s for s in required if not identity.has_scope(s)]
            if missing:
                logger.info(
                    "Denied %s for %s: missing scope(s) %s",
                    name, identity.describe(), ", ".join(missing),
                )
                raise StatementDenied(
                    f"'{name}' requires the {' '.join(required)} scope. This token "
                    f"grants: {' '.join(sorted(identity.scopes)) or 'nothing'}."
                )

        if name in ("read_query", "write_query", "execute_sql"):
            query = arguments.get("query")
            if not query:
                raise ValueError("Query is required")
            if name == "read_query":
                # Classification runs before the generic single-statement check
                # below, because on the read path a stacked statement is an
                # attempt to smuggle a write past a read-only tool -- a denial,
                # not a usability limitation. classify() detects stacking itself.
                #
                # This is not the security boundary: the read path also connects
                # as the read-only account (or opens a READ ONLY transaction), so
                # a statement that gets past here is still refused by MySQL.
                #
                # Over SSE the auth middleware has already run this same check and
                # answered 403. This copy is what protects the stdio transport,
                # which has no HTTP layer and therefore no middleware.
                verdict = classify(query, read_only=True)
                if verdict.kind is Kind.WRITE or verdict.refusal:
                    raise StatementDenied(
                        f"read_query refused this statement: {verdict.refusal or 'it modifies data'}. "
                        "Use write_query if you intend to modify anything."
                    )
                return await run_query(query, read_only=True)

            if ";" in query.strip().rstrip(";"):
                return [TextContent(type="text", text=(
                    "Only single statements are supported. "
                    "Instead of USE statements, use fully qualified names: database.table"
                ))]

            # write_query and the deprecated execute_sql both run on the
            # read-write connection.
            if name == "execute_sql":
                logger.warning(
                    "execute_sql is deprecated; use read_query for reads and write_query for writes."
                )
            return await run_query(query)

        elif name == "get_schema_info":
            table_name = arguments.get("table_name")
            if table_name:
                db, tbl = parse_table_arg(table_name)
                schema_filter = f"TABLE_SCHEMA = '{db}'" if db else "TABLE_SCHEMA = DATABASE()"
                query = f"SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_COMMENT FROM information_schema.COLUMNS WHERE {schema_filter} AND TABLE_NAME = '{tbl}' ORDER BY ORDINAL_POSITION"
            else:
                query = "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, ORDINAL_POSITION"
            return await run_query(query, read_only=True)

        elif name == "get_table_sample":
            db, tbl = parse_table_arg(arguments.get("table_name"))
            limit = min(arguments.get("limit", 5), 20)
            table_ref = f"`{db}`.`{tbl}`" if db else f"`{tbl}`"
            query = f"SELECT * FROM {table_ref} LIMIT {limit}"
            return await run_query(query, read_only=True)

        else:
            raise ValueError(f"Unknown tool: {name}")
    except StatementDenied as e:
        # Propagate so the MCP layer reports isError: true. Swallowing it into a
        # normal TextContent result -- as the generic handler below does, by
        # design, for unexpected failures -- would present a refusal as a
        # successful answer.
        logger.info("Denied tool call %s: %s", name, e)
        raise
    except Exception as e:
        logger.error(f"Error in call_tool: {str(e)}")
        logger.error(traceback.format_exc())
        # Return the error as a TextContent so the client can display it.
        # This addresses Issue #50 where errors were not being reported clearly.
        return [TextContent(type="text", text=f"Error calling tool {name}: {str(e)}")]

@app.list_prompts()
async def list_prompts() -> list[Prompt]:
    return [
        Prompt(
            name="explore_database",
            description=(
                "Systematically explore the database: discover available tables, "
                "inspect their schemas, sample the data, and summarize what's there."
            ),
            arguments=[]
        ),
        Prompt(
            name="analyze_table",
            description=(
                "Deep-dive into a specific table: retrieve its schema, sample its data, "
                "and suggest useful queries."
            ),
            arguments=[
                PromptArgument(
                    name="table_name",
                    description="Table to analyze. Use database.table notation for cross-database queries.",
                    required=True
                )
            ]
        ),
    ]

@app.get_prompt()
async def get_prompt(name: str, arguments: dict | None) -> GetPromptResult:
    if name == "explore_database":
        return GetPromptResult(
            description="Systematic database exploration workflow",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text=(
                        "Explore this MySQL database systematically:\n\n"
                        "1. Call list_resources to discover available tables "
                        "(or databases when MYSQL_DATABASE is not set).\n"
                        "2. Call get_schema_info with no table_name to see all table structures at once, "
                        "or for each table of interest individually.\n"
                        "3. Call get_table_sample on 2–3 representative tables to understand "
                        "data format and content.\n"
                        "4. Summarize: describe what each table stores, note relationships "
                        "(foreign keys, shared ID columns), and suggest 3–5 queries "
                        "an analyst would find useful."
                    ))
                )
            ]
        )
    elif name == "analyze_table":
        table_name = (arguments or {}).get("table_name", "")
        return GetPromptResult(
            description=f"Analysis workflow for: {table_name}",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text=(
                        f"Analyze the table `{table_name}`:\n\n"
                        f"1. Call get_schema_info with table_name=\"{table_name}\" "
                        "to retrieve column names, types, nullability, and comments.\n"
                        f"2. Call get_table_sample with table_name=\"{table_name}\" "
                        "to see representative rows.\n"
                        "3. Based on the schema and sample, provide:\n"
                        "   - A plain-English description of what this table stores\n"
                        "   - Notable columns (primary keys, foreign keys, important fields)\n"
                        "   - Data quality observations (NULLs, patterns, value ranges)\n"
                        "   - 3–5 example SQL queries useful for analysis"
                    ))
                )
            ]
        )
    else:
        raise ValueError(f"Unknown prompt: {name}")

def get_max_rows() -> int:
    """Row cap for a single result set. 0 disables it.

    Without a cap, one `SELECT * FROM huge_table` materialises the whole table
    in this process and then again as a string. The cap is on rows returned to
    the caller, not on rows the server scans.
    """
    try:
        value = int(os.getenv("MYSQL_MAX_ROWS", "1000"))
    except ValueError:
        logger.warning("MYSQL_MAX_ROWS is not an integer; using 1000.")
        return 1000
    return max(value, 0)


def get_statement_timeout_ms() -> int:
    """Server-side limit on read statements. 0 disables it.

    Applies via `max_execution_time`, which MySQL enforces for SELECT only —
    it is not a general-purpose timeout, and writes are unaffected.
    """
    try:
        return max(int(os.getenv("MYSQL_STATEMENT_TIMEOUT_MS", "30000")), 0)
    except ValueError:
        logger.warning("MYSQL_STATEMENT_TIMEOUT_MS is not an integer; using 30000.")
        return 30000


async def run_query(query: str, read_only: bool = False) -> list[TextContent]:
    """
    A helper function that handles the execution of a SQL query,
    formatting the results based on the query type (SHOW, DESCRIBE, SELECT, or DML).
    Uses anyio.to_thread.run_sync to prevent blocking the async event loop.

    ``read_only=True`` routes to the read-only MySQL account when one is
    configured, and otherwise opens a READ ONLY transaction so the server
    rejects writes that got past classification.
    """
    def _sync_run():
        with maybe_ssh_tunnel() as (host, port):
            config = get_db_config(host, port, read_only=read_only)
            fallback_txn = read_only and not has_readonly_credentials()
            try:
                with connect(**config) as conn:
                    with conn.cursor() as cursor:
                        if read_only:
                            timeout_ms = get_statement_timeout_ms()
                            if timeout_ms:
                                # Session-scoped, so it cannot leak into another
                                # connection; each call opens its own.
                                cursor.execute(f"SET SESSION max_execution_time = {timeout_ms}")
                            if fallback_txn:
                                # Second line of defence when a single account
                                # serves both paths: MySQL raises ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
                                # on any write attempted inside this transaction.
                                cursor.execute("START TRANSACTION READ ONLY")
                        cursor.execute(query)
                        query_upper = query.strip().upper()

                        # Specific handling for 'SHOW TABLES' to provide a cleaner header.
                        if query_upper.startswith("SHOW TABLES"):
                            tables = cursor.fetchall()
                            db_name = config.get("database", "all databases")
                            result = [f"Tables_in_{db_name}"]
                            result.extend([table[0] for table in tables])
                            return [TextContent(type="text", text="\n".join(result))]

                        # Specific handling for inspection queries to format results clearly.
                        elif any(query_upper.startswith(p) for p in ["DESCRIBE ", "DESC ", "SHOW COLUMNS FROM ", "SHOW FIELDS FROM "]):
                            columns = [desc[0] for desc in cursor.description]
                            rows = cursor.fetchall()
                            results = [",".join(columns)]
                            for row in rows:
                                # Convert None values to the string "NULL" for clarity in output.
                                results.append(",".join(str(v) if v is not None else "NULL" for v in row))
                            return [TextContent(type="text", text="\n".join(results))]

                        # Handling for standard result sets (SELECT, etc.).
                        elif cursor.description is not None:
                            columns = [desc[0] for desc in cursor.description]
                            max_rows = get_max_rows()
                            if max_rows:
                                # Fetch one extra row to detect truncation without
                                # pulling the whole result set into memory.
                                rows = cursor.fetchmany(max_rows + 1)
                                truncated = len(rows) > max_rows
                                rows = rows[:max_rows]
                            else:
                                rows = cursor.fetchall()
                                truncated = False
                            if not rows:
                                return [TextContent(type="text", text="Query executed successfully. No results returned.")]
                            # Format rows as CSV-like text.
                            result = [",".join("" if v is None else str(v) for v in row) for row in rows]
                            lines = [",".join(columns)] + result
                            if truncated:
                                # Say so explicitly: a silently truncated result
                                # set reads as a complete answer and an agent will
                                # draw conclusions from it.
                                lines.append(
                                    f"-- truncated at MYSQL_MAX_ROWS={max_rows}; "
                                    "narrow the query or raise the limit"
                                )
                            return [TextContent(type="text", text="\n".join(lines))]

                        # Handling for Data Manipulation Language (DML) queries like INSERT, UPDATE, DELETE.
                        else:
                            conn.commit() # Ensure changes are persistent.
                            return [TextContent(type="text", text=f"Query executed successfully. Rows affected: {cursor.rowcount}")]

            except Error as e:
                # Extract and log specific MySQL error messages.
                error_msg = getattr(e, 'msg', None) or str(e) or 'Unknown MySQL error'
                if is_denial(e):
                    # A policy refusal, not a fault: the caller is told it is not
                    # permitted, but not *which* account was refused. MySQL's own
                    # message names the user and host, which is not the caller's
                    # business. Full detail still goes to the server log.
                    logger.warning(
                        "Denied by MySQL (errno %s): %s", getattr(e, "errno", "?"), error_msg
                    )
                    # Raised, not returned, so the result carries isError: true.
                    raise StatementDenied(DENIAL_MESSAGE) from e
                logger.error(f"Error executing SQL: {error_msg}")
                return [TextContent(type="text", text=f"Error executing query: {error_msg}")]

    return await anyio.to_thread.run_sync(_sync_run)

async def main():
    """
    Main entry point for the MCP server.
    Supports both STDIO (default) and SSE (HTTP) transport modes.
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    if transport == "sse":
        await _run_sse_server()
    else:
        await _run_stdio_server()

async def _run_stdio_server():
    """Runs the server using standard input/output streams."""
    from mcp.server.stdio import stdio_server
    logger.info("Starting MySQL MCP server (STDIO)...")
    async with stdio_server() as (read_stream, write_stream):
        try:
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )
        except Exception as e:
            logger.error(f"Server error: {str(e)}", exc_info=True)
            raise

async def _run_sse_server():
    """
    Runs the server using Server-Sent Events (SSE) over HTTP.
    Requires 'starlette' and 'uvicorn' dependencies.
    """
    try:
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        from starlette.responses import Response
        import uvicorn
    except ImportError:
        logger.error("SSE transport requires additional dependencies. Install with: pip install mysql_mcp_server[sse]")
        raise

    logger.info("Starting MySQL MCP server (SSE)...")

    host = os.getenv("MCP_SSE_HOST", "0.0.0.0")
    port_str = os.getenv("MCP_SSE_PORT") or os.getenv("PORT") or "8000"
    port = int(port_str)

    # Build security settings with DNS rebinding protection.
    # allowed_hosts controls which Host header values are accepted; without this
    # a DNS rebinding attack can relay requests through the victim's browser.
    try:
        from mcp.server.transport_security import TransportSecuritySettings

        allowed_hosts_env = os.getenv("MCP_SSE_ALLOWED_HOSTS", "")
        if allowed_hosts_env:
            allowed_hosts = [h.strip() for h in allowed_hosts_env.split(",") if h.strip()]
        else:
            allowed_hosts = [f"localhost:{port}", f"127.0.0.1:{port}"]
            if host not in ("0.0.0.0", "127.0.0.1", "localhost", "::"):
                allowed_hosts.append(f"{host}:{port}")

        logger.info(
            "SSE DNS rebinding protection enabled. Allowed hosts: %s. "
            "Override with MCP_SSE_ALLOWED_HOSTS (comma-separated).",
            ", ".join(allowed_hosts),
        )
        security_settings = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
        )
    except ImportError:
        logger.warning(
            "mcp.server.transport_security not available (upgrade mcp>=1.9.0 for DNS rebinding protection). "
            "Running without Origin/Host validation."
        )
        security_settings = None

    sse = SseServerTransport("/messages/", security_settings=security_settings) if security_settings is not None else SseServerTransport("/messages/")

    async def handle_sse(request):
        """Handler for the SSE connection endpoint."""
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await app.run(streams[0], streams[1], app.create_initialization_options())
        return Response()

    async def health_check(request):
        """Simple health check endpoint."""
        return Response("MySQL MCP Server is running", media_type="text/plain")

    # Optional OAuth 2.1 authentication. Off unless MCP_AUTH_MODE is set, in
    # which case the routes below gain a middleware and one public discovery
    # route; with it unset nothing here changes.
    from .auth import AuthSettings

    auth_settings = AuthSettings.from_env()
    routes = [
        Route("/", endpoint=health_check),
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ]
    middleware = []
    verifier = None

    if auth_settings.enabled:
        from starlette.middleware import Middleware
        from starlette.responses import JSONResponse

        from .auth import PRM_PATH, AuthMiddleware, build_verifier

        REQUIRED_SCOPES.clear()
        REQUIRED_SCOPES.update(
            tool_scope_map(auth_settings.read_scope, auth_settings.write_scope)
        )

        verifier = await build_verifier(auth_settings)

        failure_throttle = None
        if auth_settings.throttle_failures:
            from .auth.throttle import FailureThrottle

            failure_throttle = FailureThrottle(
                max_failures=auth_settings.throttle_failures,
                window_seconds=auth_settings.throttle_window_seconds,
            )
            logger.info(
                "Throttling clients after %d authentication failures per %.0fs. "
                "Keyed on the socket peer address, so this is only meaningful when "
                "clients connect directly -- behind a proxy every caller shares one bucket.",
                auth_settings.throttle_failures,
                auth_settings.throttle_window_seconds,
            )

        async def protected_resource_metadata(request):
            """RFC 9728 discovery document. Public by necessity: a client
            cannot obtain a token without first reading where to get one."""
            return JSONResponse(verifier.protected_resource_metadata())

        routes.append(Route(PRM_PATH, endpoint=protected_resource_metadata))
        middleware.append(
            Middleware(
                AuthMiddleware,
                verifier=verifier,
                realm=auth_settings.realm,
                tool_scopes=tool_scope_map(
                    auth_settings.read_scope, auth_settings.write_scope
                ),
                read_only_tools=READ_ONLY_TOOLS,
                enforce_scopes=auth_settings.enforce_scopes,
                bind_session_to_subject=auth_settings.bind_session_to_subject,
                audit=auth_settings.audit,
                throttle=failure_throttle,
                resource_url=auth_settings.resource,
                dpop=auth_settings.dpop,
                dpop_algorithms=auth_settings.allowed_algorithms,
            )
        )

        if auth_settings.audit:
            logger.info(
                "Audit records enabled on logger 'mysql_mcp_server.audit' (one JSON "
                "object per line). Each authorized tool call records sub, client_id, "
                "jti, tool and statement -- identity a reverse proxy cannot provide."
            )

        # Report the read-path posture once, at startup. An operator who thinks
        # they are running split read/write privileges but is not should learn
        # it here rather than from an incident.
        if has_readonly_credentials():
            problems = await anyio.to_thread.run_sync(verify_readonly_account)
            if problems:
                for problem in problems:
                    logger.error("Read-only account check failed: %s", problem)
                raise RuntimeError(
                    "MYSQL_RO_USER does not have a read-only privilege set; "
                    "fix the grants or unset MYSQL_RO_USER to fall back to "
                    "READ ONLY transactions."
                )
            logger.info(
                "Read path uses the read-only MySQL account (MYSQL_RO_USER); "
                "writes are refused by the database itself."
            )
        else:
            logger.warning(
                "MYSQL_RO_USER is not set. Read tools fall back to READ ONLY "
                "transactions plus statement classification, which is weaker: "
                "set MYSQL_RO_USER/MYSQL_RO_PASSWORD to a SELECT-only account "
                "so the database enforces the read/write split."
            )

    # Define the Starlette application with SSE routes and a health check.
    starlette_app = Starlette(routes=routes, middleware=middleware)

    # Configure and start the Uvicorn server.
    server_config = uvicorn.Config(starlette_app, host=host, port=port, log_level="info")
    server = uvicorn.Server(server_config)
    try:
        await server.serve()
    finally:
        if verifier is not None:
            await verifier.aclose()

if __name__ == "__main__":
    # Start the asyncio event loop.
    asyncio.run(main())
