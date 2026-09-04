[![Tests](https://github.com/designcomputer/mysql_mcp_server/actions/workflows/test.yml/badge.svg)](https://github.com/designcomputer/mysql_mcp_server/actions)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mysql-mcp-server)](https://pypi.org/project/mysql-mcp-server/)
[![AgentAudit Safe](https://img.shields.io/badge/AgentAudit-safe-brightgreen)](https://www.agentaudit.dev/packages/mysql-mcp-server)
# MySQL MCP Server
A Model Context Protocol (MCP) implementation that enables secure interaction with MySQL databases. This server component facilitates communication between AI applications (hosts/clients) and MySQL databases, making database exploration and analysis safer and more structured through a controlled interface.

> **Note**: MySQL MCP Server supports both standard input/output (STDIO) and Streamable HTTP (SSE) transport modes. The SSE mode is recommended for remote/self-hosted deployments.

## Deployment options
- **Hosted** — [Fronteir AI](https://fronteir.ai/mcp/designcomputer-mysql-mcp-server) runs the server for you; no local setup required.
- **Local** — [Smithery](https://smithery.ai/server/designcomputer/mysql-mcp-server) installs and runs the server on your own machine.

## Features
- List available MySQL tables as resources
- Read table contents
- Execute SQL queries with proper error handling
- **Multi-database mode** (Optional `MYSQL_DATABASE`)
- **SSE/HTTP transport support** (`MCP_TRANSPORT=sse`)
- **SSH Tunneling support**
- **Comprehensive schema information**
- **Table data sampling**
- Secure database access through environment variables
- Comprehensive logging

## Installation
### Manual Installation
```bash
pip install mysql-mcp-server
```

### Installing via Smithery
To install MySQL MCP Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/designcomputer/mysql-mcp-server):
```bash
npx -y @smithery/cli install designcomputer/mysql-mcp-server --client claude
```

### Installing via Claude Code CLI
```bash
claude mcp add --transport stdio designcomputer-mysql_mcp_server uvx mysql_mcp_server
```

### Installing via Autohand Code CLI
```bash
autohand mcp add mysql env MYSQL_HOST=localhost MYSQL_PORT=3306 MYSQL_USER=your_username MYSQL_PASSWORD=your_password MYSQL_DATABASE=your_database uvx mysql_mcp_server
```

Add `--scope project` after `mcp add` to keep the registration in the current workspace. See [Autohand Code](https://github.com/autohandai/code-cli/) for current CLI details.

## Configuration
Set the following environment variables:
```bash
MYSQL_HOST=localhost     # Database host
MYSQL_PORT=3306         # Optional: Database port (defaults to 3306 if not specified)
MYSQL_USER=your_username
MYSQL_PASSWORD=your_password
MYSQL_DATABASE=your_database # Optional: Omit for multi-database mode

# Advanced Configuration
MYSQL_SSL_MODE=DISABLED  # DISABLED, REQUIRED, VERIFY_CA, VERIFY_IDENTITY
MYSQL_CONNECT_TIMEOUT=10 # Timeout in seconds

# Connection behaviour (Optional)
MYSQL_SQL_MODE=TRADITIONAL           # SQL mode applied to the connection (default: TRADITIONAL)

# Compatibility (Optional)
MYSQL_CHARSET=utf8mb4
MYSQL_COLLATION=utf8mb4_unicode_ci
MYSQL_AUTH_PLUGIN=       # e.g., mysql_native_password for older MySQL versions
MYSQL_USE_PURE=false     # Force the pure-Python connector (default: false)
MYSQL_RAISE_ON_WARNINGS=false        # Raise on SQL warnings (default: false)

# SSE Transport (Optional)
MCP_TRANSPORT=stdio      # stdio or sse
MCP_SSE_HOST=0.0.0.0     # Listen on all interfaces (required for Docker/hosting)
PORT=8000                # HTTP port (fallback for MCP_SSE_PORT)
MCP_SSE_ALLOWED_HOSTS=   # Comma-separated allowed Host headers (default: localhost:{port},127.0.0.1:{port})

# Read/Write Separation (Optional, recommended when using SSE)
MYSQL_RO_USER=           # A MySQL account with SELECT only. Read tools connect as this
MYSQL_RO_PASSWORD=       # account, so MySQL refuses writes regardless of this server
MYSQL_MAX_ROWS=1000      # Cap on rows returned per result set (0 disables)
MYSQL_STATEMENT_TIMEOUT_MS=30000  # Server-side limit on read statements (0 disables)

# OAuth 2.1 Authentication via Authplane (Optional, SSE only)
# Requires: pip install mysql_mcp_server[auth]   —   full reference: AUTHENTICATION.md
MCP_AUTH_MODE=none                # 'authplane' to enable; 'none' (default) changes nothing
AUTHPLANE_ISSUER=                 # Authplane base URL, e.g. http://localhost:9000
AUTHPLANE_RESOURCE=               # This server's canonical URI; must equal the token's 'aud'
MYSQL_SCOPE_READ=mysql:read       # Scope required by the read tools
MYSQL_SCOPE_WRITE=mysql:write     # Scope that routes execute_sql to the read-write account
MCP_AUTH_BIND_SESSION=true        # Bind each SSE session to the subject that opened it
MCP_AUTH_AUDIT=true               # Structured audit records (see Auditing below)
MCP_AUTH_DPOP=off                 # off | optional | required (RFC 9449 sender-constrained tokens)
MCP_AUTH_REVOCATION_CHECK=false   # Check revocation per request; needs the two values below
AUTHPLANE_CLIENT_ID=              # This server's client id, for introspection calls
AUTHPLANE_CLIENT_SECRET=          #
MCP_AUTH_MAX_AUTH_FAILURES=0      # Throttle a client after N auth failures (0 disables)
AUTHPLANE_CLOCK_SKEW_SECONDS=30   # Tolerance for clock drift between this server and the AS
AUTHPLANE_ALLOWED_ALGORITHMS=ES256,RS256

# SSH Tunneling (Optional)
MYSQL_SSH_ENABLE=false   # Set to true to enable
MYSQL_SSH_HOST=          # SSH jump host
MYSQL_SSH_PORT=22        # SSH port
MYSQL_SSH_USER=          # SSH username
MYSQL_SSH_KEY_PATH=      # Path to SSH private key
MYSQL_SSH_REMOTE_HOST=localhost # Host from the perspective of the jump host
MYSQL_SSH_REMOTE_PORT=3306
MYSQL_LOCAL_PORT=3330
```

### `.env` file loading

On startup the server automatically loads a `.env` file via `python-dotenv`, so for local use you can simply:

```bash
cp .env.example .env   # then edit with your credentials
```

The file is read from the **process working directory** (and parent directories), which works when you run the server yourself from the project folder.

> ⚠️ **Claude Code / Claude Desktop:** these hosts launch the server from their own working directory, so the project's `.env` will **not** be found and you'll see `Missing required database configuration`. Put your `MYSQL_*` values in the `env` block of the MCP config (shown in the Usage section below) rather than relying on `.env`.

### Multi-Database Mode
When `MYSQL_DATABASE` is not set, the server operates in multi-database mode:
- `list_resources` returns all user databases (system databases are filtered out)
- Use fully qualified table names like `mydb.mytable` in SQL queries
- **Note:** Only single SQL statements are supported. Multi-statement queries (e.g., `USE db; SELECT ...`) are not supported.

## Available Tools

### `execute_sql`
Executes any single SQL statement, read or write. **The privileges it runs with follow the caller's scope:** a caller holding only `MYSQL_SCOPE_READ` reaches the database as the read-only account, so a write is refused by MySQL itself.
- **Arguments:** `query` (string)
- **Authorization:** write scope → read-write connection; read scope only → `SELECT`-only connection; neither → refused before the database is reached. With authentication disabled (including stdio) it keeps the read-write connection, as before.
- **No statement inspection.** The server does not parse your SQL to decide what it is. The connection's MySQL privileges decide, and MySQL enforces them — which also covers stacked writes and version-gated comments such as `/*!DROP TABLE t*/`, the syntax classifiers are weakest against.
- **Limitation:** Single statements only. Multi-statement queries are not supported.
- **Cross-database:** Use `database.table` notation to query any database regardless of the `MYSQL_DATABASE` setting.

### `get_schema_info`
Provides detailed metadata about database structures.
- **Arguments:** `table_name` (optional string)
- **Output:** Column names, types, nullability, default values, and comments.
- **Cross-database:** Pass `database.table` to query a table outside `MYSQL_DATABASE`; bare names use the configured database.
- **Identifier rules:** Names must contain only alphanumeric characters, underscores, and `$` (dots are allowed as a separator between database and table names).

### `get_table_sample`
Fetches a representative sample of data.
- **Arguments:** `table_name` (string), `limit` (optional integer, max 20)
- **Use Case:** Quickly understand data formats and content without fetching large result sets.
- **Cross-database:** Pass `database.table` to sample a table outside `MYSQL_DATABASE`; bare names use the configured database.
- **Identifier rules:** Names must contain only alphanumeric characters, underscores, and `$` (dots are allowed as a separator between database and table names).

## Available Prompts

In addition to tools, the server exposes **MCP prompts** — guided, multi-step workflows that a client can launch on demand. In Claude Code they appear as slash commands (`/mcp__<server>__<prompt>`); in Claude Desktop they appear in the prompts (`+`) menu.

| Prompt | Arguments | Description |
| --- | --- | --- |
| `explore_database` | *(none)* | Systematically explore the database: discover available tables, inspect their schemas, sample the data, and summarize what's there. |
| `analyze_table` | `table_name` *(required)* | Deep-dive into a specific table: retrieve its schema, sample its data, and suggest useful queries. Accepts `database.table` notation for cross-database lookups. |

**Example (Claude Code):**
```
/mcp__mysql__explore_database
/mcp__mysql__analyze_table customers
```

Both prompts orchestrate the existing `get_schema_info` and `get_table_sample` tools; `explore_database` also uses resource listing to enumerate tables.

## Usage
### With Claude Desktop
Add this to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mysql": {
      "command": "uv",
      "args": [
        "--directory",
        "path/to/mysql_mcp_server",
        "run",
        "mysql_mcp_server"
      ],
      "env": {
        "MYSQL_HOST": "localhost",
        "MYSQL_PORT": "3306",
        "MYSQL_USER": "your_username",
        "MYSQL_PASSWORD": "your_password",
        "MYSQL_DATABASE": "your_database"
      }
    }
  }
}
```

For more detailed examples and agent-specific guidance, see [MCP_USECASES.md](MCP_USECASES.md).

### With Visual Studio Code
Add this to your `mcp.json`:
```json
{
  "mcpServers": {
    "mysql": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "--from",
        "mysql-mcp-server",
        "mysql_mcp_server"
      ],
      "env": {
        "MYSQL_HOST": "localhost",
        "MYSQL_PORT": "3306",
        "MYSQL_USER": "your_username",
        "MYSQL_PASSWORD": "your_password",
        "MYSQL_DATABASE": "your_database"
      }
    }
  }
}
```
Note: Will need to install uv for this to work

### Debugging with MCP Inspector
While MySQL MCP Server isn't intended to be run standalone or directly from the command line with Python, you can use the MCP Inspector to debug it.

The MCP Inspector provides a convenient way to test and debug your MCP implementation:

```bash
# Install dependencies
pip install -r requirements.txt
# Use the MCP Inspector for debugging (do not run directly with Python)
```

The MySQL MCP Server is designed to be integrated with AI applications like Claude Desktop and should not be run directly as a standalone Python program.

## Development
```bash
# Clone the repository
git clone https://github.com/designcomputer/mysql_mcp_server.git
cd mysql_mcp_server
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
# Install development dependencies
pip install -r requirements-dev.txt
# Copy the example config and edit with your credentials
cp .env.example .env
# Edit .env with your MySQL connection details
# Run tests
pytest
```

## Security Considerations
- **Identifier Validation:** Table and database names passed to `get_schema_info` and `get_table_sample` are validated against a strict whitelist (alphanumeric, underscore, and `$` only; a single dot is allowed as a `database.table` separator). Other special characters are rejected to prevent SQL injection.
- **Encrypted Access:** Full support for SSL/TLS and SSH Tunneling for secure remote connections.
- **Log Privacy:** Passwords and SSH private keys are automatically masked in server logs.
- **Least Privilege:** Always use a dedicated MySQL user with minimal required permissions.
- **SSE transport is unauthenticated by default.** With `MCP_AUTH_MODE` unset the SSE server binds to `0.0.0.0` and accepts connections without credentials. Two ways to close that:
  - **OAuth 2.1 (recommended if your client supports it):** see [OAuth 2.1 authentication](#oauth-21-authentication-sse) below. Unlike a proxy, this passes the caller's identity to the server, which is what makes per-tool authorization and a per-user audit trail possible.
  - **A reverse proxy**, if you only need to keep strangers out. Example with nginx and HTTP Basic Auth:

  ```nginx
  location /sse {
      auth_basic "MCP";
      auth_basic_user_file /etc/nginx/.htpasswd;
      proxy_pass http://127.0.0.1:8000;
      proxy_set_header Host $host;
      proxy_buffering off;
  }
  location /messages/ {
      auth_basic "MCP";
      auth_basic_user_file /etc/nginx/.htpasswd;
      proxy_pass http://127.0.0.1:8000;
      proxy_set_header Host $host;
  }
  ```

  Set `MCP_SSE_HOST=127.0.0.1` so the server only listens on loopback and the proxy is the sole public entry point. Set `MCP_SSE_ALLOWED_HOSTS` to the public hostname your proxy forwards (e.g. `MCP_SSE_ALLOWED_HOSTS=myserver.example.com:443`).

See [SECURITY.md](SECURITY.md) for a comprehensive guide on securing your deployment.

## OAuth 2.1 authentication (SSE)

The SSE transport can require an OAuth 2.1 access token, using [Authplane](https://authplane.com) as the authorization server via the official [Authplane Python SDK](https://pypi.org/project/authplane-sdk/) (`authplane-sdk`).

It is optional and off by default. With `MCP_AUTH_MODE` unset the server behaves exactly as it did before this feature existed: no middleware, no extra routes, and the SDK is never imported.

```bash
pip install mysql_mcp_server[auth]

export MCP_TRANSPORT=sse
export MCP_AUTH_MODE=authplane
export AUTHPLANE_ISSUER=https://auth.example.com     # your Authplane server
export AUTHPLANE_RESOURCE=https://mcp.example.com    # this server's canonical URI
export MYSQL_RO_USER=mcp_ro MYSQL_RO_PASSWORD=...    # see Read/write separation
python -m mysql_mcp_server
```

Both MCP endpoints are protected: `GET /sse`, which issues the session id, and `POST /messages/`, which carries every tool call. The health probe `/` and the RFC 9728 metadata document at `/.well-known/oauth-protected-resource` stay public, since a client cannot obtain a token without first discovering where tokens come from.

Tokens are accepted only in the `Authorization` header. `get_schema_info` and `get_table_sample` require `MYSQL_SCOPE_READ`, as do MCP resource reads. `execute_sql` is authorized differently — the caller's scope selects the database account, so the grants on that account decide the outcome, and a caller holding neither scope is refused. DPoP (RFC 9449) and per-request revocation checks are supported and ship disabled.

📖 **See [AUTHENTICATION.md](AUTHENTICATION.md)** for how it works, which SDK calls are used and where, the full configuration reference, and the known limits.

## Read/write separation

The read/write boundary is **MySQL's privilege system**, not this server. Nothing in the process parses your SQL to decide whether it writes; the caller's scope picks which MySQL account runs the statement, and that account's grants decide the outcome. Create the read-only account:

```sql
CREATE USER 'mcp_ro'@'%' IDENTIFIED BY 'a-strong-password';
GRANT SELECT ON your_database.* TO 'mcp_ro'@'%';
```

```bash
export MYSQL_RO_USER=mcp_ro
export MYSQL_RO_PASSWORD=a-strong-password
```

A read-scoped caller then connects as that account, so a write is refused by MySQL — including DDL, stacked statements, and anything smuggled through a version-gated comment. The grants are checked at startup and **the server refuses to start if that account can write**, a misconfiguration that would otherwise look identical to a correct setup.

There is no software fallback, because none of the alternatives is a boundary. Measured against MySQL 8.4, wrapping reads in `START TRANSACTION READ ONLY` refuses `INSERT`/`UPDATE`/`DELETE` but lets `CREATE`, `DROP`, `ALTER`, `TRUNCATE` and `RENAME` through, because DDL commits implicitly and ends the transaction — it would look like a boundary without being one. The account's grants are the boundary.

**Without `MYSQL_RO_USER`,** a read-scoped caller runs on the read-write account and the read scope has nothing enforcing it: a `DROP DATABASE` from a read-only token would succeed. This is permitted so that enabling authentication does not require provisioning a database account first, but with authentication on the server warns about it at startup, warns once when it first happens, and audits every such call as `read_scope_not_enforced`. With authentication off there is no scope to enforce and no warning is emitted.

## Security Best Practices
This MCP implementation requires database access to function. For security:
1. **Create a dedicated MySQL user** with minimal permissions
2. **Never use root credentials** or administrative accounts
3. **Restrict database access** to only necessary operations
4. **Enable logging** for audit purposes
5. **Regular security reviews** of database access

See [MySQL Security Configuration Guide](https://github.com/designcomputer/mysql_mcp_server/blob/main/SECURITY.md) for detailed instructions on:
- Creating a restricted MySQL user
- Setting appropriate permissions
- Monitoring database access
- Security best practices

⚠️ IMPORTANT: Always follow the principle of least privilege when configuring database access.

## License
MIT License - see LICENSE file for details.

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
