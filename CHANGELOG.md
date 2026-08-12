# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Opt-in OAuth 2.1 authentication for the SSE transport.** Off unless `MCP_AUTH_MODE` is set; with it unset no middleware is installed, no routes are added, and the auth dependency is never imported. Auth dependencies live in a new `[auth]` optional-dependency group (`pip install mysql_mcp_server[auth]`), so the base install is unchanged.
  - Both MCP endpoints are protected. `GET /sse` issues the session id and `POST /messages/` is where tool calls arrive, so authenticating only `/sse` would leave every tool call reachable without credentials.
  - `/` and `/.well-known/oauth-protected-resource` (RFC 9728) stay public: orchestrators probe the first before credentials exist, and a client cannot obtain a token without reading the second.
  - Tokens are accepted only from the `Authorization` header. A query-string token would leak into proxy logs and `Referer` headers.
  - Provider-neutral by construction: the middleware depends on a `TokenVerifier` protocol and never imports a specific provider. Authplane is the implementation shipped.
- **`read_query` and `write_query` tools**, splitting the read and write paths so each can require a different scope. `execute_sql` is now deprecated: it accepts arbitrary SQL, so it cannot be authorized precisely and is treated as a write.
- **Read/write separation enforced by MySQL.** With `MYSQL_RO_USER` / `MYSQL_RO_PASSWORD` set, read tools connect as a `SELECT`-only account, so a write that gets past statement classification is refused by the database. Grants are verified at startup and the server refuses to start if that account can write. Without it, reads run inside `START TRANSACTION READ ONLY` and a startup warning is logged.
- **Per-tool scope enforcement** via `MYSQL_SCOPE_READ` / `MYSQL_SCOPE_WRITE`. An unmapped tool name falls back to the write scope so a tool added later fails closed.
- **Session binding** (`MCP_AUTH_BIND_SESSION`, default on). An SSE session belongs to the subject that opened it; a valid token belonging to a different subject is refused on it.
- **Structured audit records** (`MCP_AUTH_AUDIT`, default on) on the `mysql_mcp_server.audit` logger — one JSON object per line with subject, client id, `jti`, tool and statement. Tokens are never recorded and statements are truncated.
- **DPoP support** (`MCP_AUTH_DPOP`: `off` / `optional` / `required`, RFC 9449) for sender-constrained tokens, so a stolen token without the client's key is unusable.
- **Optional revocation checking** (`MCP_AUTH_REVOCATION_CHECK`, RFC 7662), configured fail-closed. Off by default because local validation is what keeps the server working when the authorization server is unreachable.
- **Optional authentication-failure throttling** (`MCP_AUTH_MAX_AUTH_FAILURES`). Off by default: the only key available is the socket peer address, which behind a reverse proxy puts every caller in one bucket.
- **Result guardrails:** `MYSQL_MAX_ROWS` caps rows per result set and reports truncation explicitly; `MYSQL_STATEMENT_TIMEOUT_MS` bounds read statements server-side.
- **`AUTHENTICATION.md`** documenting the Authplane setup: the Authplane Python SDK (`authplane-sdk`) calls used and where, the full configuration reference, how a DPoP token is presented, and the known limits. The README section is now a short pointer to it.
- **Tests against a live Authplane server** (`tests/test_authplane_live.py`, `tests/test_authplane_e2e.py`, `tests/authplane_harness.py`): real tokens through the real verifier, and a real MCP client driving the real server over HTTP. They skip unless `AUTHPLANE_TEST_ISSUER`, `AUTHPLANE_TEST_ADMIN_URL` and `AUTHPLANE_TEST_ADMIN_KEY` are set — see `tests/README.md`.

### Fixed
- **DPoP was unusable over HTTP.** The `Authorization` header parser accepted only the `Bearer` scheme, but RFC 9449 §7.1 requires a DPoP-bound token to be presented as `Authorization: DPoP <token>`. Every conforming DPoP client was refused with a 401 before its proof was examined. The proof handling itself was correct; only the scheme check was wrong. It went unnoticed because the DPoP tests drive a fake verifier and construct the request context directly, so none of them ever built this header.
- **A proof presented under the `Bearer` scheme is now refused** rather than accepted, so a sender-constrained token cannot be passed off as an ordinary one.
- **`WWW-Authenticate` now advertises the schemes actually accepted**, one header value per scheme: `Bearer` when DPoP is off, both when `optional`, and `DPoP` alone when `required`. Previously every challenge said `Bearer`, which in `required` mode named the one scheme that could not work. The DPoP challenge carries `algs` (RFC 9449 §5.1) so a client knows what to sign with.

### Changed
- Result sets are read with `fetchmany()` rather than `fetchall()` so `MYSQL_MAX_ROWS` can cap them without materialising the whole set.
- Statements refused on policy grounds are now reported as tool *errors* (`isError: true`) rather than as ordinary content, so a client can tell a refusal from an answer. Unexpected failures still return readable content, as before.
- MySQL "access denied" errors on the read path are reported with a fixed message instead of the server's own text, which names the database account and host.

### Security
- **`read_query` refuses constructs a `SELECT`-only grant would otherwise allow:** `INTO OUTFILE` and `INTO DUMPFILE` (write a file on the database server), `LOAD_FILE()` (reads one), `FOR UPDATE` and `LOCK IN SHARE MODE` (take locks), `SLEEP()` and `BENCHMARK()` (consume resources).
- Statement classification strips comments and string literals before inspecting the statement, so a write hidden behind `/* */`, `--` or `#`, or inside a CTE, is still refused. MySQL's version-gated `/*! ... */` comments are treated as executable code, because that is what MySQL does with them.
- Existing DNS-rebinding protection is untouched and applies independently of authentication.

## [0.4.4] - 2026-07-30

### Fixed
- **C Extension Fallback:** Stopped forcing `use_pure=False` in the connection config by default. `mysql-connector-python` treats an explicit `use_pure=False` as a hard requirement for its C extension, raising `ImportError` instead of falling back to the pure-Python implementation when the extension can't load (e.g. built against a newer OpenSSL than the host provides, as with `mysql-connector-python` 26.7.0 on many Linux systems). `use_pure` is now only set when `MYSQL_USE_PURE` is explicitly configured.

## [0.4.3] - 2026-07-30

### Fixed
- **Missing Runtime Dependency:** `python-dotenv` is now declared as a required dependency. The server imports it directly, but `uvx`'s isolated environment doesn't install it automatically, causing a `ModuleNotFoundError` on startup (#95).
- **MCP 2.x Incompatibility:** Constrained the `mcp` dependency to `<2` since MCP 2.0 introduced breaking API changes this server has not been migrated to support, and the previous unbounded `>=1.2.0` allowed `uvx` to resolve an incompatible version (#95).

## [0.4.1] - 2026-06-08

### Fixed
- **Package Metadata:** Split author entry into name-only (`Author:`) + maintainer-with-email (`Maintainer-email:`) so sites that read the legacy `Author` field (e.g. pypistats.org) display the author name correctly.

## [0.4.0] - 2026-06-08

### Added
- **Cross-Database Support:** `get_schema_info` and `get_table_sample` now accept `database.table` notation, making their scope consistent with `execute_sql`. Bare table names continue to use `MYSQL_DATABASE`.
- **MCP Prompts:** Two guided workflow prompts usable as slash commands in supporting clients (e.g. Claude Desktop):
  - `explore_database` — walks through resource discovery, schema inspection, data sampling, and summarization.
  - `analyze_table` — schema + sample + query suggestions for a named table.
- **Package Metadata:** Added `Homepage`, `Repository`, `Issues`, and `Changelog` URLs, SPDX license expression, keywords, and classifiers to PyPI metadata.
- **Reproducible Builds:** Committed `uv.lock` so hosted build environments get pinned dependencies.

### Fixed
- **Multi-Statement Error:** `execute_sql` now returns a clear message ("Only single statements are supported…") instead of MySQL's cryptic "Commands out of sync" error when a multi-statement query is passed.

### Changed
- **Tool Descriptions:** All three tools have richer descriptions that say when to use them and what they return. Contributor credits moved out of tool descriptions.
- **Tool Annotations:** `get_schema_info` and `get_table_sample` now carry `readOnlyHint=True` so clients can distinguish them from destructive operations.

## [0.3.1] - 2026-05-31

### Fixed
- **Strict LLM Compatibility:** Refactored resource names to be 'identifier-safe' (e.g., `table_users` instead of `Table: users`) to ensure compatibility with Google Gemini models and GitHub Copilot (Issue #39).
- **MySQL 5.7 Stability:** Added built-in support for `MYSQL_AUTH_PLUGIN`, `MYSQL_USE_PURE`, and `MYSQL_RAISE_ON_WARNINGS` to stabilize connections to older MySQL servers (Issue #31).

### Added
- **Standalone Execution:** Added `__main__.py` to allow running the package directly via `python -m mysql_mcp_server` (Issue #12).

## [0.3.0] - 2026-05-31

### Fixed
- **Asynchronous Reliability:** Refactored all blocking database and SSH operations to use background threads via `anyio.to_thread.run_sync`. This prevents the server from hanging in environments like Windows 11 (Issue #54).
- **Graceful Error Reporting:** Implemented global exception handling in tool calls to return clear, actionable error messages to AI agents and users instead of silent failures (Issue #50).
- **Metadata Formatting:** Improved result set handling for `DESCRIBE`, `SHOW COLUMNS`, and other inspection queries, including explicit `NULL` value rendering (PR #38).
- **SQL Injection Risk:** Added strict regex validation for all database and table identifiers (PR #86).

### Added
- **Multi-Database Mode:** `MYSQL_DATABASE` is now optional. When omitted, the server lists all available databases and supports `USE <database>` or fully qualified table names (PR #86, Issue #68, #81).
- **SSH Tunneling:** Built-in support for secure remote database connections via an SSH jump host using `MYSQL_SSH_ENABLE` (PR #64, contributed by @GeorgeLeex).
- **New Inspection Tools:**
    - `get_schema_info`: Detailed column metadata, types, and comments.
    - `get_table_sample`: Quick data previews to understand table content (PR #64, contributed by @GeorgeLeex).
- **SSE/HTTP Transport:** Support for running as an HTTP server by setting `MCP_TRANSPORT=sse` (PR #86).
- **SSL/TLS Support:** Added `MYSQL_SSL_MODE` for encrypted connections.
- **Environment Management:** Added `.env` support and `.env.example` file (PR #69).

### Security
- Added `ToolAnnotations` to `execute_sql` to flag potentially destructive operations to AI agents (PR #78).
- Dockerfile now runs as a non-root `appuser` and follows best practices for secret management.
- Masked sensitive information (passwords, SSH keys) in server logs.

### Changed
- Refactored server initialization into distinct STDIO and SSE transport handlers.
- Updated minimum `mcp` dependency to `1.2.0` for improved stability and security.

## [0.2.2] - 2025-04-18

### Fixed
- Fixed handling of SQL commands that return result sets, including `SHOW INDEX`, `SHOW CREATE TABLE`, and `DESCRIBE`
- Added improved error handling for result fetching operations
- Added additional debug output to aid in troubleshooting

## [0.2.1] - 2025-02-15

### Added
- Support for MYSQL_PORT configuration through environment variables
- Documentation for PORT configuration in README

### Changed
- Updated tests to use handler functions directly
- Refactored database configuration to runtime

## [0.2.0] - 2025-01-20

### Added
- Initial release with MCP server implementation
- Support for SQL queries through MCP interface
- Ability to list tables and read data
