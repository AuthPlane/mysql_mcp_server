# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Opt-in OAuth 2.1 authentication for the SSE transport.** Off unless `MCP_AUTH_MODE` is set; with it unset no middleware is installed, no routes are added, and the auth dependency is never imported. Auth dependencies live in a new `[auth]` optional-dependency group (`pip install mysql_mcp_server[auth]`), so the base install is unchanged.
  - Both MCP endpoints are protected. `GET /sse` issues the session id and `POST /messages/` is where tool calls arrive, so authenticating only `/sse` would leave every tool call reachable without credentials.
  - `/` and `/.well-known/oauth-protected-resource` (RFC 9728) stay public: orchestrators probe the first before credentials exist, and a client cannot obtain a token without reading the second. Both the route and the middleware's public-path exemption are derived from the verifier's own `metadata_url()`, so they cannot disagree — per RFC 9728 §3 the well-known path carries the resource's own path, so a non-root `AUTHPLANE_RESOURCE` is served exactly where its challenge points.
  - Tokens are accepted only from the `Authorization` header. A query-string token would leak into proxy logs and `Referer` headers.
  - Provider-neutral by construction: the middleware depends on a `TokenVerifier` protocol and never imports a specific provider. Authplane is the implementation shipped.
- **`execute_sql` is scope-aware, and is the only SQL tool.** The caller's scope selects the MySQL account that runs the statement, so a read-scoped caller reaches the database as the `SELECT`-only account and MySQL refuses anything that writes. A tool accepting arbitrary SQL can therefore be authorized precisely -- by the database's grants rather than by this process classifying the statement -- and needs no deprecation. Existing configurations that call `execute_sql` are unaffected. `get_schema_info` and `get_table_sample` carry a read-scope gate, since they take a table name rather than SQL.
- **Read/write separation enforced by MySQL.** With `MYSQL_RO_USER` / `MYSQL_RO_PASSWORD` set, a read-scoped call connects as a `SELECT`-only account, so a write is refused by the database rather than by this process reading the SQL. Grants are verified at startup on every transport -- the read-only account is a property of the database configuration, not of the auth configuration -- and the server refuses to start if that account can write.
  - Without the account, a read-scoped caller runs on the read-write account and the read scope has nothing enforcing it. Permitted so that enabling auth does not require provisioning a database account first, but with auth on the server warns at startup, warns once when it first happens, and audits each such call as `read_scope_not_enforced` (`outcome: allowed`). With auth off there is no scope to enforce and nothing is logged. `START TRANSACTION READ ONLY` is **not** used as a fallback -- see the measurements below.
  - MCP resources (`mysql://<table>/data`) are a separate MCP primitive and never pass through the tool dispatcher, so they carry the read-scope requirement and the read-only connection explicitly rather than inheriting them: reading a resource costs the read scope and runs on the `SELECT`-only account.
- **Per-tool scope enforcement** via `MYSQL_SCOPE_READ` / `MYSQL_SCOPE_WRITE`. An unmapped tool name falls back to the write scope so a tool added later fails closed. `execute_sql` is the one exception, with a deliberately empty entry: its connection is its gate.
- **Scope is decided by the token that sent the call**, not by the one that opened the stream. The identity is resolved through the MCP request id, which is the one thing shared between the POST that delivered the frame and the task that executes it -- so handing a sub-agent a narrower token holds even when it shares a session with a wider one, and the `tool_call_authorized` record names the `jti` the scope decision actually used. The entry cannot be released when the POST returns, since the transport answers 202 before the handler runs, so the tool layer releases it and the table is capped for frames that never reach a handler.
- **Session binding** (`MCP_AUTH_BIND_SESSION`, default on). An SSE session belongs to the subject that opened it; a valid token belonging to a different subject is refused on it. A binding is released when its stream closes, matching the transport's own session lifetime, so the table does not drift towards its 4,096-entry cap and begin evicting sessions that are still open — an evicted session is no longer subject-checked, which is the one thing the table exists to prevent.
- **Structured audit records** (`MCP_AUTH_AUDIT`, default on) on the `mysql_mcp_server.audit` logger — one JSON object per line with subject, client id, `jti`, tool and statement. Tokens are never recorded and statements are truncated.
  - A successful authentication is audited as `stream_opened`, so the trail records who merely connected and not only who was refused or who ran SQL, and a session id appearing in later records has an origin.
  - Per-tool refusals are audited where they are decided: the tool handler emits `tool_call_denied_scope` and `tool_call_denied_statement`, so a reader asking "who was allowed to run what" is never shown a refused `DROP TABLE` recorded as authorized. These records omit `method`, `path` and `client` rather than guessing them -- the handler runs in the stream's task with no request attached, and the `stream_opened` record for the same `session_id` carries them.
  - Records carry `scheme` and `dpop_proof`, written as soon as the `Authorization` header is parsed so denials carry them too. Without them a bearer token and a sender-constrained one are indistinguishable in the trail, which makes "is DPoP actually in effect here?" unanswerable from the one place it should be obvious.
- **DPoP support** (`MCP_AUTH_DPOP`: `off` / `optional` / `required`, RFC 9449) for sender-constrained tokens, so a stolen token without the client's key is unusable. A DPoP-bound token is presented as `Authorization: DPoP <token>` (RFC 9449 §7.1), and a proof presented under the `Bearer` scheme is refused, so a sender-constrained token cannot be passed off as an ordinary one. The `htu` is built from `scope["raw_path"]`, with the decoded path as a fallback for servers that omit it, because the client signs over the on-wire target and an ASGI-decoded path containing `%2F` would not match it.
- **`WWW-Authenticate` advertises the schemes actually accepted**, one header value per scheme: `Bearer` when DPoP is off, both when `optional`, and `DPoP` alone when `required`. The DPoP challenge carries `algs` (RFC 9449 §5.1) so a client knows what to sign with.
- **DPoP proof algorithms are configured separately** from token signing algorithms, via `MCP_AUTH_DPOP_ALGORITHMS` (defaulting to `AUTHPLANE_ALLOWED_ALGORITHMS`), so proofs can be restricted to `ES256` while `RS256`-signed tokens stay acceptable — the authorization server's algorithm is a deployment fact and the client's is a policy choice.
- **An authorization-server outage is reported as one, not as a bad token.** The SDK's `http_status()` distinguishes four outcomes and all four are carried through: 503 when the AS cannot participate in validation (`JWKSFetchError`, `MetadataFetchError`, `CircuitOpenError`), 500 for an internal fault, 403 for a scope failure, and 401 only for a credential the client can actually fix. Reporting an outage as `401 invalid_token` would have a conforming client discard a working token and re-authenticate against the server that is already down — and, with `MCP_AUTH_MAX_AUTH_FAILURES` set, get throttled here for doing so. A 5xx carries no `WWW-Authenticate` challenge (the challenge is the invitation to re-authenticate) and does not count against the failure throttle; a 503 carries `Retry-After`.
- **Optional revocation checking** (`MCP_AUTH_REVOCATION_CHECK`, RFC 7662), configured fail-closed. Off by default because local validation is what keeps the server working when the authorization server is unreachable.
- **Optional authentication-failure throttling** (`MCP_AUTH_MAX_AUTH_FAILURES`). Off by default: the only key available is the socket peer address, which behind a reverse proxy puts every caller in one bucket.
- **Result guardrails:** `MYSQL_MAX_ROWS` caps rows per result set and reports truncation explicitly; `MYSQL_STATEMENT_TIMEOUT_MS` bounds read statements server-side.
- **`AUTHENTICATION.md`** documenting the Authplane setup: the Authplane Python SDK (`authplane-sdk`) calls used and where, the full configuration reference, how a DPoP token is presented, and the known limits. The README section is a short pointer to it.
- **Tests against a live Authplane server** (`tests/test_authplane_live.py`, `tests/test_authplane_e2e.py`, `tests/authplane_harness.py`): real tokens through the real verifier, and a real MCP client driving the real server over HTTP. They skip unless `AUTHPLANE_TEST_ISSUER`, `AUTHPLANE_TEST_ADMIN_URL` and `AUTHPLANE_TEST_ADMIN_KEY` are set — see `tests/README.md`.
- **`MCP_AUTH_AUDIT_FILE`** writes the audit trail to its own file, one JSON object per line. Without it the records land on stderr interleaved with the access log, which is fine for a glance and unusable for anything else. An unwritable path is logged as an error and does not stop the server.
- `.env` is in `.gitignore`, next to the `.env.example` that invites creating one: the filled-in copy holds the database password and the client secret.

### Verified
- **The browser consent flow (`authorization_code` with a human approving) works end to end** against Claude Code as a real MCP client: PRM discovery, client registration, PKCE S256, consent, scope-limited token, tool calls, and a scope refusal arriving as a JSON-RPC error rather than a hang.
- **Access-token expiry and refresh are transparent to a live session.** Authplane issues `authorization_code` access tokens with a 15-minute lifetime (`client_credentials` gets an hour). An idle MCP session outlived one, and the client refreshed silently — a new `jti` with the same scope set, no re-consent, no interruption to the session. Confirmed against `token.refreshed` in the authorization server's own log.
- **Scope enforcement holds against an agent improvising, not just against dictated tool calls.** With a token carrying only `mysql:read`, an LLM client asked in plain language to delete and to modify a table attempted the write for both, was refused each time by MySQL on the `SELECT`-only connection, and — when pressed that "there must be a way" — declined to look for a bypass rather than trying to smuggle the statement past the connection. The table and its rows were verified unchanged in MySQL afterwards. No automated test covers this path: every test names the tool to call.
- **`MCP_AUTH_DPOP=required` refuses a bearer-only client correctly**, answering a single `DPoP` challenge carrying `algs` and no `Bearer` challenge at all, with `dpop_bound_access_tokens_required: true` in the metadata document. Measured against Claude Code, which does not implement RFC 9449 and therefore cannot connect in that mode — documented in `AUTHENTICATION.md` as a client-compatibility decision rather than a security setting.

### Changed
- **`authplane-sdk` pinned to 0.4.0** (from 0.2.0). The public API this integration depends on -- `AuthplaneClient.resource()`, `resource.verify()`, `prm_url()`, `prm_response()`, `http_status()`, `InboundDPoPOptions` -- is covered by the suite. Note the hermetic suite exercises the fake verifier: the tests that drive the real SDK against a live authorization server (`test_authplane_live`, `test_authplane_e2e`) skip without one, so a live run is what confirms a version bump end to end.
- **The read path is read-only because it connects as an account that cannot write, not because this server parses statements.** Nothing here classifies SQL. Measured against MySQL 8.4, the alternative -- `START TRANSACTION READ ONLY` on the read-write account -- refuses `INSERT`/`UPDATE`/`DELETE` (1792) but lets `CREATE`, `DROP`, `ALTER`, `TRUNCATE` and `RENAME` through, because DDL commits implicitly and ends the transaction, so it would look like a boundary without being one. A hand-written SQL classifier is the other candidate, and is exactly what should not be load-bearing -- there is always one more syntax nobody thought of. `sqlguard.py` holds only the mapping from MySQL denial errnos to a clean tool error.
- **`AUTHPLANE_RESOURCE` is canonicalised rather than stripped.** RFC 3986 makes an empty path equivalent to `/` for an http(s) URI, so a resource with no path is stored as `http://host:port/` -- the form any OAuth client that parses and re-serialises the URL sends, and therefore the form the authorization server compares against. Stripping it instead produces a value no real client sends, and the authorization server answers "Unknown Resource" before consent with nothing in this server's log to explain it. A non-root path is left exactly as given, since there the slash is part of the path and `.../mcp` and `.../mcp/` are different resources. Only the `authorization_code` flow reaches this: `client_credentials` asks for its audience directly and never has a URL library re-add the slash.
- Result sets are read with `fetchmany()` rather than `fetchall()` so `MYSQL_MAX_ROWS` can cap them without materialising the whole set. The remainder of a capped result set is drained in batches, since mysql-connector raises `Unread result found` when a cursor with pending rows is closed; `test_sql_boundary.py` covers it against a live server.
- Statements refused on policy grounds are reported as tool *errors* (`isError: true`) rather than as ordinary content, so a client can tell a refusal from an answer. Unexpected failures still return readable content, as before.
- MySQL "access denied" errors on the read path are reported with a fixed message instead of the server's own text, which names the database account and host. The privilege-denial message does not claim a connection the statement may not have run on: the same errnos arrive on the read-write connection whenever the deployed account simply lacks a privilege, and there the text says so instead of mentioning read-only privileges and the write scope.
- `1045 ER_ACCESS_DENIED_ERROR` is deliberately not treated as a policy refusal. It reads like the other access-denied errnos, but MySQL raises it when *credentials* are refused, at connect time, which has nothing to do with the statement — so a wrong `MYSQL_PASSWORD` is reported as the server misconfiguration it is, with a message that points at the server's environment and still does not name the account or host.

### Security
- **What a `SELECT`-only grant still permits was measured, not assumed:** `INTO OUTFILE` and `INTO DUMPFILE` are refused (1227) and `LOAD_FILE()` returns `NULL` without the `FILE` privilege; `FOR UPDATE` is refused (1142). `SLEEP()`, `BENCHMARK()` and `GET_LOCK()` all run — resource consumption rather than a privilege violation, and bounded by `MYSQL_STATEMENT_TIMEOUT_MS` and `MYSQL_MAX_ROWS` rather than by parsing. `GET_LOCK()` is bounded differently and worth stating: a named lock belongs to the MySQL *session*, not to the statement, so the statement timeout does not cover it — what does is that `run_query` opens its own connection per call and closes it, which releases any lock the statement took. A connection reused across calls would hand a read-scoped caller a way to hold a named lock indefinitely and stall any writer coordinating on that name, so that per-call connection is load-bearing, not incidental. `test_sql_boundary.py` pins it against a live server.
- Because the boundary is the account's grants, a write hidden behind `/* */`, `--` or `#`, inside a CTE, or appended as a stacked statement is refused by MySQL — as are MySQL's version-gated `/*! ... */` comments, which MySQL executes as code and which are the syntax a classifier is weakest against.
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
