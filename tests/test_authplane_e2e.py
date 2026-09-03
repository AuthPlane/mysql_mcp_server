"""The whole stack: a real server, a real Authplane token, a real MCP client.

`test_authplane_live.py` proves the verifier speaks to Authplane correctly. This
file proves the *server* does, by starting it as a subprocess and driving it with
the official MCP client library rather than a hand-written probe.

That distinction already caught one bug that no hermetic test could: a scope
refusal answered with HTTP 403 looked correct to a probe reading the POST status,
but a conforming MCP client ignores that status and waits for a JSON-RPC response
on the SSE stream -- so the client hung and the session collapsed. Refusals now
come back as tool errors. Several tests here assert the *absence of a hang*,
which is only meaningful against a real client.

Needs a live Authplane and a MySQL server. Skipped otherwise.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager, contextmanager

import pytest

from authplane_harness import (
    DECOY_RESOURCE_AUD,
    DECOY_SCOPE,
    ISSUER,
    READ_SCOPE,
    RESOURCE,
    RESOURCE_AUD,
    WRITE_SCOPE,
    LiveAuthplane,
    new_dpop_provider,
    requires_live_authplane,
)

pytestmark = [requires_live_authplane, pytest.mark.live_auth, pytest.mark.e2e]

# The server must answer on the URI the tokens name in `aud`, so the port comes
# from the resource rather than being chosen independently.
_PARSED = urllib.parse.urlparse(RESOURCE)
PORT = _PARSED.port or 8000
BASE = f"http://127.0.0.1:{PORT}"
SSE_URL = f"{BASE}/sse"

# A second port for the `MCP_AUTH_DPOP=required` server. The resource URI, and
# therefore the token audience, stays the same for both.
STRICT_PORT = PORT + 10
STRICT_BASE = f"http://127.0.0.1:{STRICT_PORT}"
STRICT_SSE_URL = f"{STRICT_BASE}/sse"

MYSQL_ENV = {
    "MYSQL_HOST": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "MYSQL_PORT": os.getenv("MYSQL_PORT", "3306"),
    "MYSQL_USER": os.getenv("MYSQL_USER", "mcp"),
    "MYSQL_PASSWORD": os.getenv("MYSQL_PASSWORD", "mcppw"),
    "MYSQL_DATABASE": os.getenv("MYSQL_DATABASE", "testdb"),
}


def _mysql_reachable() -> bool:
    try:
        import mysql.connector

        connection = mysql.connector.connect(
            host=MYSQL_ENV["MYSQL_HOST"],
            port=int(MYSQL_ENV["MYSQL_PORT"]),
            user=MYSQL_ENV["MYSQL_USER"],
            password=MYSQL_ENV["MYSQL_PASSWORD"],
            database=MYSQL_ENV["MYSQL_DATABASE"],
            connection_timeout=5,
        )
        connection.close()
        return True
    except Exception:
        return False


requires_mysql = pytest.mark.skipif(
    not _mysql_reachable(), reason="needs a reachable MySQL (see tests/README.md)"
)


@pytest.fixture(scope="session")
def live():
    harness = LiveAuthplane()
    harness.ensure_resource("mysql-mcp-server", RESOURCE_AUD, (READ_SCOPE, WRITE_SCOPE))
    harness.ensure_resource("decoy", DECOY_RESOURCE_AUD, (DECOY_SCOPE,))
    try:
        yield harness
    finally:
        harness.cleanup()


@pytest.fixture(scope="session")
def read_token(live):
    return live.mint(live.new_client("e2e-ro", READ_SCOPE), READ_SCOPE)


@pytest.fixture(scope="session")
def write_token(live):
    credentials = live.new_client("e2e-rw", f"{READ_SCOPE} {WRITE_SCOPE}")
    return live.mint(credentials, f"{READ_SCOPE} {WRITE_SCOPE}")


@contextmanager
def running_server(log_path, port: int, dpop: str):
    """Run the real server on ``port`` with authentication on.

    A subprocess rather than an in-process app: `_run_sse_server()` builds the
    Starlette application and the uvicorn config together, so there is no factory
    to import, and running it for real is closer to what is deployed anyway.

    `AUTHPLANE_RESOURCE` stays fixed while the port varies. That is not a
    mismatch: the resource URI is what tokens carry in `aud` and what DPoP proofs
    are signed for, and the server deliberately derives both from configuration
    rather than from the socket or the `Host` header. Varying the port is the
    same situation as running behind a reverse proxy.

    Output goes to a file, not `subprocess.PIPE`. Nobody drains a pipe during the
    run, and the server logs a line per request, so the pipe buffer fills and the
    server blocks mid-write -- which looks exactly like a hung server and fails
    every test after the first handful.
    """
    import httpx

    environment = {
        **os.environ,
        **MYSQL_ENV,
        "MCP_TRANSPORT": "sse",
        "MCP_SSE_HOST": "127.0.0.1",
        "MCP_SSE_PORT": str(port),
        "MCP_AUTH_MODE": "authplane",
        "AUTHPLANE_ISSUER": ISSUER,
        "AUTHPLANE_RESOURCE": RESOURCE_AUD,
        "AUTHPLANE_DEV_MODE": "true",
        "MCP_AUTH_DPOP": dpop,
        # Pinned, not inherited. The server calls `load_dotenv()`, which does not
        # override variables already set here but does supply any that are
        # missing -- so a developer's local `.env` silently became part of the
        # test configuration. Both of these have to be fixed for the assertions
        # below to mean anything:
        #
        #   throttling: several tests deliberately present a run of bad tokens
        #   and assert 401. With a throttle configured, the later ones get 429
        #   and the suite fails in a way that looks like broken authentication.
        "MCP_AUTH_MAX_AUTH_FAILURES": "0",
        "PYTHONUNBUFFERED": "1",
    }
    environment.pop("MYSQL_RO_USER", None)
    environment.pop("MYSQL_RO_PASSWORD", None)
    #   audit file: inherited, every e2e run appends to whatever file the
    #   developer is tailing. Records still reach stderr, which is captured in
    #   this server's own log.
    environment.pop("MCP_AUTH_AUDIT_FILE", None)

    base = f"http://127.0.0.1:{port}"

    with open(log_path, "w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "mysql_mcp_server"],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )

        def logs() -> str:
            return log_path.read_text(encoding="utf-8", errors="replace")[-4000:]

        deadline = time.time() + 45
        while time.time() < deadline:
            if process.poll() is not None:
                pytest.fail(f"server exited early:\n{logs()}")
            try:
                if httpx.get(f"{base}/", timeout=2).status_code == 200:
                    break
            except Exception:
                time.sleep(0.3)
        else:
            process.kill()
            pytest.fail(f"server did not become ready:\n{logs()}")

        try:
            yield base
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - teardown only
                process.kill()


@pytest.fixture(scope="session")
def server(live, tmp_path_factory):
    log = tmp_path_factory.mktemp("server-optional") / "server.log"
    with running_server(log, PORT, "optional") as base:
        yield base


@pytest.fixture(scope="session")
def strict_server(live, tmp_path_factory):
    """A second server running `MCP_AUTH_DPOP=required`.

    The main fixture runs `optional`, so without this one strict mode never goes
    through the real HTTP stack -- which is precisely where the scheme bug lived.
    """
    log = tmp_path_factory.mktemp("server-required") / "server.log"
    with running_server(log, STRICT_PORT, "required") as base:
        yield base


@asynccontextmanager
async def mcp_session(token: str):
    """An MCP session over SSE, authenticated with a real bearer token."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    headers = {"Authorization": f"Bearer {token}"}
    # sse_read_timeout defaults to 300s. A stalled stream would then wedge the
    # suite for five minutes per test instead of failing, so it is cut down to
    # something a person will wait for.
    async with sse_client(SSE_URL, headers=headers, timeout=10, sse_read_timeout=30) as (
        read,
        write,
    ):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=30)
            yield session


def text_of(result) -> str:
    return " ".join(
        block.text for block in result.content if getattr(block, "type", "") == "text"
    )


# --------------------------------------------------------------------------
# The public surface. A client cannot authenticate without reaching these.
# --------------------------------------------------------------------------


def test_the_metadata_document_is_public(server):
    import httpx

    response = httpx.get(f"{BASE}/.well-known/oauth-protected-resource", timeout=10)

    assert response.status_code == 200, "a client cannot obtain a token without this"
    document = response.json()
    assert document["resource"] == RESOURCE_AUD
    assert document["bearer_methods_supported"] == ["header"]


def test_the_health_probe_is_public(server):
    """Orchestrators probe it before any credential exists."""
    import httpx

    assert httpx.get(f"{BASE}/", timeout=10).status_code == 200


def test_the_metadata_document_advertises_dpop_when_enabled(server):
    """The server was started with `MCP_AUTH_DPOP=optional`."""
    import httpx

    document = httpx.get(f"{BASE}/.well-known/oauth-protected-resource", timeout=10).json()

    assert document["dpop_signing_alg_values_supported"]
    assert document["dpop_bound_access_tokens_required"] is False


# --------------------------------------------------------------------------
# Authentication at the HTTP layer.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/sse", "/messages/"])
def test_both_mcp_endpoints_require_a_token(server, path):
    """Protecting only `/sse` would protect nothing.

    The SSE transport splits one logical call in two: `/sse` issues the session
    id and `/messages/` carries every tool call. A caller holding a session id
    can POST directly, so the POST route has to be protected in its own right.
    """
    import httpx

    response = httpx.request(
        "POST" if path == "/messages/" else "GET", f"{BASE}{path}", timeout=10
    )

    assert response.status_code == 401


def test_an_unauthenticated_request_points_the_client_at_the_metadata(server):
    """The `resource_metadata` challenge is what drives discovery.

    Without it a client has no way to learn where to get a token, and the
    browser-based flow cannot start at all.
    """
    import httpx

    response = httpx.get(SSE_URL, timeout=10)
    challenge = response.headers.get("www-authenticate", "")

    assert response.status_code == 401
    assert "resource_metadata=" in challenge
    assert "/.well-known/oauth-protected-resource" in challenge


@pytest.mark.parametrize(
    "header",
    ["Bearer", "Bearer not-a-jwt", "Bearer a.b.c", "Basic dXNlcjpwYXNz"],
    ids=["no-credentials", "garbage", "shaped-like-a-jwt", "wrong-scheme"],
)
def test_an_invalid_token_is_refused(server, header):
    """Whole header values, not just token bodies.

    `Bearer ` with a trailing space cannot be sent at all -- httpx rejects it as
    an illegal header value before it reaches the wire -- so the empty case is
    expressed as a bare `Bearer` scheme with no credentials.
    """
    import httpx

    response = httpx.get(SSE_URL, headers={"Authorization": header}, timeout=10)

    assert response.status_code == 401


def test_a_token_for_another_resource_is_refused(server, live):
    """The confused-deputy defence, through the full HTTP stack."""
    import httpx

    decoy = live.mint(
        live.new_client("e2e-decoy", DECOY_SCOPE), DECOY_SCOPE, resource=DECOY_RESOURCE_AUD
    )

    response = httpx.get(SSE_URL, headers={"Authorization": f"Bearer {decoy}"}, timeout=10)

    assert response.status_code == 401


def test_a_token_in_the_query_string_is_refused(server, read_token):
    """A query-string token would be copied into proxy logs and Referer headers."""
    import httpx

    response = httpx.get(f"{SSE_URL}?access_token={read_token}", timeout=10)

    assert response.status_code == 401, "the metadata advertises header-only for a reason"


def test_a_valid_token_does_not_bypass_dns_rebinding_protection(server, read_token):
    """Authentication and `MCP_SSE_ALLOWED_HOSTS` are independent controls."""
    import httpx

    response = httpx.get(
        SSE_URL,
        headers={"Authorization": f"Bearer {read_token}", "Host": "evil.example.com"},
        timeout=10,
    )

    assert response.status_code == 421


# --------------------------------------------------------------------------
# Driving the server with the official MCP client.
# --------------------------------------------------------------------------


@requires_mysql
async def test_a_read_token_can_list_tools(server, read_token):
    async with mcp_session(read_token) as session:
        tools = await asyncio.wait_for(session.list_tools(), timeout=30)

    names = {tool.name for tool in tools.tools}
    assert {"execute_sql", "get_schema_info", "get_table_sample"} <= names
    assert not {"read_query", "write_query"} & names, (
        "the removed tools must not still be advertised"
    )


@requires_mysql
async def test_a_read_token_can_run_a_select(server, read_token):
    """The end-to-end success path: token in, rows out."""
    async with mcp_session(read_token) as session:
        result = await asyncio.wait_for(
            session.call_tool("execute_sql", {"query": "SELECT 1 AS one"}), timeout=30
        )

    assert result.isError is not True, text_of(result)
    assert "1" in text_of(result)


@requires_mysql
async def test_a_read_token_is_refused_a_write(server, read_token):
    """A refusal must arrive as a tool error, and must not hang.

    This is the regression guard for the bug the first real-client run found. The
    refusal used to be an HTTP 403 on the POST, which a conforming client ignores
    while it waits for a JSON-RPC response that never came. `wait_for` is the
    assertion: a hang fails the test rather than stalling the suite.

    Note whose refusal it is now: the statement reaches MySQL on the SELECT-only
    account and the *database* refuses it. There is no scope gate on
    `execute_sql`, so the message is MySQL's denial rather than a scope name --
    which is the whole point, since a scope gate on arbitrary SQL could only ever
    have been an opinion about the statement.
    """
    statement = "CREATE TABLE should_not_exist (id INT)"

    async with mcp_session(read_token) as session:
        result = await asyncio.wait_for(
            session.call_tool("execute_sql", {"query": statement}), timeout=30
        )

    assert result.isError is True
    assert "not permitted" in text_of(result).lower()


@requires_mysql
async def test_a_read_token_is_refused_a_write_hidden_in_a_comment(server, read_token):
    """The syntax a classifier misses and a privilege system does not see at all.

    `/* c */ DROP TABLE` was the classifier's problem. On the SELECT-only account
    it makes no difference: MySQL refuses the DROP whatever it is wrapped in.
    """
    async with mcp_session(read_token) as session:
        result = await asyncio.wait_for(
            session.call_tool("execute_sql", {"query": "/* c */ DROP TABLE anything"}),
            timeout=30,
        )

    assert result.isError is True


@requires_mysql
async def test_a_write_token_can_write(server, write_token):
    """The other half of the scope split: a write-scoped token is allowed through."""
    table = f"e2e_probe_{uuid.uuid4().hex[:8]}"

    async with mcp_session(write_token) as session:
        created = await asyncio.wait_for(
            session.call_tool("execute_sql", {"query": f"CREATE TABLE {table} (id INT)"}),
            timeout=30,
        )
        assert created.isError is not True, text_of(created)

        try:
            inserted = await asyncio.wait_for(
                session.call_tool("execute_sql", {"query": f"INSERT INTO {table} VALUES (7)"}),
                timeout=30,
            )
            assert inserted.isError is not True, text_of(inserted)

            read_back = await asyncio.wait_for(
                session.call_tool("execute_sql", {"query": f"SELECT id FROM {table}"}),
                timeout=30,
            )
            assert "7" in text_of(read_back)
        finally:
            await asyncio.wait_for(
                session.call_tool("execute_sql", {"query": f"DROP TABLE IF EXISTS {table}"}),
                timeout=30,
            )


def dpop_auth(provider, token: str):
    """An ``httpx.Auth`` that signs a fresh DPoP proof for every request.

    Static headers cannot work over this transport, and the reason is worth
    stating: the SSE transport uses two different requests -- ``GET /sse`` and
    ``POST /messages/`` -- and a proof is bound to one method and one URL. Proofs
    are also single-use, so even repeating the same call needs a new one. A
    DPoP-capable client therefore has to sign per request, which is what this
    does.

    The ``htu`` is built from the configured resource rather than the connection
    host, matching how the server reconstructs it.
    """
    import httpx

    class _DPoPAuth(httpx.Auth):
        requires_request_body = False

        def auth_flow(self, request):
            htu = f"{RESOURCE}{request.url.path}"
            request.headers["Authorization"] = f"DPoP {token}"
            request.headers["DPoP"] = provider.build_proof(
                request.method, htu, access_token=token
            )
            yield request

    return _DPoPAuth()


@requires_mysql
async def test_a_dpop_bound_token_works_end_to_end(server, live):
    """A sender-constrained token driving a real MCP session.

    Note the two different hosts. The connection is made to `127.0.0.1`, but each
    proof is signed for `AUTHPLANE_RESOURCE`, because the server builds the URL it
    checks a proof against from the *configured* resource, never from the
    caller-controlled `Host` header. That is deliberate: otherwise a caller could
    choose what their own proof has to match. It also means this test exercises
    the same path a deployment behind a reverse proxy takes, where what the client
    signs and what the server sees genuinely differ.
    """
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    provider = new_dpop_provider()
    credentials = live.new_client("e2e-dpop", READ_SCOPE)
    token = live.mint(credentials, READ_SCOPE, dpop_provider=provider)

    async with sse_client(
        SSE_URL, auth=dpop_auth(provider, token), timeout=10, sse_read_timeout=30
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=30)
            result = await asyncio.wait_for(
                session.call_tool("execute_sql", {"query": "SELECT 1 AS one"}), timeout=30
            )

    assert result.isError is not True, text_of(result)
    assert "1" in text_of(result)


@requires_mysql
def test_a_dpop_bound_token_is_refused_under_the_bearer_scheme(server, live):
    """RFC 9449 §7.1 is a requirement, not a preference.

    The companion to the test above: the same bound token, presented the wrong
    way. Kept because the fix that made DPoP work over HTTP widened the accepted
    schemes, and widening it further -- to the point where the scheme stopped
    mattering -- should be a deliberate decision, not a regression.
    """
    import httpx

    provider = new_dpop_provider()
    credentials = live.new_client("e2e-dpop-scheme", READ_SCOPE)
    token = live.mint(credentials, READ_SCOPE, dpop_provider=provider)

    response = httpx.get(
        SSE_URL,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )

    assert response.status_code == 401, "a bound token still needs its proof"


@requires_mysql
def test_a_proof_signed_for_another_origin_is_refused(server, live):
    """The reason the proof URL is not derived from the `Host` header."""
    import httpx

    provider = new_dpop_provider()
    credentials = live.new_client("e2e-dpop-origin", READ_SCOPE)
    token = live.mint(credentials, READ_SCOPE, dpop_provider=provider)

    response = httpx.get(
        SSE_URL,
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": provider.build_proof(
                "GET", "http://evil.example.com/sse", access_token=token
            ),
        },
        timeout=10,
    )

    assert response.status_code == 401


# --------------------------------------------------------------------------
# Session binding.
# --------------------------------------------------------------------------


@requires_mysql
async def test_a_session_cannot_be_driven_by_another_subject(server, live, read_token):
    """A session id leaked to another identity must not become usable.

    Opened by one subject, then POSTed to by a different, perfectly valid one.
    Raw HTTP rather than the MCP client, because the client has no way to swap
    credentials halfway through a session -- which is exactly the abuse.
    """
    import httpx

    other = live.mint(live.new_client("e2e-other", READ_SCOPE), READ_SCOPE)

    async with httpx.AsyncClient(timeout=20) as client:
        async with client.stream(
            "GET", SSE_URL, headers={"Authorization": f"Bearer {read_token}"}
        ) as stream:
            assert stream.status_code == 200
            endpoint = ""
            async for line in stream.aiter_lines():
                if line.startswith("data: ") and "session_id=" in line:
                    endpoint = line[len("data: "):].strip()
                    break
            assert endpoint, "the transport should announce a message endpoint"

            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "execute_sql", "arguments": {"query": "SELECT 1"}},
            }
            hijacked = await client.post(
                f"{BASE}{endpoint}",
                headers={
                    "Authorization": f"Bearer {other}",
                    "Content-Type": "application/json",
                },
                content=json.dumps(payload),
            )

    assert hijacked.status_code >= 400, (
        "a session opened by one subject must not accept another subject's token"
    )


# --------------------------------------------------------------------------
# MCP_AUTH_DPOP=required, over the wire.
# --------------------------------------------------------------------------


def test_strict_mode_refuses_a_bearer_token(strict_server, read_token):
    """`required` means what it says: no proof, no access."""
    import httpx

    response = httpx.get(
        STRICT_SSE_URL, headers={"Authorization": f"Bearer {read_token}"}, timeout=10
    )

    assert response.status_code == 401


def test_strict_mode_challenges_with_dpop_and_not_bearer(strict_server):
    """The 401 has to name a scheme the client can actually succeed with.

    A `Bearer`-only challenge here would point every client at the one scheme
    this server refuses.
    """
    import httpx

    response = httpx.get(STRICT_SSE_URL, timeout=10)
    challenges = response.headers.get_list("www-authenticate")
    schemes = {challenge.split(" ", 1)[0] for challenge in challenges}

    assert response.status_code == 401
    assert schemes == {"DPoP"}, f"expected only a DPoP challenge, got {schemes}"
    assert any("algs=" in challenge for challenge in challenges)
    assert any("resource_metadata=" in challenge for challenge in challenges)


def test_strict_mode_advertises_bound_tokens_as_mandatory(strict_server):
    import httpx

    document = httpx.get(
        f"{STRICT_BASE}/.well-known/oauth-protected-resource", timeout=10
    ).json()

    assert document["dpop_bound_access_tokens_required"] is True


@requires_mysql
async def test_strict_mode_accepts_a_bound_token_with_a_proof(strict_server, live):
    """The other half: strict mode is usable by a client that can produce proofs."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    provider = new_dpop_provider()
    credentials = live.new_client("e2e-strict", READ_SCOPE)
    token = live.mint(credentials, READ_SCOPE, dpop_provider=provider)

    async with sse_client(
        STRICT_SSE_URL, auth=dpop_auth(provider, token), timeout=10, sse_read_timeout=30
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=30)
            result = await asyncio.wait_for(
                session.call_tool("execute_sql", {"query": "SELECT 1 AS one"}), timeout=30
            )

    assert result.isError is not True, text_of(result)
