"""Authentication and per-tool authorization, tested against a fake verifier.

Hermetic on purpose: no authorization server, no database, no network. The
middleware's job is to decide *whether* a request proceeds, and that logic must
be testable without standing up an OAuth deployment. `test_live_authplane.py`
covers the real-token path.

The fake verifier is not a shortcut around the interesting parts — it is what
proves the seam works. The middleware imports nothing from any provider, so a
15-line stand-in satisfies it completely.
"""

import json

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient

from mysql_mcp_server.auth import PRM_PATH, AuthMiddleware
from mysql_mcp_server.auth.middleware import (
    MAX_BODY_BYTES,
    SessionBinding,
    bearer_token,
    is_protected,
    prm_path_for,
)
from mysql_mcp_server.auth.protocol import (
    AuthenticationError,
    AuthorizationError,
    Identity,
    TokenVerifier,
    VerifierUnavailableError,
)

RESOURCE = "http://testserver"
METADATA_URL = f"{RESOURCE}{PRM_PATH}"


class FakeVerifier:
    """Maps a handful of fixed token strings to outcomes.

    Token format is `ok:<subject>:<space-separated scopes>`; anything else is
    rejected. That keeps each test's intent visible in the request itself.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def verify(self, token: str, request=None) -> Identity:
        self.calls.append(token)
        if token == "expired":
            raise AuthenticationError("Token has expired", error="invalid_token")
        if token == "wrong-audience":
            raise AuthenticationError("Audience mismatch", error="invalid_token")
        if token == "no-scope":
            raise AuthorizationError("Token lacks the required scope")
        if token == "boom":
            raise RuntimeError("verifier exploded")  # must not leak to the caller
        if not token.startswith("ok:"):
            raise AuthenticationError("Signature verification failed")
        _, subject, _, scopes = token.partition(":")[2].partition(":")[0], *token.split(":", 2)[1:], ""
        parts = token.split(":", 2)
        subject = parts[1]
        granted = frozenset(parts[2].split()) if len(parts) > 2 and parts[2] else frozenset()
        return Identity(subject=subject, scopes=granted, client_id=subject, token_id="jti-1")

    def protected_resource_metadata(self) -> dict:
        return {"resource": RESOURCE, "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return METADATA_URL

    async def aclose(self) -> None:
        return None


def build_app(**middleware_kwargs):
    """A stand-in for the SSE app: same paths, trivial handlers."""
    verifier = FakeVerifier()

    async def health(request):
        return PlainTextResponse("ok")

    async def sse(request):
        return PlainTextResponse("event: endpoint\ndata: /messages/?session_id=abc123\n\n")

    async def messages(request):
        body = await request.body()
        return PlainTextResponse(f"accepted:{len(body)}")

    kwargs = {
        "verifier": verifier,
        "realm": "test-realm",
        "tool_scopes": {
            "read_query": ("mysql:read",),
            "write_query": ("mysql:write",),
            "execute_sql": ("mysql:write",),
            "*": ("mysql:write",),
        },
        "read_only_tools": ("read_query",),
        # The HTTP-layer denial path is opt-in; these tests target it directly.
        "deny_at_http_layer": True,
    }
    kwargs.update(middleware_kwargs)

    async def prm(request):
        from starlette.responses import JSONResponse

        return JSONResponse(verifier.protected_resource_metadata())

    app = Starlette(
        routes=[
            Route("/", endpoint=health),
            Route(PRM_PATH, endpoint=prm),
            Route("/sse", endpoint=sse),
            Mount("/messages/", routes=[Route("/", endpoint=messages, methods=["POST"])]),
        ]
    )
    return TestClient(AuthMiddleware(app, **kwargs)), verifier


def tools_call(name: str, query: str = "SELECT 1") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": {"query": query}},
    }


READ_TOKEN = "ok:alice:mysql:read"  # note: scope string contains a colon
ALICE_READ = "ok:alice:mysql:read"
ALICE_BOTH = "ok:alice:mysql:read mysql:write"
BOB_BOTH = "ok:bob:mysql:read mysql:write"


# --------------------------------------------------------------------------
# Public paths. Both must work with no credentials, and for distinct reasons.
# --------------------------------------------------------------------------

def test_health_endpoint_is_public():
    """Container orchestrators probe `/` before any credential exists."""
    client, _ = build_app()
    assert client.get("/").status_code == 200


def test_metadata_document_is_public():
    """RFC 9728 discovery must be readable unauthenticated.

    If a token were required to learn where tokens come from, the handshake
    could never start and MCP clients would need hand-configured endpoints.
    """
    client, _ = build_app()
    response = client.get(PRM_PATH)
    assert response.status_code == 200
    body = response.json()
    assert body["resource"] == RESOURCE
    assert body["authorization_servers"], "a client must learn which AS to use"


def test_public_paths_never_reach_the_verifier():
    """Not just allowed — not even inspected. Cheap, and keeps `/` probe-safe."""
    client, verifier = build_app()
    client.get("/")
    client.get(PRM_PATH)
    assert verifier.calls == []


# --------------------------------------------------------------------------
# Both MCP endpoints are protected. This is the finding the whole change turns
# on: `/sse` hands out the session id, so protecting it alone protects nothing.
# --------------------------------------------------------------------------

def test_sse_requires_a_token():
    client, _ = build_app()
    response = client.get("/sse")
    assert response.status_code == 401


def test_messages_requires_a_token_even_with_a_session_id():
    """The two-endpoint trap. If this passes, the whole change is cosmetic.

    Every tool call arrives here. A caller who has (or guesses) a session id can
    reach this endpoint without ever touching `/sse`.
    """
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123", json=tools_call("read_query")
    )
    assert response.status_code == 401


def test_unauthenticated_rejection_advertises_where_to_get_a_token():
    """The 401 must carry `resource_metadata`.

    This header is what lets MCP Inspector and Claude Desktop complete an OAuth
    flow with nothing configured by hand: 401 -> read PRM -> discover AS.
    """
    client, _ = build_app()
    challenge = client.get("/sse").headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'realm="test-realm"' in challenge
    assert f'resource_metadata="{METADATA_URL}"' in challenge


# --------------------------------------------------------------------------
# Token extraction.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "header,expected_error",
    [
        ("Basic dXNlcjpwYXNz", "invalid_request"),
        ("Bearer", "invalid_request"),
        ("Bearer    ", "invalid_request"),
        ("bearer", "invalid_request"),
        ("Token abc", "invalid_request"),
        ("", "invalid_request"),
    ],
)
def test_non_bearer_headers_are_rejected_as_bad_requests(header, expected_error):
    """A wrong scheme is a malformed request, not an untrustworthy token.

    The distinction matters to a client deciding whether retrying could help.
    """
    client, _ = build_app()
    response = client.get("/sse", headers={"Authorization": header})
    assert response.status_code == 401
    assert response.json()["error"] == expected_error


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "BeArEr"])
def test_bearer_scheme_is_case_insensitive(scheme):
    """RFC 7235 §2.1: the scheme is case-insensitive. Clients rely on this."""
    client, _ = build_app()
    response = client.get("/sse", headers={"Authorization": f"{scheme} {ALICE_READ}"})
    assert response.status_code == 200


def test_query_string_token_is_not_accepted():
    """A token in the URL leaks into proxy logs and `Referer` headers.

    The PRM document advertises `bearer_methods_supported: ["header"]`, and this
    test is what makes that claim true rather than aspirational.
    """
    client, _ = build_app()
    response = client.get(f"/sse?access_token={ALICE_READ}")
    assert response.status_code == 401


def test_bearer_token_helper_reports_specific_failures():
    assert bearer_token([]) == (None, "", "Missing Authorization header")
    token, scheme, error = bearer_token([(b"authorization", b"Bearer abc")])
    assert (token, scheme, error) == ("abc", "bearer", None)
    token, _, error = bearer_token([(b"authorization", b"Basic abc")])
    assert token is None and "Bearer" in error


@pytest.mark.parametrize(
    "header,expected_scheme",
    [
        (b"DPoP abc", "dpop"),
        (b"dpop abc", "dpop"),
        (b"Bearer abc", "bearer"),
        (b"BEARER abc", "bearer"),
    ],
)
def test_a_dpop_bound_token_is_accepted_under_the_dpop_scheme(header, expected_scheme):
    """RFC 9449 §7.1 presents a bound token as ``Authorization: DPoP <token>``.

    Rejecting that scheme refused every conforming DPoP client with a 401 before
    its proof was ever examined, which made the whole DPoP feature unusable over
    HTTP. It went unnoticed because the DPoP tests inject tokens through a fake
    verifier and never build this header, and RFC 7235 §2.1 makes the comparison
    case-insensitive so all four spellings must work.
    """
    token, scheme, error = bearer_token([(b"authorization", header)])

    assert (token, scheme, error) == ("abc", expected_scheme, None)


def test_rejection_reason_cannot_inject_headers():
    """A scheme containing CRLF must not split the response.

    The scheme is echoed into `WWW-Authenticate`; unescaped CR/LF there is a
    response-splitting vector.
    """
    client, _ = build_app()
    response = client.get("/sse", headers={"Authorization": "Ba\rd\nScheme token"})
    assert response.status_code in (400, 401)
    for value in response.headers.values():
        assert "\r" not in value and "\n" not in value


# --------------------------------------------------------------------------
# Verifier outcomes map to the right status.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("token", ["garbage", "notajwt", "expired", "wrong-audience"])
def test_untrustworthy_tokens_are_401(token):
    client, _ = build_app()
    response = client.get("/sse", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_authorization_failure_is_403_not_401():
    """Retrying with the same token cannot help, so 401 would loop the client.

    RFC 6750 §3.1 reserves `insufficient_scope` for a valid token that is not
    permitted.
    """
    client, _ = build_app()
    response = client.get("/sse", headers={"Authorization": "Bearer no-scope"})
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"


def test_unexpected_verifier_error_fails_closed_without_leaking():
    """An exception the verifier never promised must not fail open.

    Nor may it echo internals: `verifier exploded` is for the log, not the wire.

    Reported as 500, not 401: an exception outside the taxonomy is a bug here or
    in the verifier, and says nothing about the caller's token. Telling the
    caller its credential is bad would send it to re-authenticate for a fault it
    cannot fix.
    """
    client, _ = build_app()
    response = client.get("/sse", headers={"Authorization": "Bearer boom"})
    assert response.status_code == 500
    assert response.json()["error"] == "server_error"
    assert "exploded" not in response.text
    assert "Traceback" not in response.text
    # No challenge: nothing is being asserted about the credential.
    assert "www-authenticate" not in {k.lower() for k in response.headers}


# --------------------------------------------------------------------------
# Discovery must be served at the path the challenge names.
#
# RFC 9728 §3 forms the well-known URL by inserting the segment between host and
# the resource's own path, so a resource with a path moves the document. The
# route used to be registered at a fixed constant while the challenge came from
# the SDK's suffix-aware `prm_url()`: with a path-bearing resource the 401 named
# a URL nothing served, and discovery failed with nothing in the log.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "metadata_url,expected",
    [
        # Root resource: unchanged, which is why this was invisible.
        ("http://testserver/.well-known/oauth-protected-resource", PRM_PATH),
        # Path-bearing resource: the path becomes a suffix.
        (
            "https://mcp.example.com/.well-known/oauth-protected-resource/mysql",
            "/.well-known/oauth-protected-resource/mysql",
        ),
        (
            "https://mcp.example.com/.well-known/oauth-protected-resource/v2/mysql",
            "/.well-known/oauth-protected-resource/v2/mysql",
        ),
        # Degenerate input falls back rather than producing an empty route path.
        ("", PRM_PATH),
    ],
)
def test_prm_route_path_follows_the_resource(metadata_url, expected):
    assert prm_path_for(metadata_url) == expected


class PathResourceVerifier(FakeVerifier):
    """A resource mounted under a path, as `AUTHPLANE_RESOURCE=.../mysql`."""

    RESOURCE = "https://mcp.example.com/mysql"
    METADATA = "https://mcp.example.com/.well-known/oauth-protected-resource/mysql"

    def protected_resource_metadata(self) -> dict:
        return {"resource": self.RESOURCE, "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return self.METADATA


def test_a_path_bearing_resource_keeps_its_discovery_route_public():
    """The deadlock this prevents: gating discovery makes the handshake
    unsatisfiable, because a client cannot get a token without reading it."""
    client, _ = build_app(verifier=PathResourceVerifier())

    suffixed = "/.well-known/oauth-protected-resource/mysql"
    assert is_protected(suffixed, client.app.public_paths) is False
    # The exemption follows the resource: it is the suffixed path that is
    # explicitly public now, not the root form. (Neither matches a protected
    # prefix, so `is_protected` answers False for both -- the list is what the
    # server registers a route at, and what a future prefix change would key on.)
    assert suffixed in client.app.public_paths
    assert PRM_PATH not in client.app.public_paths


def test_the_challenge_names_the_path_the_route_is_served_at():
    """The two halves must agree; they came from different sources before."""
    client, _ = build_app(verifier=PathResourceVerifier())
    response = client.get("/sse")

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert f'resource_metadata="{PathResourceVerifier.METADATA}"' in challenge
    # The advertised URL's path is exactly what the middleware treats as public.
    assert prm_path_for(PathResourceVerifier.METADATA) in client.app.public_paths


# --------------------------------------------------------------------------
# DPoP `htu` is signed over the on-wire path.
# --------------------------------------------------------------------------

def test_htu_uses_the_percent_encoded_path():
    """ASGI decodes `scope["path"]`; the client signed the raw target.

    A path containing `%2F` reconstructed as `/` produces a different `htu` than
    the client signed, so a valid proof fails -- and passes against the
    TypeScript sibling, which builds `htu` from the raw request URL.
    """
    client, _ = build_app()
    middleware = client.app

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/messages/a/b",          # decoded by ASGI
        "raw_path": b"/messages/a%2Fb",   # what actually arrived
        "headers": [],
    }
    assert middleware._request_context(scope).url.endswith("/messages/a%2Fb")


def test_htu_excludes_the_query_string():
    """RFC 9449 §4.2 defines `htu` without query -- and `/messages/` carries a
    per-session id that would otherwise change the URL on every request."""
    client, _ = build_app()
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/messages/",
        "raw_path": b"/messages/?session_id=abc123",
        "headers": [],
    }
    url = client.app._request_context(scope).url
    assert url.endswith("/messages/")
    assert "session_id" not in url


def test_htu_falls_back_when_the_server_omits_raw_path():
    """`raw_path` is optional in the ASGI spec."""
    client, _ = build_app()
    scope = {"type": "http", "method": "GET", "path": "/sse", "headers": []}
    assert client.app._request_context(scope).url.endswith("/sse")


# --------------------------------------------------------------------------
# An authorization-server outage is not a bad token.
#
# Collapsing 503 into 401 is what turns an AS outage into a stampede: every
# client is told its credential is bad, so every client discards a working token
# and re-authenticates against the server that is already down -- and, with the
# failure throttle on, gets locked out here for doing so.
# --------------------------------------------------------------------------

class UnavailableVerifier(FakeVerifier):
    """Stands in for the SDK raising JWKSFetchError / CircuitOpenError."""

    def __init__(self, status: int = 503) -> None:
        super().__init__()
        self._status = status

    async def verify(self, token: str, request=None) -> Identity:
        self.calls.append(token)
        raise VerifierUnavailableError(
            "JWKS fetch failed for https://as.internal/.well-known/jwks.json",
            status=self._status,
            error="temporarily_unavailable" if self._status == 503 else "server_error",
            retry_after=5 if self._status == 503 else 0,
        )


def test_as_outage_is_503_not_401():
    client, _ = build_app(verifier=UnavailableVerifier(503))
    response = client.get("/sse", headers={"Authorization": "Bearer ok:alice:mysql:read"})

    assert response.status_code == 503
    assert response.json()["error"] == "temporarily_unavailable"
    # The description must steer the client away from throwing its token away.
    assert "do not discard" in response.json()["error_description"].lower()


def test_as_outage_sends_no_challenge_and_a_retry_after():
    """The challenge is the invitation to re-authenticate. Do not extend it."""
    client, _ = build_app(verifier=UnavailableVerifier(503))
    response = client.get("/sse", headers={"Authorization": "Bearer ok:alice:mysql:read"})

    header_names = {k.lower() for k in response.headers}
    assert "www-authenticate" not in header_names
    assert response.headers["retry-after"] == "5"


def test_as_outage_never_leaks_the_internal_url():
    """The SDK's message names the JWKS endpoint. That is for the log."""
    client, _ = build_app(verifier=UnavailableVerifier(503))
    response = client.get("/sse", headers={"Authorization": "Bearer ok:alice:mysql:read"})

    assert "as.internal" not in response.text
    assert "jwks" not in response.text.lower()


def test_as_outage_does_not_count_against_the_failure_throttle():
    """The load-bearing half of the fix.

    Without this, an AS outage refuses the client *twice*: once for the outage,
    then for the whole throttle window after the AS recovers -- because the
    client did exactly what the 401 told it to do.
    """
    from mysql_mcp_server.auth.throttle import FailureThrottle

    throttle = FailureThrottle(max_failures=2, window_seconds=60.0)
    client, _ = build_app(verifier=UnavailableVerifier(503), throttle=throttle)

    for _ in range(5):
        response = client.get("/sse", headers={"Authorization": "Bearer ok:alice:mysql:read"})
        # Still 503 on every attempt -- never 429.
        assert response.status_code == 503


def test_internal_verifier_fault_is_500():
    client, _ = build_app(verifier=UnavailableVerifier(500))
    response = client.get("/sse", headers={"Authorization": "Bearer ok:alice:mysql:read"})

    assert response.status_code == 500
    assert response.json()["error"] == "server_error"
    assert "www-authenticate" not in {k.lower() for k in response.headers}


def test_a_genuinely_bad_token_is_still_401_with_a_challenge():
    """The regression guard for the change above: 401 must keep working.

    An expired token *is* something the client can fix by re-authenticating, so
    it keeps both the status and the challenge that tell it to.
    """
    client, _ = build_app()
    response = client.get("/sse", headers={"Authorization": "Bearer expired"})

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert "www-authenticate" in {k.lower() for k in response.headers}


def test_no_traceback_in_any_rejection_body():
    client, _ = build_app()
    for token in ["garbage", "boom", "expired", "no-scope"]:
        response = client.get("/sse", headers={"Authorization": f"Bearer {token}"})
        assert "Traceback" not in response.text
        assert "File \"" not in response.text


# --------------------------------------------------------------------------
# Per-tool scope enforcement. Done by inspecting the JSON-RPC body, because a
# tool handler cannot see the request: the MCP server consumes tool calls from
# the *stream's* task, not the POST's task, so no contextvar reaches it.
# --------------------------------------------------------------------------

def test_read_scope_can_call_a_read_tool():
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("read_query"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert response.status_code == 200


def test_read_scope_cannot_call_a_write_tool():
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("write_query", "DROP TABLE demo"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"


def test_scope_denial_tells_the_client_which_scope_is_needed():
    """Otherwise the caller cannot fix the problem without guessing."""
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("write_query"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert 'scope="mysql:write"' in response.headers["www-authenticate"]
    assert "mysql:write" in response.json()["error_description"]


def test_deprecated_execute_sql_requires_the_write_scope():
    """It accepts arbitrary SQL, so the read scope must not reach it.

    Allowing `execute_sql` under `mysql:read` would authorize `DROP TABLE` for a
    read-only caller — the exact reason the tool was split.
    """
    client, _ = build_app()
    denied = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("execute_sql", "SELECT 1"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("execute_sql", "SELECT 1"),
        headers={"Authorization": f"Bearer {ALICE_BOTH}"},
    )
    assert allowed.status_code == 200


def test_unmapped_tool_name_falls_back_to_the_strictest_scope():
    """A tool added later must not ship unprotected by omission."""
    client, _ = build_app()
    denied = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("some_future_tool"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert denied.status_code == 403


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ],
)
def test_non_tool_call_methods_need_authentication_but_no_tool_scope(payload):
    """The handshake must work for any authenticated caller.

    Requiring a tool scope to call `initialize` would make a read-only token
    unable to open a session at all.
    """
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=payload,
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert response.status_code == 200


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'{"method": 42}', b"null"])
def test_unparseable_bodies_are_authenticated_but_not_scope_checked(body):
    """An unparseable body cannot name a tool, so it cannot reach anything privileged.

    It still needs a valid token; it just needs no *tool* scope. The transport
    rejects the malformed frame itself.
    """
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        content=body,
        headers={"Authorization": f"Bearer {ALICE_READ}", "Content-Type": "application/json"},
    )
    assert response.status_code == 200


def test_body_is_forwarded_intact_after_inspection():
    """The body is buffered to read the tool name, then replayed downstream.

    If the replay were wrong, every tool call would arrive truncated or empty —
    a failure that looks like an MCP bug, not an auth bug.
    """
    client, _ = build_app()
    payload = tools_call("read_query", "SELECT " + "1," * 500 + "1")
    raw = json.dumps(payload).encode()
    response = client.post(
        "/messages/?session_id=abc123",
        content=raw,
        headers={"Authorization": f"Bearer {ALICE_READ}", "Content-Type": "application/json"},
    )
    assert response.status_code == 200
    assert response.text == f"accepted:{len(raw)}"


def test_oversized_body_is_rejected_not_buffered():
    """The body must be read in full to find the tool name; unbounded would pin memory."""
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        content=b"x" * (MAX_BODY_BYTES + 1024),
        headers={"Authorization": f"Bearer {ALICE_READ}", "Content-Type": "application/json"},
    )
    assert response.status_code == 413


# --------------------------------------------------------------------------
# A write sent to the read-only tool is refused here, with a status, rather
# than after the transport has already answered 202.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "query",
    [
        "DROP TABLE demo",
        "DELETE FROM demo",
        "SELECT 1; DROP TABLE demo",
        "/* c */ DROP TABLE demo",
        "WITH x AS (SELECT 1) INSERT INTO demo SELECT 4, 'y'",
        "SELECT * FROM demo INTO OUTFILE '/tmp/leak.csv'",
        "SELECT LOAD_FILE('/etc/passwd')",
    ],
)
def test_write_statement_on_read_tool_is_refused_with_a_status(query):
    """403 while an HTTP response still exists.

    After the transport answers 202 the tool runs in the stream's task, and a
    refusal can only come back as a JSON-RPC error. Catching it here gives the
    caller a status code it can act on.
    """
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("read_query", query),
        headers={"Authorization": f"Bearer {ALICE_BOTH}"},
    )
    assert response.status_code == 403, f"{query!r} must not reach the read tool"


def test_read_tool_refusal_explains_itself_without_naming_the_database_account():
    """The caller learns what to fix; it does not learn the MySQL user or host."""
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("read_query", "SELECT * FROM demo INTO OUTFILE '/tmp/x'"),
        headers={"Authorization": f"Bearer {ALICE_BOTH}"},
    )
    description = response.json()["error_description"]
    assert "OUTFILE" in description
    assert "@" not in description, "no user@host may appear in a client-visible message"


def test_write_tool_still_accepts_writes():
    """The split must not break the write path."""
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("write_query", "DROP TABLE demo"),
        headers={"Authorization": f"Bearer {ALICE_BOTH}"},
    )
    assert response.status_code == 200


def test_read_tool_accepts_reads():
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("read_query", "SELECT * FROM demo WHERE id = 1"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert response.status_code == 200


def test_scope_is_checked_before_statement_content():
    """Order matters: a caller without the scope learns that, not SQL advice.

    Telling an unauthorized caller "your statement is a write" would confirm the
    tool exists and how it parses input before establishing they may use it.
    """
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("write_query", "DROP TABLE demo"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"


def test_scope_enforcement_can_be_disabled_for_authentication_only_mode():
    client, _ = build_app(enforce_scopes=False)
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("write_query"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert response.status_code == 200


# --------------------------------------------------------------------------
# Session-to-subject binding (the "T2" case).
#
# Authentication is per-request, so without a binding a *valid* token belonging
# to Bob is accepted on a session Alice opened. Both requests authenticate
# correctly in isolation; nothing connects them. On a tool that runs SQL that is
# a cross-tenant hole.
# --------------------------------------------------------------------------

def test_session_is_bound_to_the_subject_that_opened_it():
    client, _ = build_app()
    stream = client.get("/sse", headers={"Authorization": f"Bearer {ALICE_READ}"})
    assert stream.status_code == 200
    assert "session_id=abc123" in stream.text

    # This fixture's `/sse` returns a completed response rather than holding a
    # stream open, so the middleware has already seen the stream end and released
    # the binding -- correctly, and the same thing it does when a real stream
    # closes. Re-seeded here because the subject of this test is the POST-side
    # check, not the binding's lifetime.
    client.app.sessions.remember("abc123", "alice")

    own = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("read_query"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert own.status_code == 200, "the subject that opened the session must be able to use it"

    other = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("read_query"),
        headers={"Authorization": f"Bearer {BOB_BOTH}"},
    )
    assert other.status_code == 403, (
        "Bob's token is valid, but this session is Alice's -- both facts are true "
        "and only the pairing is wrong"
    )


def test_unknown_session_id_is_not_treated_as_bound():
    """A session this process never saw is unbound, not forbidden.

    Otherwise a restart would lock out every live client, and a load-balanced
    deployment would reject sessions opened on a sibling process.
    """
    client, _ = build_app()
    response = client.post(
        "/messages/?session_id=neverseen",
        json=tools_call("read_query"),
        headers={"Authorization": f"Bearer {ALICE_READ}"},
    )
    assert response.status_code == 200


def test_session_binding_can_be_disabled():
    """Single-tenant deployments may not want it; it must not be mandatory."""
    client, _ = build_app(bind_session_to_subject=False)
    client.get("/sse", headers={"Authorization": f"Bearer {ALICE_READ}"})
    response = client.post(
        "/messages/?session_id=abc123",
        json=tools_call("read_query"),
        headers={"Authorization": f"Bearer {BOB_BOTH}"},
    )
    assert response.status_code == 200


def test_session_table_is_bounded_and_evicts_toward_unbound():
    """A caller with one valid token must not be able to grow the table forever.

    Eviction must degrade to "unbound", never to "bound to someone else" —
    otherwise eviction itself would hand out access.
    """
    binding = SessionBinding(limit=3)
    for i in range(10):
        binding.remember(f"session-{i}", f"subject-{i}")
    assert len(binding) <= 3
    for i in range(10):
        owner = binding.owner(f"session-{i}")
        assert owner in (None, f"subject-{i}"), "a session must never be reassigned"


# --------------------------------------------------------------------------
# Path matching. `is_protected` uses prefixes, which is only sound because
# Starlette routes on the exact path with no dot-segment normalisation.
# `test_path_normalisation.py` pins that assumption over a real socket.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/sse", "/sse/", "/sse?x=1".split("?")[0], "/messages/", "/messages", "/messages/anything"])
def test_mcp_paths_are_protected(path):
    assert is_protected(path) is True


@pytest.mark.parametrize("path", ["/", PRM_PATH])
def test_public_paths_are_not_protected(path):
    assert is_protected(path) is False


@pytest.mark.parametrize("path", ["//sse", "/SSE", "/foo/../sse", "/other"])
def test_paths_that_reach_no_mcp_handler_are_not_claimed(path):
    """These are not protected because Starlette routes none of them to a handler.

    Verified over a raw socket in `test_path_normalisation.py`: if Starlette ever
    starts normalising, that test fails and this assumption must be revisited.
    """
    assert is_protected(path) is False


def test_options_preflight_is_not_blocked():
    """A browser strips credentials from preflight, and it reaches no DB handler.

    Rejecting it would break browser clients while protecting nothing.
    """
    client, _ = build_app()
    response = client.options("/messages/?session_id=abc123")
    assert response.status_code != 401


def test_fake_verifier_satisfies_the_protocol():
    """The seam is real: a provider-agnostic stand-in is a complete verifier.

    If this fails, the middleware has grown a dependency on something outside
    `TokenVerifier`, and swapping providers is no longer a drop-in.
    """
    assert isinstance(FakeVerifier(), TokenVerifier)
