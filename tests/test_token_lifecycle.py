"""Token lifetime: expiry, revocation, clock skew, and the long-lived stream.

The legacy SSE transport makes lifetime a genuinely awkward question. A stream
is authenticated **once**, when it opens, and then stays open for as long as the
client wants -- minutes or hours. Every tool call arrives on a *separate* POST
that is authenticated individually. So "is this caller still allowed?" has two
different answers depending on which request you ask about.

These tests pin the policy that was chosen, so that a future change to it is a
deliberate decision rather than an accident.
"""

import asyncio
import time

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route

from mysql_mcp_server.auth import PRM_PATH, AuthMiddleware, AuthSettings
from mysql_mcp_server.auth.protocol import (
    AuthenticationError,
    Identity,
    VerifierConfigError,
)

RESOURCE = "http://testserver"


class LifetimeVerifier:
    """A verifier whose verdicts can be changed mid-test.

    Tokens are `ok:<subject>`, optionally suffixed `#<nonce>` to model a refresh:
    a different token string carrying the *same* subject, which is what a client
    actually gets back from a refresh grant.

    Adding a token to `expired` or `revoked` makes every subsequent verification
    of it fail, which is how a token that was good when a stream opened becomes
    bad while the stream is still open.
    """

    def __init__(self) -> None:
        self.expired: set[str] = set()
        self.revoked: set[str] = set()
        self.introspections = 0
        self.calls: list[str] = []

    async def verify(self, token: str, request=None) -> Identity:
        self.calls.append(token)
        if token in self.expired:
            raise AuthenticationError("token expired", error="invalid_token")
        if token in self.revoked:
            # A revoked token is cryptographically perfect: correct signature,
            # correct audience, exp still in the future. Only the authorization
            # server knows it is dead, which is why detecting this requires
            # asking (RFC 7662 introspection) rather than local validation.
            self.introspections += 1
            raise AuthenticationError("token revoked", error="invalid_token")
        if not token.startswith("ok:"):
            raise AuthenticationError("not a valid token")
        # Everything after '#' is a per-issue nonce, not part of the identity.
        subject = token.split(":", 1)[1].split("#", 1)[0]
        return Identity(
            subject=subject,
            scopes=frozenset({"mysql:read", "mysql:write"}),
            client_id=subject,
            token_id=f"jti-{subject}",
            expires_at=int(time.time()) + 3600,
        )

    def protected_resource_metadata(self) -> dict:
        return {"resource": RESOURCE, "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return f"{RESOURCE}{PRM_PATH}"

    async def aclose(self) -> None:
        return None


def build(verifier, chunked_session_event: bool = False, **kwargs):
    async def sse(request):
        if chunked_session_event:
            # The transport is free to flush the endpoint event across several
            # body chunks. Split it mid-token to see whether the middleware's
            # session sniffing survives that.
            async def stream():
                yield b"event: endpoint\ndata: /messages/?sess"
                yield b"ion_id=split123\n\n"

            from starlette.responses import StreamingResponse

            return StreamingResponse(stream(), media_type="text/event-stream")
        return PlainTextResponse("event: endpoint\ndata: /messages/?session_id=sess1\n\n")

    async def messages(request):
        identity = request.scope.get("auth_identity")
        return PlainTextResponse(f"ok:{identity.subject}")

    app = Starlette(
        routes=[
            Route("/", endpoint=lambda r: PlainTextResponse("ok")),
            Route("/sse", endpoint=sse),
            Mount("/messages/", routes=[Route("/", endpoint=messages, methods=["POST"])]),
        ]
    )
    defaults = {
        "verifier": verifier,
        "realm": "test",
        # Synthetic tool name; this file targets the middleware's token
        # handling, not the server's tool set.
        "tool_scopes": {"probe_read": ("mysql:read",), "*": ("mysql:write",)},
    }
    defaults.update(kwargs)
    return AuthMiddleware(app, **defaults)


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=RESOURCE)


CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "probe_read", "arguments": {"query": "SELECT 1"}},
}


# --------------------------------------------------------------------------
# Expiry. Every tool call is re-authenticated, which is what makes expiry
# actually take effect on this transport.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expired_token_cannot_open_a_stream():
    verifier = LifetimeVerifier()
    verifier.expired.add("ok:alice")
    app = build(verifier)

    async with client_for(app) as client:
        response = await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_token_that_expires_after_the_stream_opens_stops_tool_calls():
    """The documented policy: **tool calls stop, the stream is not torn down.**

    Every POST is verified independently, so once the token expires no further
    work can be done through it -- which is the property that matters, because
    tool calls are where the database is touched. The already-open stream stays
    up until the client closes it; it can carry no new calls.

    The alternative (actively terminating the stream on expiry) would need a
    timer per connection and gains nothing, since an idle stream reaches no
    database.
    """
    verifier = LifetimeVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        stream = await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})
        assert stream.status_code == 200

        before = await client.post(
            "/messages/?session_id=sess1", json=CALL, headers={"Authorization": "Bearer ok:alice"}
        )
        assert before.status_code == 200, "the call should work while the token is live"

        verifier.expired.add("ok:alice")

        after = await client.post(
            "/messages/?session_id=sess1", json=CALL, headers={"Authorization": "Bearer ok:alice"}
        )

    assert after.status_code == 401, (
        "an expired token kept working on an already-authenticated session; "
        "authentication is per-request precisely so this cannot happen"
    )


@pytest.mark.asyncio
async def test_expiry_is_re_checked_on_every_call_not_cached_per_session():
    """No 'already authenticated this session' shortcut may exist.

    Caching the first verdict for the life of a session would make expiry and
    revocation unenforceable for as long as a client keeps its stream open --
    which a well-behaved MCP client does indefinitely.
    """
    verifier = LifetimeVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})
        for _ in range(5):
            await client.post(
                "/messages/?session_id=sess1", json=CALL,
                headers={"Authorization": "Bearer ok:alice"},
            )

    # 1 for the stream + 5 for the calls.
    assert len(verifier.calls) == 6, (
        f"the verifier was consulted {len(verifier.calls)} times for 6 requests; "
        "a verdict is being reused across requests"
    )


@pytest.mark.asyncio
async def test_a_fresh_token_works_on_a_session_whose_token_expired():
    """Re-authenticating with a new token must recover, not stay poisoned.

    A client whose token expires mid-session refreshes it and retries. If the
    session were permanently associated with the dead token, refresh could not
    help and the client would have to reconnect for no reason.
    """
    verifier = LifetimeVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})
        verifier.expired.add("ok:alice")
        denied = await client.post(
            "/messages/?session_id=sess1", json=CALL,
            headers={"Authorization": "Bearer ok:alice"},
        )
        assert denied.status_code == 401

        # A refresh grant returns a new token string for the same subject.
        recovered = await client.post(
            "/messages/?session_id=sess1", json=CALL,
            headers={"Authorization": "Bearer ok:alice#refreshed"},
        )

    assert recovered.status_code == 200


# --------------------------------------------------------------------------
# Revocation. A revoked JWT is cryptographically valid, so local validation
# cannot detect it -- the authorization server has to be asked.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoked_token_is_refused_when_the_verifier_reports_it():
    verifier = LifetimeVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        allowed = await client.post(
            "/messages/?session_id=unbound", json=CALL,
            headers={"Authorization": "Bearer ok:bob"},
        )
        assert allowed.status_code == 200

        verifier.revoked.add("ok:bob")
        refused = await client.post(
            "/messages/?session_id=unbound", json=CALL,
            headers={"Authorization": "Bearer ok:bob"},
        )

    assert refused.status_code == 401
    assert verifier.introspections == 1


def test_revocation_is_off_by_default_and_that_is_a_documented_trade_off(monkeypatch):
    """Default: tokens stay valid here until `exp`, even if revoked upstream.

    This is the single most important thing to understand about the security
    posture. Local JWT validation is what keeps the server working when the
    authorization server is unreachable -- and the same property means a
    revocation upstream is invisible here for the token's remaining lifetime,
    up to an hour with default lifetimes.
    """
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    monkeypatch.delenv("MCP_AUTH_REVOCATION_CHECK", raising=False)

    settings = AuthSettings.from_env()
    assert settings.revocation_check is False


def test_revocation_requires_client_credentials(monkeypatch):
    """Introspection is an authenticated call, so it cannot be enabled bare.

    With fail-closed semantics, enabling it without credentials would reject
    every request -- a total outage. Better to refuse at startup.
    """
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    monkeypatch.setenv("MCP_AUTH_REVOCATION_CHECK", "true")
    monkeypatch.delenv("MCP_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("MCP_OAUTH_CLIENT_SECRET", raising=False)

    with pytest.raises(VerifierConfigError, match="MCP_OAUTH_CLIENT_ID"):
        AuthSettings.from_env()


def test_revocation_enabled_with_credentials_is_accepted(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    monkeypatch.setenv("MCP_AUTH_REVOCATION_CHECK", "true")
    monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "csecret")

    settings = AuthSettings.from_env()
    assert settings.revocation_check is True
    assert settings.client_id == "cid"


# --------------------------------------------------------------------------
# Clock skew. `exp` and `nbf` are absolute timestamps, so the two machines'
# clocks have to agree. Skew tolerance absorbs the difference.
# --------------------------------------------------------------------------

def test_clock_skew_defaults_to_a_small_tolerance(monkeypatch):
    """Zero tolerance would reject valid tokens whenever clocks drift, which they
    always do; a large tolerance keeps expired tokens alive for that long."""
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    monkeypatch.delenv("MCP_OAUTH_CLOCK_SKEW_SECONDS", raising=False)

    assert AuthSettings.from_env().clock_skew_seconds == 30


@pytest.mark.parametrize("value", ["not-a-number", "-1", "1.5"])
def test_invalid_clock_skew_is_rejected_at_startup(monkeypatch, value):
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    monkeypatch.setenv("MCP_OAUTH_CLOCK_SKEW_SECONDS", value)

    with pytest.raises(VerifierConfigError):
        AuthSettings.from_env()


def test_large_clock_skew_is_allowed_but_warned_about(monkeypatch, caplog):
    """It is a legitimate choice on badly-synchronised infrastructure, and it
    widens the window in which an expired token still works -- so it is loud."""
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    monkeypatch.setenv("MCP_OAUTH_CLOCK_SKEW_SECONDS", "600")

    with caplog.at_level("WARNING"):
        settings = AuthSettings.from_env()

    assert settings.clock_skew_seconds == 600
    assert any("CLOCK_SKEW" in record.message or "skew" in record.message.lower()
               for record in caplog.records)


# --------------------------------------------------------------------------
# Session sniffing across chunk boundaries. The middleware reads the session id
# out of the outbound stream, one body message at a time.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_session_id_split_across_body_chunks_fails_safe():
    """A session id split mid-token cannot be read, and that must not grant access.

    The sniffing looks at each `http.response.body` message on its own, so a
    transport that flushes `...?sess` and `ion_id=abc` separately leaves the
    session unrecorded. The consequence must be "unbound" -- checked but not
    found, so no cross-subject claim is possible -- and never "bound to whoever
    asks next".

    Recorded rather than fixed: reassembling across chunks would mean buffering
    stream output, which is exactly what must not happen to an SSE body. The
    real transport emits the endpoint event as a single write.
    """
    verifier = LifetimeVerifier()
    app = build(verifier, chunked_session_event=True)

    async with client_for(app) as client:
        stream = await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})
        assert stream.status_code == 200

        # Not recorded, because the id never appeared whole in one chunk.
        assert app.sessions.owner("split123") is None

        # Unbound means "not checked against an owner", so Bob is allowed --
        # the same behaviour as any session this process never saw. It fails
        # open for *binding* while still requiring a valid token, which is why
        # binding is defence in depth rather than the primary control.
        response = await client.post(
            "/messages/?session_id=split123", json=CALL,
            headers={"Authorization": "Bearer ok:bob"},
        )
        assert response.status_code == 200

        # And nothing was misattributed.
        assert app.sessions.owner("split123") is None


@pytest.mark.asyncio
async def test_unauthenticated_stream_never_records_a_session():
    """A rejected stream must leave no trace to be reused."""
    verifier = LifetimeVerifier()
    verifier.expired.add("ok:alice")
    app = build(verifier)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})

    assert len(app.sessions) == 0


@pytest.mark.asyncio
async def test_concurrent_expiry_does_not_let_a_racing_call_through():
    """A token expiring while calls are in flight: none of the later ones succeed."""
    verifier = LifetimeVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})

        async def call():
            return await client.post(
                "/messages/?session_id=sess1", json=CALL,
                headers={"Authorization": "Bearer ok:alice"},
            )

        first_wave = asyncio.gather(*(call() for _ in range(10)))
        verifier.expired.add("ok:alice")
        results = await first_wave
        second_wave = await asyncio.gather(*(call() for _ in range(10)))

    # The first wave raced the expiry, so either verdict is legitimate there.
    assert all(r.status_code in (200, 401) for r in results)
    # The second wave started strictly after expiry: none may succeed.
    assert all(r.status_code == 401 for r in second_wave), (
        "a call made after the token expired was accepted"
    )
