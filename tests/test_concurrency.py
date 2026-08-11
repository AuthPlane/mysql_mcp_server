"""Concurrency: many clients, one server, one database.

The single-client case is not the real deployment. Every test here runs requests
*simultaneously* through the ASGI app, because the failures being hunted only
appear under interleaving:

  * one request's identity being used to authorize another's call
  * shared state (the session table) corrupting or reassigning under contention
  * a verifier failure serialising every other request behind it

`httpx.AsyncClient` over `ASGITransport` is used rather than `TestClient`,
because `TestClient` drives the app from a sync thread and cannot express two
in-flight requests.
"""

import asyncio

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route

from mysql_mcp_server.auth import PRM_PATH, AuthMiddleware
from mysql_mcp_server.auth.middleware import SessionBinding
from mysql_mcp_server.auth.protocol import AuthenticationError, Identity

RESOURCE = "http://testserver"


class CountingVerifier:
    """Accepts `ok:<subject>:<scopes>`, and records concurrency as it goes.

    `max_in_flight` is what proves the middleware does not serialise: if it
    awaited verifications under a lock, this would never exceed 1.
    """

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.calls = 0
        self.in_flight = 0
        self.max_in_flight = 0
        self.rejected = 0

    async def verify(self, token: str, request=None) -> Identity:
        self.calls += 1
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if not token.startswith("ok:"):
                self.rejected += 1
                raise AuthenticationError("rejected by test verifier")
            parts = token.split(":", 2)
            subject = parts[1]
            scopes = frozenset(parts[2].split()) if len(parts) > 2 and parts[2] else frozenset()
            return Identity(subject=subject, scopes=scopes, client_id=subject, token_id=f"jti-{subject}")
        finally:
            self.in_flight -= 1

    def protected_resource_metadata(self) -> dict:
        return {"resource": RESOURCE, "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return f"{RESOURCE}{PRM_PATH}"

    async def aclose(self) -> None:
        return None


def build(verifier, **kwargs):
    """An app whose handlers echo back the identity the middleware attached.

    Echoing the subject is the point: it is how a response can be checked
    against the token that asked for it, which is what makes claim leakage
    detectable at all.
    """

    async def sse(request):
        identity = request.scope.get("auth_identity")
        return PlainTextResponse(
            f"event: endpoint\ndata: /messages/?session_id=sess-{identity.subject}\n\n"
        )

    async def messages(request):
        identity = request.scope.get("auth_identity")
        body = await request.body()
        return PlainTextResponse(f"{identity.subject}|{len(body)}")

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
        "tool_scopes": {"read_query": ("mysql:read",), "write_query": ("mysql:write",), "*": ("mysql:write",)},
        "read_only_tools": ("read_query",),
        "deny_at_http_layer": True,
    }
    defaults.update(kwargs)
    return AuthMiddleware(app, **defaults)


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=RESOURCE)


def call_body(tool: str = "read_query", query: str = "SELECT 1") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"query": query}},
    }


# --------------------------------------------------------------------------
# Claim isolation. The failure this hunts: request A authorized with request
# B's identity. On a tool that runs SQL against a shared database, that is one
# tenant reading another's data.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_100_concurrent_requests_each_carry_their_own_identity():
    verifier = CountingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        async def one(i: int):
            subject = f"user{i}"
            response = await client.post(
                f"/messages/?session_id=sess-{subject}",
                json=call_body(),
                headers={"Authorization": f"Bearer ok:{subject}:mysql:read"},
            )
            return subject, response

        results = await asyncio.gather(*(one(i) for i in range(100)))

    for subject, response in results:
        assert response.status_code == 200
        echoed = response.text.split("|")[0]
        assert echoed == subject, (
            f"request for {subject} was handled as {echoed}: identity leaked across "
            "concurrent requests"
        )
    assert verifier.calls == 100


@pytest.mark.asyncio
async def test_interleaved_valid_and_invalid_tokens_never_cross_over():
    """No invalid request succeeds and no valid request is spuriously rejected.

    Alternating them matters: a shared-state bug tends to show up as one
    request inheriting the *previous* one's verdict.
    """
    verifier = CountingVerifier(delay=0.001)
    app = build(verifier)

    async with client_for(app) as client:
        async def one(i: int):
            valid = i % 2 == 0
            token = f"ok:user{i}:mysql:read" if valid else f"garbage{i}"
            response = await client.post(
                "/messages/?session_id=unbound",
                json=call_body(),
                headers={"Authorization": f"Bearer {token}"},
            )
            return valid, response.status_code

        outcomes = await asyncio.gather(*(one(i) for i in range(120)))

    for valid, status in outcomes:
        if valid:
            assert status == 200, "a valid token was rejected under concurrency"
        else:
            assert status == 401, "an invalid token was accepted under concurrency"


@pytest.mark.asyncio
async def test_concurrent_scope_checks_do_not_leak_authorization():
    """A caller with only the read scope must never ride a write-scoped request through."""
    verifier = CountingVerifier(delay=0.001)
    app = build(verifier)

    async with client_for(app) as client:
        async def one(i: int):
            privileged = i % 3 == 0
            scopes = "mysql:read mysql:write" if privileged else "mysql:read"
            response = await client.post(
                "/messages/?session_id=unbound",
                json=call_body("write_query", "DROP TABLE demo"),
                headers={"Authorization": f"Bearer ok:user{i}:{scopes}"},
            )
            return privileged, response.status_code

        outcomes = await asyncio.gather(*(one(i) for i in range(90)))

    for privileged, status in outcomes:
        assert status == (200 if privileged else 403), (
            "scope enforcement is not per-request under concurrency"
        )


@pytest.mark.asyncio
async def test_middleware_does_not_serialise_verifications():
    """Verifications must overlap.

    If the middleware held a lock across `verify()`, a slow authorization server
    would turn every concurrent request into a queue -- a latency cliff that only
    appears under load.
    """
    verifier = CountingVerifier(delay=0.05)
    app = build(verifier)

    async with client_for(app) as client:
        await asyncio.gather(
            *(
                client.post(
                    "/messages/?session_id=unbound",
                    json=call_body(),
                    headers={"Authorization": f"Bearer ok:user{i}:mysql:read"},
                )
                for i in range(20)
            )
        )

    assert verifier.max_in_flight > 1, (
        f"verifications never overlapped (max in flight: {verifier.max_in_flight}); "
        "the middleware is serialising them"
    )


@pytest.mark.asyncio
async def test_one_slow_verification_does_not_block_the_others():
    """Total time must look concurrent, not sequential."""
    verifier = CountingVerifier(delay=0.05)
    app = build(verifier)

    async with client_for(app) as client:
        started = asyncio.get_running_loop().time()
        await asyncio.gather(
            *(
                client.get("/sse", headers={"Authorization": f"Bearer ok:user{i}:mysql:read"})
                for i in range(20)
            )
        )
        elapsed = asyncio.get_running_loop().time() - started

    # Sequential would be 20 * 50ms = 1.0s. Generous bound to stay stable on a
    # loaded CI machine while still failing on true serialisation.
    assert elapsed < 0.5, f"20 requests at 50ms each took {elapsed:.2f}s; they ran in series"


# --------------------------------------------------------------------------
# Session binding under contention. Shared mutable state, so this is where a
# concurrency bug would actually grant access.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_session_opens_bind_to_the_right_subjects():
    verifier = CountingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await asyncio.gather(
            *(
                client.get("/sse", headers={"Authorization": f"Bearer ok:user{i}:mysql:read"})
                for i in range(40)
            )
        )

        # Each subject may use its own session...
        own = await asyncio.gather(
            *(
                client.post(
                    f"/messages/?session_id=sess-user{i}",
                    json=call_body(),
                    headers={"Authorization": f"Bearer ok:user{i}:mysql:read"},
                )
                for i in range(40)
            )
        )
        # ...and no subject may use its neighbour's.
        crossed = await asyncio.gather(
            *(
                client.post(
                    f"/messages/?session_id=sess-user{i}",
                    json=call_body(),
                    headers={"Authorization": f"Bearer ok:user{(i + 1) % 40}:mysql:read"},
                )
                for i in range(40)
            )
        )

    assert all(r.status_code == 200 for r in own), "a subject was locked out of its own session"
    assert all(r.status_code == 403 for r in crossed), (
        "a session was usable by a different subject under concurrency"
    )


@pytest.mark.asyncio
async def test_session_table_never_reassigns_under_concurrent_writes():
    """Eviction may forget a session; it must never hand it to someone else.

    The table does check-then-mutate, so concurrent writers could interleave.
    The invariant that matters is not "the limit is exact" but "a session id is
    never bound to a subject that did not open it".
    """
    binding = SessionBinding(limit=16)

    async def writer(start: int):
        for i in range(start, start + 50):
            binding.remember(f"sess-{i}", f"subject-{i}")
            await asyncio.sleep(0)

    await asyncio.gather(*(writer(base * 50) for base in range(8)))

    assert len(binding) <= 16 + 8, "the table grew well past its bound"
    for i in range(400):
        owner = binding.owner(f"sess-{i}")
        assert owner in (None, f"subject-{i}"), (
            f"sess-{i} is bound to {owner}, which never opened it"
        )


@pytest.mark.asyncio
async def test_many_concurrent_streams_are_all_tracked_or_safely_forgotten():
    """A caller with one valid token must not be able to grow the table forever.

    Opening more sessions than the bound is allowed to evict older ones; what it
    must not do is grow without limit or misattribute a session.
    """
    verifier = CountingVerifier()
    app = build(verifier)
    middleware = app

    async with client_for(app) as client:
        await asyncio.gather(
            *(
                client.get("/sse", headers={"Authorization": f"Bearer ok:user{i}:mysql:read"})
                for i in range(200)
            )
        )

    assert len(middleware.sessions) <= 4096
    for i in range(200):
        owner = middleware.sessions.owner(f"sess-user{i}")
        assert owner in (None, f"user{i}")


# --------------------------------------------------------------------------
# Rejections under concurrency must stay cheap and quiet.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_rejections_do_not_leak_details_or_hang():
    verifier = CountingVerifier(delay=0.001)
    app = build(verifier)

    async with client_for(app) as client:
        responses = await asyncio.gather(
            *(
                client.get("/sse", headers={"Authorization": f"Bearer bad{i}"})
                for i in range(60)
            )
        )

    assert all(r.status_code == 401 for r in responses)
    for response in responses:
        assert "Traceback" not in response.text
        assert "test verifier" not in response.text, "verifier internals reached the caller"


@pytest.mark.asyncio
async def test_public_paths_stay_responsive_while_verifications_are_slow():
    """A health probe must not queue behind authentication work.

    If it did, a slow authorization server would make an orchestrator conclude
    the container is unhealthy and restart it.
    """
    verifier = CountingVerifier(delay=0.2)
    app = build(verifier)

    async with client_for(app) as client:
        slow = asyncio.gather(
            *(
                client.get("/sse", headers={"Authorization": f"Bearer ok:user{i}:mysql:read"})
                for i in range(10)
            )
        )
        await asyncio.sleep(0.01)
        started = asyncio.get_running_loop().time()
        health = await client.get("/")
        elapsed = asyncio.get_running_loop().time() - started
        await slow

    assert health.status_code == 200
    assert elapsed < 0.15, f"health check waited {elapsed:.3f}s behind authentication work"


@pytest.mark.asyncio
async def test_body_replay_is_not_shared_between_concurrent_requests():
    """Each request must see its own body.

    The middleware buffers and replays bodies; a replay built from shared state
    would deliver one caller's SQL to another's connection.
    """
    verifier = CountingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        async def one(i: int):
            payload = call_body("read_query", "SELECT " + ("1," * i) + "1")
            import json as _json

            raw = _json.dumps(payload).encode()
            response = await client.post(
                "/messages/?session_id=unbound",
                content=raw,
                headers={
                    "Authorization": f"Bearer ok:user{i}:mysql:read",
                    "Content-Type": "application/json",
                },
            )
            return len(raw), response

        results = await asyncio.gather(*(one(i) for i in range(50)))

    for expected_length, response in results:
        assert response.status_code == 200
        echoed_length = int(response.text.split("|")[1])
        assert echoed_length == expected_length, (
            "a request received a body of the wrong length: replay state is shared"
        )
