"""The session binding must live exactly as long as the stream it describes.

`SessionBinding` maps a session id to the subject that opened it, and that map
is what stops a valid token belonging to B from being accepted on a session
opened by A. It used to have no release path at all: `forget()` existed and was
never called, so the table only grew. On a long-lived deployment it drifted
towards its 4,096-entry cap and then began evicting entries for sessions that
were still open -- and an evicted session is no longer subject-checked, which is
the single outcome the table exists to prevent.

Testing this needs a stream that is genuinely still open while a second request
is made, which `TestClient` cannot provide: it drives the ASGI app through one
portal, so a suspended response generator blocks every other request on the same
client (verified -- it deadlocks). So this file runs a real uvicorn server on a
socket and holds the SSE response open from a separate thread, the same shape as
`test_path_normalisation.py`.
"""

import threading
import time

import anyio
import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, StreamingResponse
from starlette.routing import Mount, Route

from mysql_mcp_server.auth import PRM_PATH, AuthMiddleware
from mysql_mcp_server.auth.protocol import AuthenticationError, Identity

PORT = 8773
BASE = f"http://127.0.0.1:{PORT}"

SESSION_ID = "sess0001"


class TwoSubjects:
    """`ok:<subject>` is accepted; anything else is not."""

    async def verify(self, token: str, request=None) -> Identity:
        if not token.startswith("ok:"):
            raise AuthenticationError("unknown token")
        subject = token.split(":", 1)[1]
        return Identity(
            subject=subject, scopes=frozenset({"mysql:read"}), client_id=subject
        )

    def protected_resource_metadata(self) -> dict:
        return {"resource": BASE, "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return f"{BASE}{PRM_PATH}"

    async def aclose(self) -> None:
        return None


# Set from a test to let the held-open SSE response finish.
_close_stream = threading.Event()


@pytest.fixture(scope="module")
def live():
    async def sse(request):
        async def body():
            # The endpoint event is what the middleware sniffs the session id
            # out of, so the binding is established at this yield.
            yield f"event: endpoint\ndata: /messages/?session_id={SESSION_ID}\n\n".encode()
            # Then behave like a real SSE stream: stay open. This is the state
            # the binding is supposed to cover.
            while not _close_stream.is_set():
                await anyio.sleep(0.02)

        return StreamingResponse(body(), media_type="text/event-stream")

    async def messages(request):
        return PlainTextResponse("accepted")

    app = Starlette(
        routes=[
            Route("/", endpoint=lambda r: PlainTextResponse("ok")),
            Route("/sse", endpoint=sse),
            Mount("/messages/", routes=[Route("/", endpoint=messages, methods=["POST"])]),
        ]
    )
    middleware = AuthMiddleware(app, verifier=TwoSubjects(), realm="test")

    config = uvicorn.Config(middleware, host="127.0.0.1", port=PORT, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 15
    while time.time() < deadline:
        if getattr(server, "started", False):
            break
        time.sleep(0.1)
    else:  # pragma: no cover - only on a very slow machine
        pytest.fail("uvicorn did not start")

    yield middleware

    _close_stream.set()
    server.should_exit = True
    thread.join(timeout=10)


def _open_stream(client: httpx.Client):
    """Open `/sse` and return once the endpoint event has been received.

    Returning at the first chunk rather than at completion is the point: the
    response is still open when this returns.
    """
    ctx = client.stream("GET", "/sse", headers={"Authorization": "Bearer ok:alice"})
    response = ctx.__enter__()
    assert response.status_code == 200
    # One iterator for the life of the response: httpx refuses a second one.
    chunks = response.iter_bytes()
    assert SESSION_ID.encode() in next(chunks)
    return ctx, chunks


def test_binding_holds_while_the_stream_is_open(live):
    _close_stream.clear()
    with httpx.Client(base_url=BASE, timeout=10) as client:
        ctx, _chunks = _open_stream(client)
        try:
            assert live.sessions.owner(SESSION_ID) == "alice"

            # Alice's own POST goes through while her stream is open.
            own = client.post(
                f"/messages/?session_id={SESSION_ID}",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Authorization": "Bearer ok:alice"},
            )
            assert own.status_code == 200

            # Bob's does not. Both tokens are valid; only the pairing is wrong.
            crossed = client.post(
                f"/messages/?session_id={SESSION_ID}",
                json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                headers={"Authorization": "Bearer ok:bob"},
            )
            assert crossed.status_code == 403
        finally:
            _close_stream.set()
            ctx.__exit__(None, None, None)


def test_binding_is_released_when_the_stream_closes(live):
    """The regression this exists for: the table must not grow without bound."""
    _close_stream.clear()
    with httpx.Client(base_url=BASE, timeout=10) as client:
        ctx, chunks = _open_stream(client)
        assert len(live.sessions) == 1

        _close_stream.set()
        # Drain so the server-side response actually completes.
        for _ in chunks:
            pass
        ctx.__exit__(None, None, None)

    deadline = time.time() + 5
    while time.time() < deadline and len(live.sessions) != 0:
        time.sleep(0.05)
    assert len(live.sessions) == 0, (
        "the binding outlived its stream; repeated over a long-lived deployment "
        "this is what drove the table to its cap and started evicting live sessions"
    )


def test_repeated_streams_do_not_accumulate(live):
    """Ten streams opened and closed in sequence must leave the table empty."""
    for _ in range(10):
        _close_stream.clear()
        with httpx.Client(base_url=BASE, timeout=10) as client:
            ctx, chunks = _open_stream(client)
            _close_stream.set()
            for _ in chunks:
                pass
            ctx.__exit__(None, None, None)

    deadline = time.time() + 5
    while time.time() < deadline and len(live.sessions) != 0:
        time.sleep(0.05)
    assert len(live.sessions) == 0
