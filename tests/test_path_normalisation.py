"""Pins the assumption that makes prefix-based path matching safe.

`is_protected()` decides whether a request needs a token by matching path
prefixes. That is only sound if the middleware and the router agree on what the
path *is*. If Starlette normalised dot segments after the middleware ran, then
`/foo/../sse` would skip the middleware (it starts with neither protected
prefix) and still reach the `/sse` handler. That is a straightforward auth
bypass.

Every request here is sent over a raw socket, because HTTP clients normalise
URIs before transmitting: `httpx.get("/foo/../sse")` actually sends `/sse`, so
testing through a client proves nothing about the server. The bypass has to be
attempted with the exact bytes on the wire.

This is a test of Starlette's behaviour, not of our code. It is here so that if
a future version starts normalising, this fails loudly rather than the
protection silently disappearing.
"""

import socket
import threading
import time

import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route

from mysql_mcp_server.auth import PRM_PATH, AuthMiddleware
from mysql_mcp_server.auth.protocol import AuthenticationError, Identity

PORT = 8771


class AlwaysRejects:
    """Rejects every token, so any 200 on a protected path is a bypass.

    Using a verifier that never succeeds removes token handling from the
    experiment: the only question is whether the middleware was consulted.
    """

    async def verify(self, token: str, request=None) -> Identity:
        raise AuthenticationError("no token is valid in this test")

    def protected_resource_metadata(self) -> dict:
        return {"resource": f"http://localhost:{PORT}", "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return f"http://localhost:{PORT}{PRM_PATH}"

    async def aclose(self) -> None:
        return None


@pytest.fixture(scope="module")
def live_server():
    async def health(request):
        return PlainTextResponse("health")

    async def sse(request):
        # Reaching this handler unauthenticated is the failure being hunted.
        return PlainTextResponse("SSE HANDLER REACHED")

    async def messages(request):
        return PlainTextResponse("MESSAGES HANDLER REACHED")

    app = Starlette(
        routes=[
            Route("/", endpoint=health),
            Route("/sse", endpoint=sse),
            Mount("/messages/", routes=[Route("/", endpoint=messages, methods=["GET", "POST"])]),
        ]
    )
    wrapped = AuthMiddleware(app, verifier=AlwaysRejects(), realm="test")

    config = uvicorn.Config(wrapped, host="127.0.0.1", port=PORT, log_level="error")
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

    yield f"127.0.0.1:{PORT}"

    server.should_exit = True
    thread.join(timeout=10)


def raw_request(target: str, method: str = "GET") -> str:
    """Send ``target`` verbatim and return the status line.

    Deliberately does not use an HTTP client: clients resolve `..` and collapse
    `//` before sending, which would defeat the entire test.
    """
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    try:
        request = (
            f"{method} {target} HTTP/1.1\r\n"
            f"Host: localhost:{PORT}\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("latin-1"))
        buffer = b""
        while b"\r\n" not in buffer and len(buffer) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
        return buffer.split(b"\r\n")[0].decode("latin-1", "replace")
    finally:
        sock.close()


# Targets that must never reach an MCP handler without a token. Each is a
# different way of spelling a protected path.
TRAVERSAL_TARGETS = [
    "/foo/../sse",
    "/messages/../sse",
    "/./sse",
    "/a/b/../../sse",
    "//sse",
    "///sse",
    "/foo/%2e%2e/sse",
    "/%2e/sse",
    "/foo/..%2fsse",
    "/sse%20",
    "/%73se",
    "/SSE",
    "/Sse",
    "/foo/../messages/",
    "//messages/",
    "/./messages/",
    "/.well-known/oauth-protected-resource/../../sse",
]


@pytest.mark.parametrize("target", TRAVERSAL_TARGETS)
def test_no_spelling_of_a_protected_path_reaches_a_handler_unauthenticated(live_server, target):
    """Either the middleware rejects it (401) or the router does not resolve it (404).

    Both outcomes are safe. A 200 is not: it would mean the router reached an MCP
    handler that the middleware decided not to inspect.
    """
    status = raw_request(target)
    assert "200" not in status, (
        f"{target!r} reached a handler unauthenticated: {status}. "
        "Starlette is normalising paths after the middleware runs, so prefix "
        "matching in is_protected() is no longer sufficient."
    )
    assert any(code in status for code in ("401", "403", "404", "400", "405")), (
        f"unexpected response for {target!r}: {status}"
    )


def test_controls_confirm_the_experiment_is_valid(live_server):
    """Without these, every assertion above could pass for the wrong reason.

    If `/sse` did not 401, the verifier is not wired in and the traversal results
    are meaningless. If `/` did not 200, the server is not serving at all.
    """
    assert "401" in raw_request("/sse"), "the protected path must be rejected"
    assert "200" in raw_request("/"), "the public path must be served"


def test_trailing_slash_variants_are_still_protected(live_server):
    """`/sse/` and `/messages` must not slip through on a slash difference."""
    for target in ("/sse/", "/messages", "/messages/"):
        status = raw_request(target)
        assert "200" not in status, f"{target!r} reached a handler unauthenticated: {status}"
