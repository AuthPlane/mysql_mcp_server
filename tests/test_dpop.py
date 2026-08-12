"""DPoP: sender-constrained tokens (RFC 9449).

The problem being solved: a bearer token is a bearer token. Whoever holds the
string can use it, from anywhere. Leak one into a log, a proxy, or a client's
memory and it works until it expires.

DPoP binds the token to a key the client holds. Each request carries a `DPoP`
header — a JWT signed with that key, covering the HTTP method and target URI — so
the token alone proves nothing. A thief needs the private key too.

Three settings, because the middle one is the only safe way to adopt it:

    off       bearer only
    optional  advertised and verified when presented; clients without DPoP keep working
    required  no proof, no access — locks out clients that cannot produce one

These tests cover the plumbing: that the middleware reconstructs the right
request description and hands it to the verifier. Whether a *proof* is
cryptographically valid is the SDK's job, exercised live rather than re-tested
here.
"""

import importlib.util

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route

from mysql_mcp_server.auth import PRM_PATH, AuthMiddleware, AuthSettings
from mysql_mcp_server.auth.protocol import (
    AuthenticationError,
    Identity,
    RequestContext,
    TokenVerifier,
    VerifierConfigError,
)

RESOURCE = "http://testserver"

# The Authplane SDK requires Python 3.12+ and ships in the optional [auth] extra,
# so it is absent both on the 3.11 CI leg and on any base install. Tests that
# exercise the real verifier skip rather than error, which keeps the suite green
# for contributors who never touch auth.
_HAS_SDK = importlib.util.find_spec("authplane") is not None
requires_sdk = pytest.mark.skipif(
    not _HAS_SDK, reason="needs the [auth] extra (authplane-sdk, Python 3.12+)"
)


class ContextCapturingVerifier:
    """Records the `RequestContext` it was handed, and can demand a proof.

    Standing in for the SDK here is the right level: what needs testing is that
    the middleware describes the request correctly. If `url` or `method` is wrong,
    every real proof fails and the failure looks like a client bug.
    """

    def __init__(self, require_proof: bool = False) -> None:
        self.require_proof = require_proof
        self.contexts: list[RequestContext | None] = []

    async def verify(self, token: str, request: RequestContext | None = None) -> Identity:
        self.contexts.append(request)
        if not token.startswith("ok:"):
            raise AuthenticationError("bad token")
        if self.require_proof and (request is None or not request.proof):
            # What the SDK does in `required` mode.
            raise AuthenticationError("DPoP proof required", error="invalid_token")
        return Identity(
            subject=token.split(":", 1)[1],
            scopes=frozenset({"mysql:read", "mysql:write"}),
            client_id="c",
            token_id="j",
        )

    def protected_resource_metadata(self) -> dict:
        return {"resource": RESOURCE, "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return f"{RESOURCE}{PRM_PATH}"

    async def aclose(self) -> None:
        return None


def build(verifier, **kwargs):
    async def messages(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[
        Route("/", endpoint=lambda r: PlainTextResponse("ok")),
        Route("/sse", endpoint=lambda r: PlainTextResponse(
            "event: endpoint\ndata: /messages/?session_id=s1\n\n")),
        Mount("/messages/", routes=[Route("/", endpoint=messages, methods=["POST"])]),
    ])
    defaults = {"verifier": verifier, "realm": "test", "resource_url": RESOURCE}
    defaults.update(kwargs)
    return AuthMiddleware(app, **defaults)


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=RESOURCE)


CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read_query", "arguments": {"query": "SELECT 1"}}}


# --------------------------------------------------------------------------
# The request description handed to the verifier. Getting this wrong makes every
# valid proof fail, and the symptom looks like a broken client.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proof_header_is_passed_to_the_verifier():
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.get(
            "/sse",
            headers={"Authorization": "DPoP ok:alice", "DPoP": "the-proof-jwt"},
        )

    assert verifier.contexts[0].proof == "the-proof-jwt"


@pytest.mark.asyncio
async def test_absent_proof_header_is_reported_as_none_not_empty_string():
    """`None` means "no proof presented"; an empty string could read as one."""
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})

    assert verifier.contexts[0].proof is None


@pytest.mark.asyncio
async def test_method_is_reported_per_request():
    """A proof is signed over the method, so GET and POST must not be conflated."""
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "DPoP ok:alice", "DPoP": "p"})
        await client.post(
            "/messages/?session_id=s1", json=CALL,
            headers={"Authorization": "DPoP ok:alice", "DPoP": "p"},
        )

    assert [c.method for c in verifier.contexts] == ["GET", "POST"]


@pytest.mark.asyncio
async def test_url_excludes_the_query_string():
    """RFC 9449 §4.2 defines `htu` without query or fragment.

    Load-bearing on this transport: `/messages/` carries a per-session id, so
    including the query would change the URL on every request and no proof could
    ever match.
    """
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.post(
            "/messages/?session_id=abc123", json=CALL,
            headers={"Authorization": "DPoP ok:alice", "DPoP": "p"},
        )

    url = verifier.contexts[0].url
    assert url == f"{RESOURCE}/messages/"
    assert "session_id" not in url, "the per-session query would break every proof"


@pytest.mark.asyncio
async def test_url_comes_from_configuration_not_the_host_header():
    """`Host` is caller-controlled and wrong behind a proxy.

    Deriving the URL a proof is checked against from a caller-supplied header
    would let the caller choose what their own proof has to match. And behind a
    reverse proxy the scheme and host the server sees differ from what the client
    signed, so every proof would fail.
    """
    verifier = ContextCapturingVerifier()
    app = build(verifier, resource_url="https://mcp.example.com")

    async with client_for(app) as client:
        await client.get(
            "/sse",
            headers={
                "Authorization": "DPoP ok:alice",
                "DPoP": "p",
                "Host": "attacker.example.net",
            },
        )

    assert verifier.contexts[0].url == "https://mcp.example.com/sse"


@pytest.mark.asyncio
async def test_resource_url_falls_back_to_the_metadata_document():
    """Both are the same canonical value, so the fallback cannot disagree."""
    verifier = ContextCapturingVerifier()
    app = build(verifier, resource_url="")

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})

    assert verifier.contexts[0].url == f"{RESOURCE}/sse"


@pytest.mark.asyncio
async def test_a_context_is_supplied_even_when_dpop_is_unused():
    """The middleware always describes the request; the verifier decides if it matters.

    Keeps the middleware free of any DPoP configuration — it does not need to know
    whether the verifier cares.
    """
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})

    context = verifier.contexts[0]
    assert context is not None and context.method == "GET"


@pytest.mark.asyncio
async def test_malformed_proof_header_bytes_do_not_crash_the_request():
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        response = await client.get(
            "/sse",
            headers={"Authorization": "DPoP ok:alice", "DPoP": "  spaced-proof  "},
        )

    assert response.status_code == 200
    assert verifier.contexts[0].proof == "spaced-proof", "the proof should be trimmed"


# --------------------------------------------------------------------------
# Required mode.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_required_mode_refuses_a_token_with_no_proof():
    verifier = ContextCapturingVerifier(require_proof=True)
    app = build(verifier)

    async with client_for(app) as client:
        without = await client.get("/sse", headers={"Authorization": "Bearer ok:alice"})
        with_proof = await client.get(
            "/sse", headers={"Authorization": "DPoP ok:alice", "DPoP": "p"}
        )

    assert without.status_code == 401
    assert with_proof.status_code == 200


@pytest.mark.asyncio
async def test_required_mode_still_leaves_public_paths_open():
    """A health probe cannot produce a DPoP proof, and should not have to."""
    verifier = ContextCapturingVerifier(require_proof=True)
    app = build(verifier)

    async with client_for(app) as client:
        assert (await client.get("/")).status_code == 200


# --------------------------------------------------------------------------
# Configuration.
# --------------------------------------------------------------------------

@pytest.fixture
def base_env(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("AUTHPLANE_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("AUTHPLANE_RESOURCE", "http://localhost:8000")
    monkeypatch.delenv("MCP_AUTH_DPOP", raising=False)
    return monkeypatch


def test_dpop_is_off_by_default(base_env):
    """Because `required` would lock out clients and `optional` still costs nothing
    only if the operator has decided to advertise it."""
    assert AuthSettings.from_env().dpop == "off"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("off", "off"), ("false", "off"), ("0", "off"), ("", "off"),
        ("optional", "optional"), ("true", "optional"), ("1", "optional"),
        ("required", "required"), ("REQUIRED", "required"),
    ],
)
def test_dpop_setting_accepts_the_documented_values(base_env, value, expected):
    base_env.setenv("MCP_AUTH_DPOP", value)
    assert AuthSettings.from_env().dpop == expected


def test_unrecognised_dpop_value_fails_at_startup(base_env):
    """A typo must not silently mean "off" — the operator would think it was on."""
    base_env.setenv("MCP_AUTH_DPOP", "mandatory")
    with pytest.raises(VerifierConfigError, match="not recognised"):
        AuthSettings.from_env()


def test_required_mode_warns_at_startup(base_env, caplog):
    """Every client without RFC 9449 support will be refused. That must be loud."""
    base_env.setenv("MCP_AUTH_DPOP", "required")
    with caplog.at_level("WARNING"):
        settings = AuthSettings.from_env()
    assert settings.dpop == "required"
    assert any("DPoP" in r.message for r in caplog.records)


@requires_sdk
def test_request_context_satisfies_the_sdk_protocol():
    """`RequestContext` is handed straight to the SDK, so its shape is a contract.

    The SDK reads `method`, `url` and `proof` off whatever it is given. If a field
    were renamed here, DPoP verification would break with a confusing error rather
    than a type failure.
    """
    context = RequestContext(method="POST", url="http://x/mcp", proof="p")
    assert context.method == "POST" and context.url == "http://x/mcp" and context.proof == "p"

    from authplane import DPoPRequestContext

    # The SDK's protocol is not @runtime_checkable, so compare the declared
    # members directly. This is what catches a rename upstream: if the SDK starts
    # reading `htu` instead of `url`, this fails here rather than as an opaque
    # verification error at runtime.
    required = getattr(DPoPRequestContext, "__protocol_attrs__", {"method", "url", "proof"})
    missing = [name for name in required if not hasattr(context, name)]
    assert missing == [], (
        f"RequestContext is missing {missing}, which the SDK's DPoPRequestContext "
        "protocol declares; DPoP verification would fail at runtime"
    )


def test_capturing_verifier_still_satisfies_the_seam():
    """The protocol change must not have leaked provider specifics into it."""
    assert isinstance(ContextCapturingVerifier(), TokenVerifier)


# --------------------------------------------------------------------------
# How the token is presented, and what the server advertises back.
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_proof_under_the_bearer_scheme_is_refused():
    """RFC 9449 §7.1 pairs a proof with the DPoP scheme, not with Bearer.

    Accepting the pair under `Bearer` would let a sender-constrained token be
    presented as though it were an ordinary one, which is the ambiguity the
    scheme exists to remove.
    """
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        response = await client.get(
            "/sse", headers={"Authorization": "Bearer ok:alice", "DPoP": "p"}
        )

    assert response.status_code == 401
    assert verifier.contexts == [], "the token should be refused before verification"


@pytest.mark.asyncio
async def test_a_proof_under_the_dpop_scheme_is_accepted():
    verifier = ContextCapturingVerifier()
    app = build(verifier)

    async with client_for(app) as client:
        response = await client.get(
            "/sse", headers={"Authorization": "DPoP ok:alice", "DPoP": "p"}
        )

    assert response.status_code == 200
    assert verifier.contexts[-1].proof == "p"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,expect_bearer,expect_dpop",
    [("off", True, False), ("optional", True, True), ("required", False, True)],
)
async def test_the_challenge_advertises_the_schemes_actually_accepted(
    mode, expect_bearer, expect_dpop
):
    """A client learns from the 401 how it is supposed to authenticate.

    In `required` mode a `Bearer`-only challenge is actively misleading: it names
    the one scheme that cannot work. Each scheme gets its own header value,
    because a comma also separates parameters *inside* a challenge and two
    schemes in one value cannot be parsed unambiguously.
    """
    app = build(
        ContextCapturingVerifier(), dpop=mode, dpop_algorithms=("ES256", "RS256")
    )

    async with client_for(app) as client:
        response = await client.get("/sse")

    assert response.status_code == 401
    challenges = response.headers.get_list("www-authenticate")
    schemes = {challenge.split(" ", 1)[0] for challenge in challenges}

    assert ("Bearer" in schemes) is expect_bearer
    assert ("DPoP" in schemes) is expect_dpop
    for challenge in challenges:
        assert "resource_metadata=" in challenge, "discovery must survive both schemes"
    if expect_dpop:
        dpop_challenge = next(c for c in challenges if c.startswith("DPoP "))
        assert 'algs="ES256 RS256"' in dpop_challenge, (
            "RFC 9449 §5.1: tell the client which algorithms to sign with"
        )
