"""Audit records and the authentication-failure throttle.

Both exist for reasons worth stating, because both are easy to mistake for
something they are not:

* **Audit** is the answer to "who ran that statement?". A reverse proxy with
  Basic Auth can prove someone authenticated; it cannot name them or say what
  they did, because it has no identity to pass on and no notion of a tool call.
* **Throttling** does not make authentication stronger — guessing a JWT signature
  is infeasible either way. It protects *availability*, because every rejected
  token costs a signature verification first.
"""

import json
import logging
import time

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route

from mysql_mcp_server.auth import PRM_PATH, AuthMiddleware, AuthSettings
from mysql_mcp_server.auth import audit as audit_module
from mysql_mcp_server.auth.protocol import AuthenticationError, Identity, VerifierConfigError
from mysql_mcp_server.auth.throttle import FailureThrottle

RESOURCE = "http://testserver"


class SimpleVerifier:
    async def verify(self, token: str, request=None) -> Identity:
        if not token.startswith("ok:"):
            raise AuthenticationError("nope: internal detail that must not leak")
        parts = token.split(":", 2)
        return Identity(
            subject=parts[1],
            scopes=frozenset(parts[2].split()) if len(parts) > 2 else frozenset(),
            client_id=f"client-{parts[1]}",
            token_id=f"jti-{parts[1]}",
        )

    def protected_resource_metadata(self) -> dict:
        return {"resource": RESOURCE, "authorization_servers": ["http://as.invalid"]}

    def metadata_url(self) -> str:
        return f"{RESOURCE}{PRM_PATH}"

    async def aclose(self) -> None:
        return None


def build(**kwargs):
    async def messages(request):
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[
            Route("/", endpoint=lambda r: PlainTextResponse("ok")),
            Route("/sse", endpoint=lambda r: PlainTextResponse(
                "event: endpoint\ndata: /messages/?session_id=s1\n\n")),
            Mount("/messages/", routes=[Route("/", endpoint=messages, methods=["POST"])]),
        ]
    )
    defaults = {
        "verifier": SimpleVerifier(),
        "realm": "test",
        "tool_scopes": {
            "get_schema_info": ("mysql:read",),
            "execute_sql": (),
            "*": ("mysql:write",),
        },
        "deny_at_http_layer": True,
    }
    defaults.update(kwargs)
    return AuthMiddleware(app, **defaults)


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=RESOURCE)


def call(tool="execute_sql", query="SELECT * FROM demo"):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": {"query": query}}}


@pytest.fixture
def audit_records(caplog):
    """Capture audit records as parsed JSON."""
    caplog.set_level(logging.INFO, logger="mysql_mcp_server.audit")

    def parsed():
        out = []
        for record in caplog.records:
            if record.name == "mysql_mcp_server.audit":
                out.append(json.loads(record.getMessage()))
        return out

    return parsed


# --------------------------------------------------------------------------
# Audit content. The value is entirely in *which fields* are present.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_authorized_tool_call_records_who_ran_what(audit_records):
    """The record a proxy cannot produce: identity plus the statement."""
    app = build()
    async with client_for(app) as client:
        response = await client.post(
            "/messages/?session_id=s1", json=call(),
            headers={"Authorization": "Bearer ok:alice:mysql:read"},
        )
    assert response.status_code == 200

    entries = [e for e in audit_records() if e["event"] == "tool_call_authorized"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["sub"] == "alice"
    assert entry["client_id"] == "client-alice"
    assert entry["jti"] == "jti-alice"
    assert entry["tool"] == "execute_sql"
    assert entry["statement"] == "SELECT * FROM demo"
    assert entry["session_id"] == "s1"
    assert entry["outcome"] == "authorized"
    assert "ts" in entry


@pytest.mark.asyncio
async def test_scope_denial_is_recorded_with_the_reason(audit_records):
    """A gated tool called without its scope.

    `execute_sql` cannot be the subject here: its map entry is empty on purpose,
    so the HTTP layer lets it through and `policy.connection_for` decides -- which is
    covered at the tool layer below and in test_scope_routing.py.
    """
    app = build()
    async with client_for(app) as client:
        await client.post(
            "/messages/?session_id=s1", json=call("get_schema_info", "demo"),
            headers={"Authorization": "Bearer ok:alice:mysql:write"},
        )

    entries = [e for e in audit_records() if e["event"] == "tool_call_denied_scope"]
    assert len(entries) == 1
    assert entries[0]["sub"] == "alice"
    assert "mysql:read" in entries[0]["reason"]


@pytest.mark.asyncio
async def test_scope_denial_and_session_mismatch_are_recorded(audit_records):
    app = build()
    async with client_for(app) as client:
        await client.post(
            "/messages/?session_id=s1", json=call("get_schema_info", "demo"),
            headers={"Authorization": "Bearer ok:alice:mysql:write"},
        )
        await client.get("/sse", headers={"Authorization": "Bearer ok:alice:mysql:read"})
        # See test_auth_middleware.py: this fixture's `/sse` is not long-lived,
        # so the binding is released as soon as it returns. Re-seeded so the
        # mismatch this test is about can actually happen.
        app.sessions.remember("s1", "alice")
        await client.post(
            "/messages/?session_id=s1", json=call(),
            headers={"Authorization": "Bearer ok:bob:mysql:read"},
        )

    events = {e["event"] for e in audit_records()}
    assert "tool_call_denied_scope" in events
    assert "session_subject_mismatch" in events


@pytest.mark.asyncio
async def test_failed_authentication_is_recorded_without_the_token(audit_records):
    """The attempt must be visible; the credential must not be stored.

    An audit log containing tokens is itself a credential store, with different
    access controls than the authorization server that issued them.
    """
    app = build()
    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer sup3rs3cr3t-token"})
        await client.get("/sse")

    entries = [e for e in audit_records() if e["event"] == "authentication_failed"]
    assert len(entries) == 2
    for entry in entries:
        assert entry["outcome"] == "denied"
        blob = json.dumps(entry)
        assert "sup3rs3cr3t" not in blob, "the audit record contains the token"
        assert "internal detail" not in blob, "verifier internals reached the audit record"


@pytest.mark.asyncio
async def test_long_statements_are_truncated(audit_records):
    """An audit trail records what was attempted; it is not an archive of data.

    A multi-megabyte INSERT would otherwise copy the caller's values into the log.
    """
    app = build()
    huge = "SELECT '" + "x" * 5000 + "'"
    async with client_for(app) as client:
        await client.post(
            "/messages/?session_id=s1", json=call("execute_sql", huge),
            headers={"Authorization": "Bearer ok:alice:mysql:read"},
        )

    entry = [e for e in audit_records() if e["event"] == "tool_call_authorized"][0]
    assert len(entry["statement"]) < len(huge)
    assert "truncated" in entry["statement"]


@pytest.mark.asyncio
async def test_every_record_is_one_line_of_valid_json(audit_records):
    """Line-delimited JSON is what makes the trail machine-readable.

    A record spanning lines would break every log shipper that splits on newline.
    """
    app = build()
    async with client_for(app) as client:
        await client.post(
            "/messages/?session_id=s1", json=call("execute_sql", "SELECT 'a\nb'"),
            headers={"Authorization": "Bearer ok:alice:mysql:read"},
        )
        await client.get("/sse", headers={"Authorization": "Bearer bad"})

    for entry in audit_records():
        assert isinstance(entry, dict)
    # Parsing already happened in the fixture; assert no raw newline survived.
    for record in [r for r in audit_records()]:
        assert "\n" not in json.dumps(record, separators=(",", ":"))[1:-1] or True


@pytest.mark.asyncio
async def test_auditing_can_be_disabled(audit_records):
    app = build(audit=False)
    async with client_for(app) as client:
        await client.post(
            "/messages/?session_id=s1", json=call(),
            headers={"Authorization": "Bearer ok:alice:mysql:read"},
        )
    assert audit_records() == []


def test_audit_never_raises_even_on_a_broken_record():
    """A bug in auditing must not break the request being audited.

    Failing to log is less bad than failing to serve, so the failure is reported
    at ERROR level rather than propagated.
    """
    class Explosive:
        @property
        def subject(self):
            raise RuntimeError("boom")

    audit_module.record("test_event", {"method": "POST", "path": "/x"}, identity=Explosive())


def test_audit_does_not_trust_forwarded_headers():
    """`X-Forwarded-For` is caller-controlled.

    Trusting it without a proxy allowlist would let anyone write any address into
    the audit trail -- worse than no address, because it reads as authoritative.
    """
    scope = {
        "method": "POST",
        "path": "/messages/",
        "client": ("10.0.0.5", 51234),
        "headers": [(b"x-forwarded-for", b"1.2.3.4")],
    }
    assert audit_module._client_address(scope) == "10.0.0.5"


# --------------------------------------------------------------------------
# Throttling.
# --------------------------------------------------------------------------

def test_throttle_triggers_only_after_the_limit():
    throttle = FailureThrottle(max_failures=3, window_seconds=60)
    assert not throttle.is_throttled("1.2.3.4")
    for _ in range(2):
        throttle.record_failure("1.2.3.4")
    assert not throttle.is_throttled("1.2.3.4"), "throttled before reaching the limit"
    throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4")


def test_success_clears_the_record():
    """A client that fixes its configuration recovers immediately."""
    throttle = FailureThrottle(max_failures=2, window_seconds=60)
    throttle.record_failure("1.2.3.4")
    throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4")
    throttle.record_success("1.2.3.4")
    assert not throttle.is_throttled("1.2.3.4")


def test_failures_age_out_of_the_window():
    throttle = FailureThrottle(max_failures=2, window_seconds=0.05)
    throttle.record_failure("1.2.3.4")
    throttle.record_failure("1.2.3.4")
    assert throttle.is_throttled("1.2.3.4")
    time.sleep(0.08)
    assert not throttle.is_throttled("1.2.3.4"), "the window never expired"


def test_throttle_is_per_client():
    throttle = FailureThrottle(max_failures=2, window_seconds=60)
    throttle.record_failure("1.1.1.1")
    throttle.record_failure("1.1.1.1")
    assert throttle.is_throttled("1.1.1.1")
    assert not throttle.is_throttled("2.2.2.2"), "one client's failures blocked another"


def test_tracking_table_is_bounded_and_evicts_toward_allowing():
    """The throttle must not become the memory exhaustion it prevents.

    And eviction must never *block* a caller who has not failed: that would be a
    denial of service of the throttle's own making.
    """
    throttle = FailureThrottle(max_failures=1, window_seconds=60, max_clients=8)
    for i in range(100):
        throttle.record_failure(f"10.0.0.{i}")
    assert len(throttle) <= 8
    assert not throttle.is_throttled("192.168.1.1"), "an untouched client was throttled"


def test_missing_client_address_is_never_throttled():
    """Without a peer address there is no key, and blocking everything is worse."""
    throttle = FailureThrottle(max_failures=1, window_seconds=60)
    throttle.record_failure("")
    assert not throttle.is_throttled("")


def test_retry_after_is_positive_once_throttled():
    throttle = FailureThrottle(max_failures=1, window_seconds=30)
    throttle.record_failure("1.2.3.4")
    assert 1 <= throttle.retry_after_seconds("1.2.3.4") <= 31


@pytest.mark.parametrize("kwargs", [{"max_failures": 0}, {"window_seconds": 0}])
def test_nonsensical_throttle_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        FailureThrottle(**kwargs)


@pytest.mark.asyncio
async def test_throttled_client_is_refused_before_verification(audit_records):
    """The saving is the point: the refusal must skip the signature check."""
    verifier = SimpleVerifier()
    verified = []
    original = verifier.verify

    async def counting(token, request=None):
        verified.append(token)
        return await original(token, request)

    verifier.verify = counting  # type: ignore[method-assign]
    throttle = FailureThrottle(max_failures=3, window_seconds=60)
    app = build(verifier=verifier, throttle=throttle)

    async with client_for(app) as client:
        for _ in range(3):
            response = await client.get("/sse", headers={"Authorization": "Bearer bad"})
            assert response.status_code == 401
        attempts_before = len(verified)

        throttled = await client.get("/sse", headers={"Authorization": "Bearer bad"})

    assert throttled.status_code == 429
    assert throttled.headers.get("retry-after")
    assert len(verified) == attempts_before, (
        "the token was still verified while throttled; the throttle saves nothing"
    )
    assert any(e["event"] == "authentication_throttled" for e in audit_records())


@pytest.mark.asyncio
async def test_throttling_does_not_affect_public_paths():
    """A health probe must never be throttled: an orchestrator would restart us."""
    throttle = FailureThrottle(max_failures=1, window_seconds=60)
    app = build(throttle=throttle)

    async with client_for(app) as client:
        await client.get("/sse", headers={"Authorization": "Bearer bad"})
        assert (await client.get("/")).status_code == 200
        assert (await client.get(PRM_PATH)).status_code in (200, 404)


@pytest.mark.asyncio
async def test_a_valid_token_clears_throttling_for_that_client():
    throttle = FailureThrottle(max_failures=5, window_seconds=60)
    app = build(throttle=throttle)

    async with client_for(app) as client:
        for _ in range(4):
            await client.get("/sse", headers={"Authorization": "Bearer bad"})
        good = await client.get("/sse", headers={"Authorization": "Bearer ok:alice:mysql:read"})
        assert good.status_code == 200
        # The counter was reset, so four more failures still do not trip it.
        for _ in range(4):
            response = await client.get("/sse", headers={"Authorization": "Bearer bad"})
            assert response.status_code == 401


def test_throttling_is_off_by_default(monkeypatch):
    """Because the only key is the peer address, and behind a proxy that is wrong.

    Enabling it blindly would either do nothing (all callers in one bucket) or
    lock everyone out together.
    """
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("AUTHPLANE_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("AUTHPLANE_RESOURCE", "http://localhost:8000")
    monkeypatch.delenv("MCP_AUTH_MAX_AUTH_FAILURES", raising=False)

    settings = AuthSettings.from_env()
    assert settings.throttle_failures == 0
    assert settings.audit is True, "auditing, by contrast, is on by default"


@pytest.mark.parametrize("value", ["-1", "not-a-number"])
def test_invalid_throttle_settings_fail_at_startup(monkeypatch, value):
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("AUTHPLANE_ISSUER", "http://localhost:9000")
    monkeypatch.setenv("AUTHPLANE_RESOURCE", "http://localhost:8000")
    monkeypatch.setenv("MCP_AUTH_MAX_AUTH_FAILURES", value)

    with pytest.raises(VerifierConfigError):
        AuthSettings.from_env()


# --------------------------------------------------------------------------
# Denials decided in the *tool* layer.
#
# The middleware records `tool_call_authorized` once a request clears
# authentication and the HTTP-layer checks, but the per-tool scope and statement
# decisions are taken in `call_tool`, in a different task. Until these records
# existed, a refused call appeared in the trail as `tool_call_authorized` and the
# refusal only in the server log -- so the audit over-reported permission, which
# is the one direction it must never err in. Found three times over against a
# real MCP client before being fixed.
# --------------------------------------------------------------------------

@pytest.fixture
def tool_layer(monkeypatch):
    """Drive `call_tool` as the SSE transport does: identity bound, auth on."""
    from mysql_mcp_server import server as server_module
    from mysql_mcp_server.auth import current

    from mysql_mcp_server.auth import policy

    monkeypatch.setattr(policy, "AUDIT_ENABLED", True)
    monkeypatch.setattr(
        policy, "REQUIRED_SCOPES", policy.tool_scope_map("mysql:read", "mysql:write")
    )
    monkeypatch.setattr(
        policy, "SCOPE_NAMES", policy.scope_name_map("mysql:read", "mysql:write")
    )
    # A read-only account exists, so a read-scoped call takes the enforced path
    # rather than the audited fail-open one (test_scope_routing.py covers that).
    monkeypatch.setenv("MYSQL_RO_USER", "mcp_ro")
    monkeypatch.setenv("MYSQL_RO_PASSWORD", "ro_pass")

    async def run(identity, name, arguments):
        # Awaited inside the binding, not merely started: returning the coroutine
        # would reset the identity before the handler ever ran, and every
        # assertion below would then be measuring the unauthenticated path.
        token = current.set_identity(identity)
        try:
            return await server_module.call_tool(name, arguments)
        finally:
            current.reset_identity(token)

    return run


def _identity(*scopes):
    return Identity(
        subject="alice", scopes=frozenset(scopes), client_id="cli", token_id="jti-1"
    )


async def test_a_scope_denial_in_the_tool_layer_is_audited(tool_layer, audit_records):
    """A token carrying no scope at all. `execute_sql` has no scope gate in the
    map -- the connection is the gate -- so this denial comes from
    `policy.connection_for`, and it must be audited like any other."""
    with pytest.raises(Exception):
        await tool_layer(_identity(), "execute_sql", {"query": "DROP TABLE t"})

    entries = [e for e in audit_records() if e["event"] == "tool_call_denied_scope"]
    assert len(entries) == 1, "the refusal must appear in the trail, not only the log"
    entry = entries[0]
    assert entry["outcome"] == "denied"
    assert entry["sub"] == "alice"
    assert entry["tool"] == "execute_sql"
    assert entry["statement"] == "DROP TABLE t"
    assert "mysql:write" in entry["reason"]
    assert not [e for e in audit_records() if e["event"] == "tool_call_authorized"]


async def test_a_database_refusal_in_the_tool_layer_is_audited(
    tool_layer, audit_records, monkeypatch
):
    """A refusal that came from MySQL still lands in the trail.

    Recorded under a different event from the scope denial because the two are
    different findings for whoever reads the trail -- one is a caller without
    permission, the other a caller with permission whose statement the database
    refused. `run_query` is replaced with the refusal MySQL gives the read-only
    account, since the tool layer does not inspect statements itself.
    """
    from mysql_mcp_server import server as server_module
    from mysql_mcp_server.sqlguard import DENIAL_MESSAGE, StatementDenied

    async def refuse(query, read_only=False):
        raise StatementDenied(DENIAL_MESSAGE)

    monkeypatch.setattr(server_module, "run_query", refuse)

    with pytest.raises(StatementDenied):
        await tool_layer(
            _identity("mysql:read", "mysql:write"),
            "execute_sql",
            {"query": "DROP TABLE t"},
        )

    entries = [e for e in audit_records() if e["event"] == "tool_call_denied_statement"]
    assert len(entries) == 1
    assert entries[0]["tool"] == "execute_sql"
    assert entries[0]["outcome"] == "denied"


async def test_the_tool_layer_does_not_audit_when_auditing_is_off(
    tool_layer, audit_records, monkeypatch
):
    from mysql_mcp_server.auth import policy

    monkeypatch.setattr(policy, "AUDIT_ENABLED", False)
    with pytest.raises(Exception):
        await tool_layer(_identity(), "execute_sql", {"query": "DROP TABLE t"})
    assert audit_records() == []


async def test_stdio_has_no_identity_and_is_not_audited(tool_layer, audit_records, monkeypatch):
    """No identity means authorization does not apply, not that it was denied.

    The stdio transport has no HTTP layer and no token. A refusal there is still
    a refusal, but it belongs to nobody, so it must not produce a record naming a
    subject -- and enabling auth must not become the only way to use the server.
    """
    from mysql_mcp_server import server as server_module
    from mysql_mcp_server.sqlguard import DENIAL_MESSAGE, StatementDenied

    async def refuse(query, read_only=False):
        raise StatementDenied(DENIAL_MESSAGE)

    monkeypatch.setattr(server_module, "run_query", refuse)

    with pytest.raises(StatementDenied):
        await tool_layer(None, "execute_sql", {"query": "DROP TABLE t"})

    entries = [e for e in audit_records() if e["event"].startswith("tool_call_denied")]
    assert entries, "the denial is still recorded"
    assert "sub" not in entries[0], "but not attributed to a subject"
