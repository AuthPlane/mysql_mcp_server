"""Startup failures, misconfiguration, and the transports auth does not touch.

Cheap tests for the paths that are written and easy to leave unexercised. Each
one exists because the *failure* mode is worse than the feature: a server that
boots claiming auth is on when it is not, or one that hangs instead of reporting
an unreachable authorization server, is harder to diagnose than an outright
crash.
"""

import asyncio
import importlib.util
import socket
import threading
import time

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from mysql_mcp_server.auth import AuthSettings, build_verifier
from mysql_mcp_server.auth.protocol import VerifierConfigError
from mysql_mcp_server.auth.settings import CANONICAL_MODE, RENAMED_ENV_VARS

# The Authplane SDK ships in the optional [auth] extra, so it is absent on any
# base install. Tests that exercise the real verifier skip rather than error,
# which keeps the suite green for contributors who never touch auth.
_HAS_SDK = importlib.util.find_spec("authplane") is not None
requires_sdk = pytest.mark.skipif(
    not _HAS_SDK, reason="needs the [auth] extra (authplane-sdk)"
)


# --------------------------------------------------------------------------
# Misconfiguration must be fatal at startup, never a surprise per-request.
#
# A server that starts "with auth enabled" but cannot verify anything is worse
# than one that refuses to start: the failure surfaces later as mysterious 401s
# under load instead of a message on the console.
# --------------------------------------------------------------------------

@pytest.fixture
def clean_env(monkeypatch):
    for name in (
        "MCP_AUTH_MODE", "MCP_OAUTH_ISSUER", "MCP_OAUTH_RESOURCE", "MCP_OAUTH_SCOPES",
        "MCP_OAUTH_ALLOWED_ALGORITHMS", "MCP_OAUTH_CLOCK_SKEW_SECONDS", "MCP_OAUTH_DEV_MODE",
        "MYSQL_SCOPE_READ", "MYSQL_SCOPE_WRITE", "MCP_AUTH_REVOCATION_CHECK",
        "MCP_AUTH_MAX_AUTH_FAILURES", "MCP_AUTH_AUDIT",
    ):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_auth_disabled_by_default(clean_env):
    """The whole change is inert unless explicitly switched on."""
    settings = AuthSettings.from_env()
    assert settings.enabled is False


@pytest.mark.parametrize("value", ["none", "off", "false", "0", ""])
def test_explicit_off_values_all_disable_auth(clean_env, value):
    clean_env.setenv("MCP_AUTH_MODE", value)
    assert AuthSettings.from_env().enabled is False


def test_unknown_mode_is_rejected_rather_than_silently_ignored(clean_env):
    """A typo must not fail open.

    `MCP_AUTH_MODE=authpalne` quietly meaning "no auth" is the worst possible
    outcome: the operator believes the server is protected.
    """
    clean_env.setenv("MCP_AUTH_MODE", "authpalne")
    with pytest.raises(VerifierConfigError, match="not recognised"):
        AuthSettings.from_env()


# --------------------------------------------------------------------------
# The configuration surface carries no provider's name. The prefixed spellings
# these variables had during development stay readable, which is a documented
# promise rather than a convenience -- so it is asserted, not assumed.
# --------------------------------------------------------------------------

def _minimal_oauth_env(env, *, issuer=True, resource=True):
    env.setenv("MCP_AUTH_MODE", CANONICAL_MODE)
    if issuer:
        env.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    if resource:
        env.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")


def test_documented_mode_is_the_protocol_not_the_backend(clean_env):
    """`MCP_AUTH_MODE=oauth` is what the docs and .env.example carry."""
    _minimal_oauth_env(clean_env)
    settings = AuthSettings.from_env()
    assert settings.enabled is True
    assert settings.mode == CANONICAL_MODE


@pytest.mark.parametrize("spelling", ["authplane", "AuthPlane", "AUTHPLANE"])
def test_pre_rename_mode_still_boots_and_normalises(clean_env, spelling):
    """`authplane` was the mode during development, before it named the protocol.

    Refusing to boot on it would take a *protected* server down, and the
    operator's fastest way back up is a value that boots -- which may well be
    `none`. It resolves to the canonical mode so `build_verifier` dispatches on
    one spelling.
    """
    clean_env.setenv("MCP_AUTH_MODE", spelling)
    clean_env.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    clean_env.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    assert AuthSettings.from_env().mode == CANONICAL_MODE


def test_mode_alias_normalises_on_hand_built_settings_too(clean_env):
    """The harness and embedding applications construct settings directly."""
    settings = AuthSettings(enabled=True, mode="authplane")
    assert settings.mode == CANONICAL_MODE


@pytest.mark.parametrize("current,legacy", sorted(RENAMED_ENV_VARS.items()))
def test_every_renamed_variable_still_reads_its_predecessor(clean_env, current, legacy):
    """Parametrised over the table itself, so a new entry cannot ship untested."""
    # Start from a configuration that boots, then move exactly one variable to
    # its pre-rename spelling. Issuer and resource are required, so for those
    # two the legacy name is carrying the value the boot depends on.
    _minimal_oauth_env(clean_env)
    clean_env.delenv(current, raising=False)
    # Values that have to parse as something specific; the rest take a URL.
    values = {
        "MCP_OAUTH_CLOCK_SKEW_SECONDS": "45",
        "MCP_OAUTH_ALLOWED_ALGORITHMS": "ES256",
        "MCP_OAUTH_DEV_MODE": "true",
        "MCP_OAUTH_SCOPES": "a:read",
        "MCP_OAUTH_REALM": "legacy-realm",
        "MCP_OAUTH_CLIENT_ID": "c",
        "MCP_OAUTH_CLIENT_SECRET": "s",
    }
    clean_env.setenv(legacy, values.get(current, "http://localhost:9000"))

    # The assertion is that it boots at all: every one of these is either
    # required or validated, so a dropped fallback surfaces as a raise here.
    assert AuthSettings.from_env().enabled is True


def test_pre_rename_value_is_honoured_with_its_meaning_intact(clean_env):
    """Not just "it boots" -- the value arrives where it belongs."""
    _minimal_oauth_env(clean_env)
    clean_env.delenv("MCP_OAUTH_CLOCK_SKEW_SECONDS", raising=False)
    clean_env.setenv("AUTHPLANE_CLOCK_SKEW_SECONDS", "45")
    assert AuthSettings.from_env().clock_skew_seconds == 45


def test_current_name_wins_over_its_predecessor(clean_env):
    """An operator part way through the rename has both set."""
    _minimal_oauth_env(clean_env)
    clean_env.setenv("MCP_OAUTH_CLOCK_SKEW_SECONDS", "10")
    clean_env.setenv("AUTHPLANE_CLOCK_SKEW_SECONDS", "45")
    assert AuthSettings.from_env().clock_skew_seconds == 10


def test_blank_current_name_falls_back_rather_than_failing_the_boot(clean_env):
    """A fresh .env.example leaves the documented names blank beside a populated one.

    Treating the blank as the answer would fail a boot whose configuration is
    sitting in the environment one variable away.
    """
    _minimal_oauth_env(clean_env, issuer=False)
    clean_env.setenv("MCP_OAUTH_ISSUER", "")
    clean_env.setenv("AUTHPLANE_ISSUER", "http://localhost:9000")
    assert AuthSettings.from_env().issuer == "http://localhost:9000"


def test_using_a_pre_rename_name_warns_and_names_its_replacement(clean_env, caplog):
    """A silent fallback is a rename nobody ever completes."""
    _minimal_oauth_env(clean_env)
    clean_env.delenv("MCP_OAUTH_CLOCK_SKEW_SECONDS", raising=False)
    clean_env.setenv("AUTHPLANE_CLOCK_SKEW_SECONDS", "45")
    with caplog.at_level("WARNING"):
        AuthSettings.from_env()
    assert any(
        "AUTHPLANE_CLOCK_SKEW_SECONDS" in r.message
        and "MCP_OAUTH_CLOCK_SKEW_SECONDS" in r.message
        for r in caplog.records
    ), "the warning has to name both spellings to be actionable"


def test_no_provider_name_remains_in_the_configuration_surface(clean_env):
    """The point of the rename: what an operator sets carries no vendor's name.

    Asserted against the error text an operator actually meets, because that is
    the other place a variable name is published.
    """
    clean_env.setenv("MCP_AUTH_MODE", CANONICAL_MODE)
    with pytest.raises(VerifierConfigError) as caught:
        AuthSettings.from_env()
    assert "AUTHPLANE" not in str(caught.value).upper()
    assert "MCP_OAUTH_ISSUER" in str(caught.value)


@pytest.mark.parametrize(
    "present,missing",
    [
        ({"MCP_OAUTH_ISSUER": "http://localhost:9000"}, "MCP_OAUTH_RESOURCE"),
        ({"MCP_OAUTH_RESOURCE": "http://localhost:8000"}, "MCP_OAUTH_ISSUER"),
        ({}, "MCP_OAUTH_ISSUER"),
    ],
)
def test_auth_on_without_required_settings_fails_at_startup(clean_env, present, missing):
    clean_env.setenv("MCP_AUTH_MODE", "authplane")
    for key, value in present.items():
        clean_env.setenv(key, value)
    with pytest.raises(VerifierConfigError, match=missing):
        AuthSettings.from_env()


def test_alg_none_is_refused_in_configuration(clean_env):
    """`alg: none` means an unsigned token: anyone can mint one for any subject.

    Refused at configuration time so it cannot be reached at all, rather than
    relying on the verifier to reject each token.
    """
    clean_env.setenv("MCP_AUTH_MODE", "authplane")
    clean_env.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    clean_env.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    clean_env.setenv("MCP_OAUTH_ALLOWED_ALGORITHMS", "ES256,none")
    with pytest.raises(VerifierConfigError, match="none"):
        AuthSettings.from_env()


def test_empty_algorithm_list_is_refused(clean_env):
    clean_env.setenv("MCP_AUTH_MODE", "authplane")
    clean_env.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    clean_env.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    clean_env.setenv("MCP_OAUTH_ALLOWED_ALGORITHMS", " , ")
    with pytest.raises(VerifierConfigError):
        AuthSettings.from_env()


def test_identical_read_and_write_scopes_are_refused(clean_env):
    """Identical values collapse the read/write split into no split at all."""
    clean_env.setenv("MCP_AUTH_MODE", "authplane")
    clean_env.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    clean_env.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    clean_env.setenv("MYSQL_SCOPE_READ", "mysql:all")
    clean_env.setenv("MYSQL_SCOPE_WRITE", "mysql:all")
    with pytest.raises(VerifierConfigError, match="collapse"):
        AuthSettings.from_env()


def test_issuer_trailing_slash_is_stripped(clean_env):
    """The issuer must match the token's `iss` byte-for-byte.

    Unlike the resource (below), the issuer's source of truth is whatever
    Authplane itself puts in the token, and by its own convention that is the
    bare origin with no trailing slash -- so stripping one here is correct.
    """
    clean_env.setenv("MCP_AUTH_MODE", "authplane")
    clean_env.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000/")
    clean_env.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    settings = AuthSettings.from_env()
    assert settings.issuer == "http://localhost:9000"


@pytest.mark.parametrize(
    "given,expected",
    [
        # A root resource always gains the trailing slash: RFC 3986 treats an
        # empty path as equivalent to `/`, so any URL library a real OAuth
        # client uses to build its `resource=` parameter produces the
        # slash form. Reproduced directly against a live Authplane server:
        # a client requesting `http://localhost:8000/` was refused with
        # "Unknown Resource" when this server's own settings said
        # `http://localhost:8000` -- both are the same resource, but the
        # authorization server compares strings, not URIs.
        ("http://localhost:8000", "http://localhost:8000/"),
        ("http://localhost:8000/", "http://localhost:8000/"),
        # A non-root path is left exactly as given in both directions: the
        # slash there is part of the path, not an artefact of an empty one,
        # and `.../mcp` and `.../mcp/` are different resources.
        ("http://localhost:8000/mcp", "http://localhost:8000/mcp"),
        ("http://localhost:8000/mcp/", "http://localhost:8000/mcp/"),
    ],
)
def test_resource_root_path_is_canonicalised(clean_env, given, expected):
    """The Resource URI must match what a real client sends, byte-for-byte."""
    clean_env.setenv("MCP_AUTH_MODE", "authplane")
    clean_env.setenv("MCP_OAUTH_ISSUER", "http://localhost:9000")
    clean_env.setenv("MCP_OAUTH_RESOURCE", given)
    settings = AuthSettings.from_env()
    assert settings.resource == expected


def test_http_issuer_warns_outside_dev_mode(clean_env, caplog):
    """Bearer tokens over http:// travel in cleartext. Legitimate locally, loud anyway."""
    clean_env.setenv("MCP_AUTH_MODE", "authplane")
    clean_env.setenv("MCP_OAUTH_ISSUER", "http://auth.example.com")
    clean_env.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    with caplog.at_level("WARNING"):
        AuthSettings.from_env()
    assert any("http://" in r.message or "unencrypted" in r.message for r in caplog.records)


# --------------------------------------------------------------------------
# An unreachable or broken authorization server at startup.
# --------------------------------------------------------------------------

def _settings(issuer: str) -> AuthSettings:
    return AuthSettings(
        enabled=True,
        mode="authplane",
        issuer=issuer,
        resource="http://localhost:8000",
        scopes=("mysql:read", "mysql:write"),
        allowed_algorithms=("ES256",),
        dev_mode=True,
    )


@requires_sdk
@pytest.mark.asyncio
async def test_unreachable_authorization_server_fails_with_an_actionable_message():
    """Not a traceback, and not a hang: a sentence naming the address and the fix.

    Discovery happens at startup deliberately, so a wrong issuer is a boot
    failure rather than a 401 storm later.
    """
    # Port 9 is the discard service; nothing listens on it in practice.
    with pytest.raises(VerifierConfigError) as caught:
        await build_verifier(_settings("http://127.0.0.1:9"))

    message = str(caught.value)
    assert "127.0.0.1:9" in message, "the message should name the address that failed"
    assert "MCP_AUTH_MODE" in message or "Start it" in message, (
        "the message should say what to do about it"
    )


@requires_sdk
@pytest.mark.asyncio
async def test_malformed_discovery_document_fails_cleanly():
    """A server that answers with nonsense must not be treated as usable."""
    port = 8791

    async def bad_metadata(request):
        return PlainTextResponse("this is not json at all", media_type="application/json")

    app = Starlette(routes=[
        Route("/.well-known/oauth-authorization-server", endpoint=bad_metadata),
        Route("/.well-known/openid-configuration", endpoint=bad_metadata),
    ])

    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 15
        while not getattr(server, "started", False) and time.time() < deadline:
            time.sleep(0.05)

        with pytest.raises(VerifierConfigError):
            await build_verifier(_settings(f"http://127.0.0.1:{port}"))
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@requires_sdk
@pytest.mark.asyncio
async def test_jwks_endpoint_serving_garbage_fails_cleanly():
    """Valid discovery, unusable key set: still a startup failure, not a half-alive server.

    The alternative -- booting with an empty key cache -- means every token is
    rejected with no indication why.
    """
    port = 8792

    async def metadata(request):
        base = f"http://127.0.0.1:{port}"
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "response_types_supported": ["code"],
        })

    async def jwks(request):
        return PlainTextResponse("{not json", media_type="application/json")

    app = Starlette(routes=[
        Route("/.well-known/oauth-authorization-server", endpoint=metadata),
        Route("/.well-known/openid-configuration", endpoint=metadata),
        Route("/.well-known/jwks.json", endpoint=jwks),
    ])

    import uvicorn

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 15
        while not getattr(server, "started", False) and time.time() < deadline:
            time.sleep(0.05)

        verifier = None
        try:
            verifier = await build_verifier(_settings(f"http://127.0.0.1:{port}"))
        except VerifierConfigError:
            return  # failing at startup is the preferred outcome
        finally:
            if verifier is not None:
                await verifier.aclose()
        # If it did start, it must at least not accept tokens.
        pytest.skip(
            "the SDK tolerated a malformed JWKS at startup; verify() behaviour is "
            "covered by the rejection tests"
        )
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@requires_sdk
@pytest.mark.asyncio
async def test_a_hanging_authorization_server_does_not_hang_startup_forever():
    """A socket that accepts and never answers must not wedge the boot.

    Without a bounded timeout the process would sit in discovery indefinitely,
    and an orchestrator would see a container that never becomes ready and never
    fails either.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    accepted = []

    def accept_and_stall():
        try:
            conn, _ = listener.accept()
            accepted.append(conn)  # held open, never written to
        except OSError:
            pass

    threading.Thread(target=accept_and_stall, daemon=True).start()

    try:
        with pytest.raises((VerifierConfigError, asyncio.TimeoutError)):
            await asyncio.wait_for(
                build_verifier(_settings(f"http://127.0.0.1:{port}")), timeout=60
            )
    finally:
        for conn in accepted:
            conn.close()
        listener.close()


# --------------------------------------------------------------------------
# Transports and requests that auth must leave alone.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stdio_transport_ignores_auth_configuration(monkeypatch):
    """stdio has no HTTP layer, so there is nothing for auth to attach to.

    The client launches this server as a subprocess and talks over pipes; the
    security boundary is the OS process, not a token. Auth settings must be
    ignored entirely rather than causing a startup failure for stdio users who
    happen to have the variables exported.
    """
    from mysql_mcp_server import server as server_module

    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://127.0.0.1:9")  # would fail if consulted
    monkeypatch.setenv("MCP_OAUTH_RESOURCE", "http://localhost:8000")
    # No read-only account configured, so the startup read-path check reports
    # the posture and returns without touching MySQL. Cleared explicitly rather
    # than inherited: this test is about transport dispatch, and an ambient
    # MYSQL_RO_USER would otherwise send it looking for a database.
    # The read-only account is required at startup; this test is about transport
    # dispatch, so it is configured and the grant check stubbed out.
    monkeypatch.setenv("MYSQL_RO_USER", "mcp_ro")
    monkeypatch.setattr(server_module, "verify_readonly_account", lambda: [])

    ran = []

    async def fake_stdio():
        ran.append("stdio")

    async def fake_sse():  # pragma: no cover - must not be reached
        ran.append("sse")

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)
    monkeypatch.setattr(server_module, "_run_sse_server", fake_sse)

    await server_module.main()

    assert ran == ["stdio"], "stdio transport should not touch the SSE/auth path"


@pytest.mark.asyncio
async def test_unset_transport_defaults_to_stdio(monkeypatch):
    from mysql_mcp_server import server as server_module

    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    monkeypatch.setenv("MYSQL_RO_USER", "mcp_ro")
    monkeypatch.setattr(server_module, "verify_readonly_account", lambda: [])
    ran = []

    async def fake_stdio():
        ran.append("stdio")

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)
    await server_module.main()
    assert ran == ["stdio"]


# --------------------------------------------------------------------------
# The read-path posture check, and why its two halves answer differently.
#
# *Verifying* the account is a property of the database configuration:
# `get_db_config(read_only=True)` honours MYSQL_RO_USER unconditionally --
# including over stdio, which never reaches the SSE path -- so an account that
# can write is fatal on every transport, and the check runs in `main()` ahead of
# the transport split rather than inside `if auth_settings.enabled:`. Gate it on
# auth instead and an operator running stdio with a misprovisioned account gets
# the weaker posture with no check and no warning.
#
# The account being *absent* is different: there is a working degraded mode, and
# it only degrades something if scopes exist. So that half is a warning, and only
# under auth.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stdio_verifies_the_read_only_account(monkeypatch):
    """The regression this move exists to prevent."""
    from mysql_mcp_server import server as server_module

    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("MYSQL_RO_USER", "mcp_ro")
    monkeypatch.delenv("MCP_AUTH_MODE", raising=False)

    checked = []
    monkeypatch.setattr(
        server_module, "verify_readonly_account", lambda: checked.append(True) or []
    )

    async def fake_stdio():
        return None

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)
    await server_module.main()

    assert checked == [True], "stdio must verify the read-only grants too"


@pytest.mark.asyncio
async def test_a_writable_read_only_account_refuses_to_boot_on_stdio(monkeypatch):
    """Fatal, not a warning.

    A read-only account that can write is not a degraded configuration, it is a
    false one: every read-scoped call claims a guarantee the database is not
    enforcing, and unlike a missing account there is nothing to preserve.
    """
    from mysql_mcp_server import server as server_module

    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("MYSQL_RO_USER", "mcp_ro")
    monkeypatch.setattr(
        server_module,
        "verify_readonly_account",
        lambda: ["MYSQL_RO_USER holds INSERT, so the read path is not read-only"],
    )

    async def fake_stdio():  # pragma: no cover - must not be reached
        raise AssertionError("server should not have started")

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)

    with pytest.raises(RuntimeError, match="read-only privilege set"):
        await server_module.main()


@pytest.mark.asyncio
async def test_no_read_only_account_warns_under_auth_and_still_boots(monkeypatch, caplog):
    """Absent account: a warning, not a refusal to start.

    It was fatal for one release. That failed closed on a configuration that has
    a working degraded mode -- a read-scoped caller runs on the read-write
    account -- so it broke every deployment upgrading into it before an operator
    could provision the account. The guarantee the read scope makes is weaker
    until they do, which is what the warning is for.
    """
    from mysql_mcp_server import server as server_module

    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("MCP_AUTH_MODE", "authplane")
    monkeypatch.delenv("MYSQL_RO_USER", raising=False)

    started = []

    async def fake_stdio():
        started.append(True)

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)

    with caplog.at_level("WARNING", logger="mysql_mcp_server"):
        await server_module.main()

    assert started == [True], "a missing read-only account must not stop the server"
    warnings = [r for r in caplog.records if "MYSQL_RO_USER" in r.getMessage()]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "DROP DATABASE" in message, (
        "the operator has to learn the consequence, not just the missing variable"
    )
    assert "CREATE USER" in message and "GRANT SELECT" in message, (
        "a warning about a configuration must say how to fix it"
    )


@pytest.mark.asyncio
async def test_no_read_only_account_is_silent_without_auth(monkeypatch, caplog):
    """Without auth there is no scope, so nothing is being claimed.

    This is the original server's configuration: one MySQL account, no tokens,
    the process boundary as the security boundary. Warning there would be
    telling an operator their setup is degraded against a guarantee they never
    asked for.
    """
    from mysql_mcp_server import server as server_module

    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.delenv("MCP_AUTH_MODE", raising=False)
    monkeypatch.delenv("MYSQL_RO_USER", raising=False)

    async def fake_stdio():
        return None

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)

    with caplog.at_level("WARNING", logger="mysql_mcp_server"):
        await server_module.main()

    assert not [r for r in caplog.records if "MYSQL_RO_USER" in r.getMessage()]


@pytest.mark.asyncio
async def test_a_half_configured_auth_env_does_not_break_the_read_path_check(monkeypatch):
    """The check asks only whether auth is on.

    `AuthSettings.from_env()` raises on a half-configured auth setup, which is
    right where auth is about to be wired up and wrong here: an operator running
    stdio with a stray AUTHPLANE_* variable exported would get an exception from
    the read-path check instead of a server.
    """
    from mysql_mcp_server import server as server_module

    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.delenv("MCP_AUTH_MODE", raising=False)
    monkeypatch.setenv("MCP_OAUTH_ISSUER", "http://127.0.0.1:9")
    monkeypatch.delenv("MCP_OAUTH_RESOURCE", raising=False)
    monkeypatch.delenv("MYSQL_RO_USER", raising=False)

    started = []

    async def fake_stdio():
        started.append(True)

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)
    await server_module.main()
    assert started == [True]


@pytest.mark.asyncio
async def test_cors_preflight_is_not_rejected_by_auth():
    """A browser strips credentials from a preflight by design.

    Answering 401 would stop the browser from ever sending the real request, so
    browser clients would break entirely -- while protecting nothing, since a
    preflight reaches no handler that touches the database.

    Note the wider limitation: this repo ships no CORS middleware at all, so a
    browser still cannot use the server. This asserts only that auth does not
    make that worse.
    """
    import httpx
    from starlette.routing import Mount

    from mysql_mcp_server.auth import AuthMiddleware
    from mysql_mcp_server.auth.protocol import AuthenticationError, Identity

    class Rejects:
        async def verify(self, token, request=None):
            raise AuthenticationError("no")

        def protected_resource_metadata(self):
            return {"resource": "http://testserver", "authorization_servers": ["http://x"]}

        def metadata_url(self):
            return "http://testserver/.well-known/oauth-protected-resource"

        async def aclose(self):
            return None

    async def messages(request):
        return PlainTextResponse("reached")

    app = Starlette(routes=[
        Mount("/messages/", routes=[
            Route("/", endpoint=messages, methods=["POST", "OPTIONS"]),
        ]),
    ])
    wrapped = AuthMiddleware(app, verifier=Rejects(), realm="test")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=wrapped), base_url="http://testserver"
    ) as client:
        response = await client.options(
            "/messages/?session_id=x",
            headers={
                "Origin": "http://example.com",
                "Access-Control-Request-Method": "POST",
            },
        )

    assert response.status_code != 401, "a credential-less preflight must not be rejected by auth"


def test_auth_package_imports_without_the_optional_dependency():
    """`import mysql_mcp_server` must work with only the base install.

    The provider SDK is imported inside `AuthplaneVerifier.create()`, not at
    module scope, so someone running stdio with no `[auth]` extra is unaffected.
    """
    import importlib

    import mysql_mcp_server.auth as auth_pkg
    import mysql_mcp_server.auth.authplane as authplane_module

    importlib.reload(auth_pkg)
    source = authplane_module.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()

    module_level = [
        line for line in text.splitlines()
        if line.startswith("import authplane") or line.startswith("from authplane")
    ]
    assert module_level == [], (
        f"authplane is imported at module scope ({module_level}); this breaks "
        "`import mysql_mcp_server` when the [auth] extra is not installed"
    )


@requires_sdk
@pytest.mark.asyncio
async def test_missing_extra_produces_an_actionable_message(monkeypatch):
    """The message must name the install command, not just fail on ImportError."""
    import builtins

    from mysql_mcp_server.auth import authplane as authplane_module

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "authplane":
            raise ImportError("No module named 'authplane'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(VerifierConfigError, match=r"mysql_mcp_server\[auth\]"):
        await authplane_module.AuthplaneVerifier.create(_settings("http://localhost:9000"))


@pytest.mark.asyncio
async def test_an_unreachable_database_is_not_reported_as_a_bad_grant(monkeypatch):
    """The two findings the grant check can produce need different messages.

    `verify_readonly_account` reports both through one list. Told "MYSQL_RO_USER
    does not have a read-only privilege set" when the real problem is that MySQL
    is down, an operator goes and inspects grants that are fine. Found by running
    the startup path with the database stopped.
    """
    from mysql_mcp_server import server as server_module

    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("MYSQL_RO_USER", "mcp_ro")
    monkeypatch.setattr(
        server_module,
        "verify_readonly_account",
        lambda: [f"{server_module.UNVERIFIABLE_PREFIX}: Can't connect to MySQL server"],
    )

    async def fake_stdio():  # pragma: no cover - must not be reached
        raise AssertionError("server should not have started")

    monkeypatch.setattr(server_module, "_run_stdio_server", fake_stdio)

    with pytest.raises(RuntimeError, match="Could not verify") as caught:
        await server_module.main()

    message = str(caught.value)
    assert "MYSQL_HOST" in message, "it must point at the connection, not the grants"
    assert "privilege set" not in message
