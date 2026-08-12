"""``AuthplaneVerifier`` against a real Authplane server, with real tokens.

This file exists because the rest of the suite cannot cover what it covers. Every
other auth test drives a fake verifier through the ``TokenVerifier`` protocol,
which proves our middleware and proves nothing about our use of the SDK: a fake
raises on cue, so it cannot notice that we read a claim by the wrong name, or
that an SDK default is not what we assumed.

Skipped unless a live server is configured. See ``authplane_harness`` and
``tests/README.md``.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

import pytest

from authplane_harness import (
    DECOY_RESOURCE,
    DECOY_SCOPE,
    READ_SCOPE,
    RESOURCE,
    WRITE_SCOPE,
    LiveAuthplane,
    claims_of,
    header_of,
    new_dpop_provider,
    requires_live_authplane,
    settings_for,
)

from mysql_mcp_server.auth.protocol import (
    AuthenticationError,
    AuthorizationError,
    RequestContext,
)

pytestmark = [requires_live_authplane, pytest.mark.live_auth]

MESSAGES_URL = f"{RESOURCE}/messages/"


@asynccontextmanager
async def verifier(**overrides):
    """A real ``AuthplaneVerifier``, closed afterwards.

    Construction performs live discovery and primes the JWKS cache, so each one
    is a real round trip to the authorization server.
    """
    from mysql_mcp_server.auth.authplane import AuthplaneVerifier

    built = await AuthplaneVerifier.create(settings_for(**overrides))
    try:
        yield built
    finally:
        await built.aclose()


@pytest.fixture(scope="session")
def live():
    harness = LiveAuthplane()
    harness.ensure_resource("mysql-mcp-server", RESOURCE, (READ_SCOPE, WRITE_SCOPE))
    harness.ensure_resource("decoy", DECOY_RESOURCE, (DECOY_SCOPE,))
    try:
        yield harness
    finally:
        harness.cleanup()


@pytest.fixture(scope="session")
def rw_client(live):
    return live.new_client("mcp-rw", f"{READ_SCOPE} {WRITE_SCOPE}")


@pytest.fixture(scope="session")
def ro_client(live):
    return live.new_client("mcp-ro", READ_SCOPE)


@pytest.fixture(scope="session")
def decoy_client(live):
    return live.new_client("mcp-decoy", DECOY_SCOPE)


@pytest.fixture
def rw_token(live, rw_client):
    return live.mint(rw_client, f"{READ_SCOPE} {WRITE_SCOPE}")


# --------------------------------------------------------------------------
# The success path. Nothing else in the suite executes it.
# --------------------------------------------------------------------------


async def test_a_real_token_verifies(rw_token):
    """The baseline: a token Authplane actually issued is accepted."""
    async with verifier() as v:
        identity = await v.verify(rw_token)
    assert identity.subject


async def test_every_identity_field_is_populated_from_real_claims(live, rw_client, rw_token):
    """Guards the silent-empty-string failure mode.

    ``AuthplaneVerifier.verify`` reads claims defensively --
    ``getattr(claims, "sub", "") or ""``. If the SDK ever renames a field, that
    does not raise: it yields an *empty* subject, an empty ``jti``, an
    ``expires_at`` of 0, and authentication keeps "working" while the audit trail
    silently loses the identity it exists to record. Only a real token can catch
    it, because a fake verifier returns whatever Identity the test wrote.
    """
    claims = claims_of(rw_token)

    async with verifier() as v:
        identity = await v.verify(rw_token)

    assert identity.subject == claims["sub"], "subject must come from the real 'sub' claim"
    assert identity.client_id == claims["client_id"] == rw_client[0]
    assert identity.token_id == claims["jti"], "jti is what the audit trail records instead of the token"
    assert identity.expires_at == claims["exp"]
    assert identity.expires_at > time.time(), "a freshly minted token should not be expired"
    assert identity.raw, "raw claims should be carried through for auditing"


async def test_scopes_are_read_from_the_real_claim(live, ro_client):
    """Pins the scope-claim contract that ``_scopes_of`` guesses at.

    RFC 8693 makes ``scope`` a space-delimited string, and the code tolerates
    both that and a pre-split sequence because the SDK's shape was not certain.
    Against a real token the answer is definite: the SDK exposes
    ``VerifiedClaims.scopes`` as a tuple, and the raw claim is the RFC's string.
    Both are asserted so a change to either is caught here.
    """
    token = live.mint(ro_client, READ_SCOPE)

    assert claims_of(token)["scope"] == READ_SCOPE, "the wire format is the RFC's string"

    async with verifier() as v:
        identity = await v.verify(token)

    assert identity.scopes == frozenset({READ_SCOPE}), "a read-only token grants exactly the read scope"
    assert WRITE_SCOPE not in identity.scopes


async def test_a_read_only_token_does_not_carry_the_write_scope(live, ro_client):
    """The scope split is enforced by the authorization server, not just by us."""
    token = live.mint(ro_client, READ_SCOPE)
    async with verifier() as v:
        identity = await v.verify(token)
    assert identity.scopes == frozenset({READ_SCOPE})


# --------------------------------------------------------------------------
# Rejection paths, against genuinely malformed or foreign tokens.
# --------------------------------------------------------------------------


async def test_a_token_minted_for_another_resource_is_refused(live, decoy_client):
    """The confused-deputy defence, with a token that is otherwise perfectly valid.

    Correctly signed by the same authorization server, unexpired, and useless
    here because its ``aud`` names a different resource. This is the check that
    stops a token issued for some other service being replayed against the
    database.
    """
    decoy = live.mint(decoy_client, DECOY_SCOPE, resource=DECOY_RESOURCE)
    assert claims_of(decoy)["aud"] == [DECOY_RESOURCE], "the decoy really is for another audience"

    async with verifier() as v:
        with pytest.raises(AuthenticationError):
            await v.verify(decoy)


async def test_a_tampered_signature_is_refused(rw_token):
    head, payload, signature = rw_token.split(".")
    forged = signature[:-4] + ("aaaa" if not signature.endswith("aaaa") else "bbbb")
    async with verifier() as v:
        with pytest.raises(AuthenticationError):
            await v.verify(f"{head}.{payload}.{forged}")


async def test_a_payload_edited_after_signing_is_refused(live, ro_client):
    """Escalating the scope claim by hand must not survive signature validation."""
    import base64
    import json

    token = live.mint(ro_client, READ_SCOPE)
    head, payload, signature = token.split(".")
    claims = claims_of(token)
    claims["scope"] = f"{READ_SCOPE} {WRITE_SCOPE}"
    forged_payload = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    )

    async with verifier() as v:
        with pytest.raises(AuthenticationError):
            await v.verify(f"{head}.{forged_payload}.{signature}")


@pytest.mark.parametrize("garbage", ["", "not-a-jwt", "a.b.c", "..", "Bearer something"])
async def test_malformed_tokens_are_refused_without_leaking_detail(garbage):
    async with verifier() as v:
        with pytest.raises(AuthenticationError):
            await v.verify(garbage)


async def test_an_unsigned_token_is_refused(rw_token):
    """``alg: none`` means anyone can mint a token for any subject."""
    import base64
    import json

    payload = rw_token.split(".")[1]
    unsigned_header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "at+jwt"}).encode())
        .rstrip(b"=")
        .decode()
    )
    async with verifier() as v:
        with pytest.raises(AuthenticationError):
            await v.verify(f"{unsigned_header}.{payload}.")


async def test_an_algorithm_outside_the_allowlist_is_refused(rw_token):
    """The allowlist is enforced against a real ES256 token, not a simulated one."""
    assert header_of(rw_token)["alg"] == "ES256"
    async with verifier(allowed_algorithms=("RS256",)) as v:
        with pytest.raises(AuthenticationError):
            await v.verify(rw_token)


# --------------------------------------------------------------------------
# DPoP, with proofs signed by a real key.
# --------------------------------------------------------------------------


async def test_the_authorization_server_binds_the_token_to_the_proof_key(live, ro_client):
    """Sending a proof on the *token* request is what produces a bound token."""
    provider = new_dpop_provider()
    token = live.mint(ro_client, READ_SCOPE, dpop_provider=provider)

    confirmation = claims_of(token).get("cnf")
    assert confirmation, "a DPoP token request must yield a cnf claim"
    assert confirmation["jkt"] == provider.key_material.thumbprint


async def test_a_real_dpop_proof_is_accepted(live, ro_client):
    provider = new_dpop_provider()
    token = live.mint(ro_client, READ_SCOPE, dpop_provider=provider)
    proof = provider.build_proof("POST", MESSAGES_URL, access_token=token)

    async with verifier(dpop="optional") as v:
        identity = await v.verify(
            token, RequestContext(method="POST", url=MESSAGES_URL, proof=proof)
        )

    assert identity.scopes == frozenset({READ_SCOPE})


async def test_a_replayed_proof_is_refused(live, ro_client):
    """A captured proof must be single-use.

    Both calls go through one verifier on purpose: replay detection is stateful,
    and a fresh verifier would have an empty replay store and accept the proof.
    """
    provider = new_dpop_provider()
    token = live.mint(ro_client, READ_SCOPE, dpop_provider=provider)
    proof = provider.build_proof("POST", MESSAGES_URL, access_token=token)
    context = RequestContext(method="POST", url=MESSAGES_URL, proof=proof)

    async with verifier(dpop="optional") as v:
        await v.verify(token, context)
        with pytest.raises(AuthenticationError):
            await v.verify(token, context)


async def test_a_stale_proof_is_refused(live, ro_client):
    """An old proof must not be replayable later, even against a fresh verifier."""
    provider = new_dpop_provider()
    token = live.mint(ro_client, READ_SCOPE, dpop_provider=provider)
    stale = provider.build_proof(
        "POST", MESSAGES_URL, access_token=token, issued_at=int(time.time()) - 3600
    )

    async with verifier(dpop="optional") as v:
        with pytest.raises(AuthenticationError):
            await v.verify(token, RequestContext(method="POST", url=MESSAGES_URL, proof=stale))


@pytest.mark.parametrize(
    "method,url",
    [("GET", MESSAGES_URL), ("POST", f"{RESOURCE}/somewhere-else")],
    ids=["wrong-method", "wrong-url"],
)
async def test_a_proof_bound_to_a_different_request_is_refused(live, ro_client, method, url):
    """A proof is bound to one method and one URL, so it cannot be lifted onto another call."""
    provider = new_dpop_provider()
    token = live.mint(ro_client, READ_SCOPE, dpop_provider=provider)
    proof = provider.build_proof(method, url, access_token=token)

    async with verifier(dpop="optional") as v:
        with pytest.raises(AuthenticationError):
            await v.verify(token, RequestContext(method="POST", url=MESSAGES_URL, proof=proof))


async def test_a_proof_signed_by_a_different_key_is_refused(live, ro_client):
    """The whole point of DPoP: a stolen token without its key is unusable."""
    owner = new_dpop_provider()
    thief = new_dpop_provider()
    token = live.mint(ro_client, READ_SCOPE, dpop_provider=owner)
    forged = thief.build_proof("POST", MESSAGES_URL, access_token=token)

    async with verifier(dpop="optional") as v:
        with pytest.raises(AuthenticationError):
            await v.verify(token, RequestContext(method="POST", url=MESSAGES_URL, proof=forged))


async def test_a_bound_token_presented_without_a_proof_is_refused(live, ro_client):
    """`optional` is about the *client's* choice, not the token's.

    Once a token carries `cnf.jkt` the binding is a property of the token, so
    presenting it bare is refused even in optional mode. Otherwise stripping the
    proof header would downgrade a sender-constrained token to a bearer token.
    """
    provider = new_dpop_provider()
    token = live.mint(ro_client, READ_SCOPE, dpop_provider=provider)

    async with verifier(dpop="optional") as v:
        with pytest.raises(AuthenticationError):
            await v.verify(token, RequestContext(method="POST", url=MESSAGES_URL, proof=""))


async def test_optional_mode_still_accepts_a_plain_bearer_token(live, ro_client):
    """The reason `optional` is the safe way to adopt DPoP: nothing else breaks."""
    token = live.mint(ro_client, READ_SCOPE)
    async with verifier(dpop="optional") as v:
        identity = await v.verify(
            token, RequestContext(method="POST", url=MESSAGES_URL, proof="")
        )
    assert identity.scopes == frozenset({READ_SCOPE})


async def test_required_mode_refuses_an_unbound_token(live, ro_client):
    token = live.mint(ro_client, READ_SCOPE)
    assert "cnf" not in claims_of(token)

    async with verifier(dpop="required") as v:
        with pytest.raises(AuthenticationError):
            await v.verify(token, RequestContext(method="POST", url=MESSAGES_URL, proof=""))


# --------------------------------------------------------------------------
# Revocation, against the real introspection endpoint.
# --------------------------------------------------------------------------


async def test_a_live_token_passes_the_revocation_check(live, ro_client):
    """Introspection is an authenticated call; wrong credentials would fail everything."""
    client_id, secret = ro_client
    token = live.mint(ro_client, READ_SCOPE)

    async with verifier(
        revocation_check=True, client_id=client_id, client_secret=secret
    ) as v:
        identity = await v.verify(token)

    assert identity.subject


async def test_a_revoked_token_is_refused_immediately(live, ro_client):
    """The behaviour that revocation checking exists to provide.

    With it off, this token would stay valid here for its full hour, because
    local validation cannot know the authorization server has withdrawn it.
    """
    client_id, secret = ro_client
    token = live.mint(ro_client, READ_SCOPE)

    async with verifier(
        revocation_check=True, client_id=client_id, client_secret=secret
    ) as v:
        await v.verify(token)

        live.revoke(claims_of(token)["jti"])

        with pytest.raises(AuthenticationError):
            await v.verify(token)


async def test_a_revoked_token_still_passes_when_checking_is_off(live, ro_client):
    """Documents the default's real cost, so it cannot be mistaken for an oversight.

    Without introspection a revoked token remains usable here until it expires.
    That is the trade-off for local validation, and it is why the setting exists.
    """
    token = live.mint(ro_client, READ_SCOPE)
    live.revoke(claims_of(token)["jti"])

    async with verifier() as v:
        identity = await v.verify(token)

    assert identity.subject, "local validation cannot see an upstream revocation"


async def test_revocation_checking_fails_closed_when_introspection_is_unreachable(
    live, ro_client
):
    """Our deliberate override of the SDK's fail-*open* default.

    ``IntrospectionRevocation`` is documented as fail-open, so an unanswerable
    check would admit the token. For a server that executes SQL that is the wrong
    default, and ``fail_closed=True`` reverses it. Nothing else guards that line:
    if it were dropped, every other revocation test here would still pass.
    """
    client_id, secret = ro_client
    token = live.mint(ro_client, READ_SCOPE)

    async with verifier(
        revocation_check=True, client_id=client_id, client_secret="wrong-secret"
    ) as v:
        with pytest.raises((AuthenticationError, AuthorizationError)):
            await v.verify(token)


# --------------------------------------------------------------------------
# The metadata document a client discovers us through.
# --------------------------------------------------------------------------


async def test_the_metadata_document_describes_this_resource():
    async with verifier() as v:
        document = v.protected_resource_metadata()
        url = v.metadata_url()

    assert document["resource"] == RESOURCE, "must match the token 'aud' byte-for-byte"
    assert document["authorization_servers"], "a client cannot find the AS without this"
    assert document["bearer_methods_supported"] == ["header"], (
        "advertising query-string tokens would invite them into proxy logs"
    )
    assert set(document["scopes_supported"]) == {READ_SCOPE, WRITE_SCOPE}
    assert url.endswith("/.well-known/oauth-protected-resource")


async def test_the_metadata_document_advertises_dpop_only_when_it_is_enabled():
    """Verifies the claim the code makes about ``InboundDPoPOptions``.

    ``authplane.py`` states that passing the options object at all is what makes
    the document advertise DPoP -- which is how a client discovers it can send
    sender-constrained tokens. Until now nothing checked that.
    """
    async with verifier(dpop="off") as v:
        assert "dpop_signing_alg_values_supported" not in v.protected_resource_metadata()

    async with verifier(dpop="optional") as v:
        document = v.protected_resource_metadata()
    assert document["dpop_signing_alg_values_supported"], "clients discover DPoP support here"
    assert document["dpop_bound_access_tokens_required"] is False

    async with verifier(dpop="required") as v:
        assert v.protected_resource_metadata()["dpop_bound_access_tokens_required"] is True


# --------------------------------------------------------------------------
# Signing key rotation.
# --------------------------------------------------------------------------


async def test_rotating_the_signing_key_causes_no_outage(live, rw_client):
    """Rotation must not need a restart, a cache expiry, or a maintenance window.

    Three properties in one test because they are one event: tokens signed with
    the retired key keep working, a token signed with the brand-new key is
    accepted by a verifier that primed its cache *before* the rotation, and
    neither requires waiting. The SDK refetches JWKS when it meets an unknown
    `kid`; this asserts that actually happens against a real rotation.
    """
    async with verifier() as v:
        before = live.mint(rw_client, f"{READ_SCOPE} {WRITE_SCOPE}")
        await v.verify(before)
        old_kid = header_of(before)["kid"]

        new_kid = live.rotate_keys()
        assert new_kid != old_kid, "rotation should produce a different key"

        after = live.mint(rw_client, f"{READ_SCOPE} {WRITE_SCOPE}")
        assert header_of(after)["kid"] == new_kid

        identity = await v.verify(after)
        assert identity.subject, "a token with the new kid is accepted with no restart"

        still_valid = await v.verify(before)
        assert still_valid.subject, "tokens signed by the retired key keep working"
