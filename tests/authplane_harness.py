"""Shared plumbing for tests that run against a *real* Authplane server.

Deliberately not named ``test_*``: pytest must not collect it.

Everything else in the suite verifies our own middleware against fake verifiers
that satisfy the ``TokenVerifier`` protocol. That proves our code, not our use of
the SDK -- a fake raises on cue, so it cannot catch a claim we read by the wrong
name or an SDK default we assumed wrongly. The tests built on this harness mint
genuine tokens, sign genuine DPoP proofs, and push them through
``AuthplaneVerifier``.

Configure with:

    AUTHPLANE_TEST_ISSUER      public OAuth surface, e.g. http://localhost:9000
    AUTHPLANE_TEST_ADMIN_URL   admin API,             e.g. http://localhost:9101
    AUTHPLANE_TEST_ADMIN_KEY   AUTHPLANE_ADMIN_API_KEY of that server
    AUTHPLANE_TEST_RESOURCE          optional, default http://localhost:8000
    AUTHPLANE_TEST_DECOY_RESOURCE    optional, default http://localhost:9999

Everything skips when those are unset, so `pytest` stays green without a server.
See tests/README.md for the one `docker run` that provides them.

The authorization server must have ``AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true``
and ``AUTHPLANE_DPOP_ENABLED=true``. Every grant is off by default in Authplane
and discovery silently omits a grant that is not enabled, so without the first
one token minting fails with ``unsupported_grant_type``.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import uuid
from typing import Any

import pytest

_HAS_SDK = importlib.util.find_spec("authplane") is not None
_HAS_HTTPX = importlib.util.find_spec("httpx") is not None

ISSUER = os.getenv("AUTHPLANE_TEST_ISSUER", "").strip().rstrip("/")
ADMIN_URL = os.getenv("AUTHPLANE_TEST_ADMIN_URL", "").strip().rstrip("/")
ADMIN_KEY = os.getenv("AUTHPLANE_TEST_ADMIN_KEY", "").strip()
#: Base URL, with no trailing slash, for *building request URLs*
#: (``f"{RESOURCE}/messages/"``). Distinct from the identifier below.
RESOURCE = os.getenv("AUTHPLANE_TEST_RESOURCE", "http://localhost:8000").strip().rstrip("/")
DECOY_RESOURCE = os.getenv("AUTHPLANE_TEST_DECOY_RESOURCE", "http://localhost:9999").strip().rstrip("/")

#: The same resources as *identifiers*: what is registered at the authorization
#: server, sent as ``resource=``, carried in ``aud``, and published in the PRM
#: document. For a root resource this is the base URL plus the ``/`` that RFC
#: 3986 makes part of its canonical form, so the two differ by exactly that
#: character and must not be used interchangeably.
#:
#: Imported from the production helper rather than recomputed here: these values
#: have to agree with what the running server derives, and a second
#: implementation is a second thing to keep in sync.
from mysql_mcp_server.auth.settings import canonical_resource  # noqa: E402

RESOURCE_AUD = canonical_resource(RESOURCE)
DECOY_RESOURCE_AUD = canonical_resource(DECOY_RESOURCE)

READ_SCOPE = "mysql:read"
WRITE_SCOPE = "mysql:write"
DECOY_SCOPE = "decoy:all"

_CONFIGURED = bool(ISSUER and ADMIN_URL and ADMIN_KEY and _HAS_SDK and _HAS_HTTPX)

requires_live_authplane = pytest.mark.skipif(
    not _CONFIGURED,
    reason=(
        "needs a live Authplane: set AUTHPLANE_TEST_ISSUER, AUTHPLANE_TEST_ADMIN_URL and "
        "AUTHPLANE_TEST_ADMIN_KEY, and install the [auth] extra. See tests/README.md."
    ),
)


def decode_segment(token: str, index: int) -> dict:
    """Decode a JWT header (0) or payload (1) without verifying anything.

    Tests need to read `kid`, `jti` and `cnf` off a token to drive the
    authorization server's admin API. Verification is what the code under test
    does; this is only for reading.
    """
    segment = token.split(".")[index]
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def claims_of(token: str) -> dict:
    return decode_segment(token, 1)


def header_of(token: str) -> dict:
    return decode_segment(token, 0)


class LiveAuthplane:
    """Thin wrapper over the authorization server's admin and token endpoints.

    Clients are created per session with a random suffix and deleted on
    teardown, so repeated runs do not leave a trail behind in the server.
    """

    def __init__(self) -> None:
        import httpx

        self._httpx = httpx
        self._admin_headers = {"Authorization": f"Bearer {ADMIN_KEY}"}
        self._run_id = uuid.uuid4().hex[:8]
        self._created_clients: list[str] = []

    # -- provisioning --------------------------------------------------

    def ensure_resource(self, slug: str, uri: str, scopes: tuple[str, ...]) -> None:
        """Register a resource, tolerating one that already exists.

        The resource URI is the contract: it must match byte-for-byte here, in
        the PRM document this server serves, and in the `resource=` parameter at
        the token endpoint. Authplane's own docs call a mismatch the
        second-most-common misconfiguration, so it comes from one constant.
        """
        existing = self._httpx.get(
            f"{ADMIN_URL}/admin/resources", headers=self._admin_headers, timeout=20
        )
        existing.raise_for_status()
        for resource in existing.json():
            if resource.get("uri", "") == uri:
                return
            if resource.get("uri", "").rstrip("/") == uri.rstrip("/"):
                # Same resource, registered under the other trailing-slash form.
                # Compared exactly above and repaired here rather than tolerated:
                # the authorization server matches this string exactly, so a
                # registration that differs by the slash is not an equivalent
                # spelling, it is a resource that cannot be minted for. Left
                # alone, every token request fails with "unknown resource".
                patch = self._httpx.patch(
                    f"{ADMIN_URL}/admin/resources/{resource['id']}",
                    headers=self._admin_headers,
                    timeout=20,
                    json={"uri": uri},
                )
                if patch.status_code >= 300:
                    raise RuntimeError(
                        f"could not repair resource {slug} URI to {uri}: "
                        f"{patch.status_code} {patch.text}"
                    )
                return

        response = self._httpx.post(
            f"{ADMIN_URL}/admin/resources",
            headers=self._admin_headers,
            timeout=20,
            json={
                "slug": slug,
                "display_name": slug,
                "backend_kind": "mint",
                "uri": uri,
                "scopes": [{"name": s, "description": s} for s in scopes],
            },
        )
        if response.status_code >= 300:
            raise RuntimeError(f"could not create resource {slug}: {response.status_code} {response.text}")

    def new_client(self, name: str, scope: str) -> tuple[str, str]:
        """Create a client and return ``(client_id, client_secret)``.

        The secret is shown once and never stored in plaintext, so it has to be
        captured here at creation.
        """
        response = self._httpx.post(
            f"{ADMIN_URL}/admin/clients",
            headers=self._admin_headers,
            timeout=20,
            json={
                "client_name": f"{name}-{self._run_id}",
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_basic",
                "scope": scope,
            },
        )
        if response.status_code >= 300:
            raise RuntimeError(f"could not create client {name}: {response.status_code} {response.text}")
        body = response.json()
        client_id, secret = body["client_id"], body["client_secret"]
        self._created_clients.append(client_id)
        return client_id, secret

    # -- tokens --------------------------------------------------------

    def mint(
        self,
        credentials: tuple[str, str],
        scope: str,
        resource: str | None = None,
        dpop_provider: Any = None,
    ) -> str:
        """Mint an access token via ``client_credentials``.

        Passing ``dpop_provider`` sends a DPoP proof on the token request, which
        is what makes the authorization server bind the token to that key and
        emit a ``cnf.jkt`` claim.
        """
        url = f"{ISSUER}/oauth/token"
        form = {
            "grant_type": "client_credentials",
            "scope": scope,
            "resource": resource or RESOURCE_AUD,
        }

        def post(extra_headers: dict) -> Any:
            return self._httpx.post(
                url, auth=credentials, headers=extra_headers, timeout=20, data=form
            )

        if dpop_provider is None:
            response = post({})
            if response.status_code >= 300:
                raise RuntimeError(
                    f"token request failed: {response.status_code} {response.text}"
                )
            return response.json()["access_token"]

        # RFC 9449 lets the authorization server demand a server-chosen nonce at
        # any point, answering with `use_dpop_nonce` and supplying one in the
        # `DPoP-Nonce` header. Authplane sends that header on every response and
        # rotates it, so a proof built without the current one is refused --
        # intermittently, because it depends on where the rotation window falls.
        # A real client notes the nonce and retries, which is what this does.
        attempts = []
        for _ in range(3):
            response = post(dpop_provider.build_headers("POST", url))
            attempts.append(response.status_code)
            if response.status_code < 300:
                return response.json()["access_token"]
            nonce = response.headers.get("DPoP-Nonce", "")
            if not nonce:
                break
            dpop_provider.note_nonce(url, nonce)

        raise RuntimeError(
            f"DPoP token request failed after {len(attempts)} attempt(s) "
            f"{attempts}: {response.status_code} {response.text}"
        )

    def revoke(self, jti: str) -> None:
        response = self._httpx.delete(
            f"{ADMIN_URL}/admin/tokens/{jti}", headers=self._admin_headers, timeout=20
        )
        if response.status_code >= 300:
            raise RuntimeError(f"revoke failed: {response.status_code} {response.text}")

    def rotate_keys(self) -> str:
        """Rotate the signing key and return the new ``kid``."""
        response = self._httpx.post(
            f"{ADMIN_URL}/admin/keys/rotate", headers=self._admin_headers, timeout=20
        )
        response.raise_for_status()
        return response.json()["kid"]

    # -- teardown ------------------------------------------------------

    def cleanup(self) -> None:
        """Delete the clients this run created.

        ``force=true`` is required: these clients have minted tokens, and the
        admin API answers 409 ("client has active tokens") without it. Deleting
        with it revokes those tokens too, which is what we want -- they exist
        only for the run that is ending.
        """
        for client_id in self._created_clients:
            try:
                self._httpx.delete(
                    f"{ADMIN_URL}/admin/clients/{client_id}",
                    params={"force": "true"},
                    headers=self._admin_headers,
                    timeout=10,
                )
            except Exception:  # pragma: no cover - teardown is best effort
                pass
        self._created_clients.clear()


def new_dpop_provider(algorithm: str = "ES256"):
    """A client-side DPoP signer, built with the SDK's own helpers.

    Using `DPoPProvider` rather than hand-rolling a proof keeps the test honest:
    a proof is produced the way a real client using this SDK would produce one.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from authplane import DPoPKeyMaterial, DPoPProvider

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return DPoPProvider(key_material=DPoPKeyMaterial.from_pem(pem, algorithm=algorithm))


def settings_for(**overrides):
    """Build ``AuthSettings`` pointed at the live server.

    ``dev_mode=True`` only silences the http:// issuer warning; it does not relax
    any check these tests rely on.
    """
    from mysql_mcp_server.auth.settings import AuthSettings

    base = dict(
        enabled=True,
        mode="authplane",
        issuer=ISSUER,
        resource=RESOURCE_AUD,
        scopes=(READ_SCOPE, WRITE_SCOPE),
        read_scope=READ_SCOPE,
        write_scope=WRITE_SCOPE,
        allowed_algorithms=("ES256", "RS256"),
        clock_skew_seconds=30,
        dev_mode=True,
    )
    base.update(overrides)
    return AuthSettings(**base)
