# Running the tests

```bash
python -m pytest -q -W ignore
```

`-W ignore` silences an `AuthlibDeprecationWarning` raised inside a dependency.

Tests that need an external service skip themselves when it is not configured,
so a bare run is always green. That also means a green run does not tell you
which layers ran — check the skip count, or select a layer explicitly:

```bash
python -m pytest -q -W ignore -m "not live_auth"   # no authorization server
python -m pytest -q -W ignore -m live_auth         # only those that need one
python -m pytest tests/test_auth_middleware.py -v  # one file, named cases
```

Markers: `live_auth` needs an Authplane server, `e2e` starts the real server as a
subprocess and drives it over HTTP.

## MySQL

```bash
docker run -d --name mcp-mysql -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=rootpw -e MYSQL_DATABASE=testdb \
  -e MYSQL_USER=mcp -e MYSQL_PASSWORD=mcppw mysql:8
```

The read/write separation tests also need a `SELECT`-only account, because they
send statements straight to MySQL over the read-only connection and assert the
database itself refuses them:

```bash
docker exec mcp-mysql mysql -uroot -prootpw -e "
CREATE USER IF NOT EXISTS 'mcp_ro'@'%' IDENTIFIED BY 'ropw';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'mcp_ro'@'%';
GRANT SELECT ON testdb.* TO 'mcp_ro'@'%';
FLUSH PRIVILEGES;"
```

```bash
MYSQL_HOST=127.0.0.1 MYSQL_PORT=3306 \
MYSQL_USER=mcp MYSQL_PASSWORD=mcppw MYSQL_DATABASE=testdb \
MYSQL_RO_USER=mcp_ro MYSQL_RO_PASSWORD=ropw \
  python -m pytest -q -W ignore
```

## Authplane

`test_authplane_live.py` and `test_authplane_e2e.py` mint real tokens and sign
real DPoP proofs against a running authorization server.

Both grants must be enabled explicitly. Authplane turns every grant off by
default and discovery silently omits one that is not enabled, so without
`CLIENT_CREDENTIALS_ENABLED` token minting fails with `unsupported_grant_type`.

```bash
docker run -d --name authplane-as -p 9000:9000 -p 9101:9001 \
  -e AUTHPLANE_SERVER_ISSUER=http://localhost:9000 \
  -e AUTHPLANE_ADMIN_API_KEY=dev-admin-key \
  -e AUTHPLANE_SESSION_SECRET=dev-session-secret \
  -e AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true \
  -e AUTHPLANE_DPOP_ENABLED=true \
  authplane/authserver:latest serve
```

The admin API is published on 9101 rather than 9001 because Windows reserves
9001. On Linux either works.

```bash
AUTHPLANE_TEST_ISSUER=http://localhost:9000 \
AUTHPLANE_TEST_ADMIN_URL=http://localhost:9101 \
AUTHPLANE_TEST_ADMIN_KEY=dev-admin-key \
  python -m pytest -q -W ignore -m live_auth
```

Resources and clients are provisioned by the tests through the admin API and
deleted on teardown. Two resources are used: the server under test, and a decoy
that exists so a token minted for the wrong audience can be tested against a real
one.

`AUTHPLANE_TEST_RESOURCE` defaults to `http://localhost:8000`. The end-to-end
servers derive their ports from it, because it is also the `aud` the tokens
carry.
