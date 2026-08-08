# @octopus-security/auth-client

Shared JWT auth client and Express middleware for Octopus services.

## Install

Add to `.npmrc` in the consuming repo:

```
@octopus-security:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

Then:

```bash
npm install @octopus-security/auth-client
```

`GITHUB_TOKEN` needs `read:packages` on the `Octopus-Security` org.

## Usage

### Protect an Express route

```js
const { createAuthMiddleware, requireRole } = require('@octopus-security/auth-client');

const authenticate = createAuthMiddleware();
const authenticateOptional = createAuthMiddleware({ optional: true });

app.get('/protected', authenticate, (req, res) => {
  // req.user = { userId, username, role }
  res.json({ user: req.user });
});

app.get('/admin-only', authenticate, requireRole('admin'), (req, res) => {
  res.json({ ok: true });
});
```

### Honour session revocation

`createAuthMiddleware()` verifies the signature locally. That is fast and needs no
network, but it **cannot see a revoked session** — `octopus-auth` invalidates
tokens by bumping a per-user epoch, and only `octopus-auth` knows the current one.
A password reset, an admin cutting off an account, or someone pressing "sign out
everywhere" changes neither the signature nor the expiry, so a local check keeps
letting a dead session through for up to the full 7 days.

Turn on remote mode to close that:

```js
const authenticate = createAuthMiddleware({ remote: true, cacheTtlMs: 60_000 });
```

or, without touching code, set `AUTH_REMOTE_VERIFY=1` in the service's stack env.

Each token is confirmed against `/api/auth/verify` and the answer cached, so
**`cacheTtlMs` is this service's revocation window**. Signature and expiry are
still checked locally first, so a forged or expired token never costs a call.

Two behaviours to know about:

- **It fails closed.** If `octopus-auth` is unreachable, requests are rejected. A
  revocation check that opens the gate when it cannot reach the authority is not a
  revocation check. This makes auth a hard dependency for these routes — the same
  bargain every service already makes with the SSO cookie.
- **`role` comes from auth, not the token.** A demotion lands within one TTL
  instead of surviving until the token expires.

Services that authenticate the shared `octopus_sso` cookie by calling
`/api/auth/verify` already get revocation for free (with their own cache TTL as
the window) and need no change. Remote mode is for `Authorization: Bearer` routes.

### Verify a token directly

```js
const { verifyToken } = require('@octopus-security/auth-client');

try {
  const user = verifyToken(token); // { userId, username, role }
} catch (e) {
  // invalid or expired
}
```

### Sign a token (octopus-auth only)

```js
const { signToken } = require('@octopus-security/auth-client');

const token = signToken({ userId, username, role }, { expiresIn: '7d' });
```

### HTTP client for server-side auth calls

```js
const { AuthClient } = require('@octopus-security/auth-client');

const auth = new AuthClient(); // defaults to http://octopus-auth:3002
// or: new AuthClient(process.env.AUTH_SERVICE_URL)

const { ok, data } = await auth.login(username, password);
const { ok, data } = await auth.register(username, password, email, inviteCode);
const { ok, data } = await auth.verify(token);
const { ok, data } = await auth.refresh(token);
```

## Environment variables

| Variable | Required | Default |
|---|---|---|
| `JWT_SECRET` | Yes | — |
| `AUTH_SERVICE_URL` | No | `http://octopus-auth:3002` |
| `AUTH_REMOTE_VERIFY` | No | unset (local verification only) |

## req.user shape

After `createAuthMiddleware()` runs successfully, `req.user` is always:

```js
{ userId, username, role }  // role defaults to 'user' if absent in token
```

## The auth contract

Every Octopus service trusts tokens signed with the same shared `JWT_SECRET`.
That has one consequence worth internalising before you write auth anywhere:

> **A valid signature does not mean the caller is logged in.**

`octopus-auth` issues short-lived *purpose* tokens part-way through login, signed
with that same secret:

| `purpose` | Issued when | Means |
|---|---|---|
| `totp-challenge` | Password accepted, 2FA code not yet given | **Not** authenticated |
| `totp-enroll` | 2FA-less account being forced to enrol | **Not** authenticated |

A session token carries **no `purpose` claim**. `verifyToken()` therefore rejects
any token that has one — otherwise a caller holding only a stolen password could
present a challenge token and be let through, defeating `REQUIRE_2FA`, which
exists precisely to survive a stolen password.

And one more, which is why remote mode exists:

> **A valid signature does not mean the session still exists.**

Sessions carry an `epoch` claim matching `User.tokenEpoch` in `octopus-auth`.
Bumping that column orphans every token already issued to the user — there is no
token store and no denylist. Only `/api/auth/verify` and `/api/auth/refresh` can
see it, so any service checking tokens purely locally is blind to revocation by
construction.

If you are writing auth for a service that does *not* use this package, it must
apply both rules. `test/contract.test.js` and `test/revocation.test.js` are the
executable definition — 43 cases covering purpose tokens, expiry, wrong secrets,
`alg: none`, missing secrets, role handling, cache windows, and fail-closed
behaviour.

```bash
npm test
```

CI runs it on every push, and `npm publish` is gated on it.
