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

If you are writing auth for a service that does *not* use this package, it must
apply the same rule. `test/contract.test.js` is the executable definition — 22
cases covering purpose tokens, expiry, wrong secrets, `alg: none`, missing
secrets, and role handling.

```bash
npm test
```

CI runs it on every push, and `npm publish` is gated on it.
