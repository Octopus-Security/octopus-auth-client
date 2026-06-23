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
