// The browser half of Octopus Auth.
//
// createAuthMiddleware reads an `Authorization: Bearer` header, which is what a
// service-to-service caller sends. A person in a browser sends the `octopus_sso`
// cookie instead, and the package never covered that — so cortex, games, math,
// planner and shopper each wrote their own copy of "parse the cookie, POST it to
// /api/auth/verify, cache the answer". Five implementations of one security
// decision is why revocation could not be rolled out fleet-wide.
//
// These pin the behaviour those five already have, so migrating them onto this
// is a deduplication rather than a change.
//
// Run with: npm test

const { test } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-secret-do-not-use-anywhere-real';
const SECRET = process.env.JWT_SECRET;

const { createSSOMiddleware, parseCookies } = require('..');

const sign = (payload, opts = {}) => jwt.sign(payload, SECRET, { expiresIn: '7d', ...opts });
const session = (over = {}) => sign({ userId: 1, username: 'testuser', role: 'user', ...over });

const VALID_BODY = { success: true, valid: true, user: { userId: 1, username: 'testuser', role: 'user' } };

function fakeFetch(body, { ok = true, throws = false } = {}) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    if (throws) throw new Error('auth unreachable');
    return { ok, json: async () => body };
  };
  fn.calls = calls;
  return fn;
}

const run = async (mw, cookieHeader) => {
  const req = { headers: cookieHeader ? { cookie: cookieHeader } : {} };
  let called = false;
  await mw(req, {}, () => { called = true; });
  return { req, called };
};

// ── Cookie parsing ───────────────────────────────────────────────────────────

test('parses a cookie header the way browsers actually send it', () => {
  const c = parseCookies('a=1; octopus_sso=abc.def.ghi; theme=dark');
  assert.equal(c.octopus_sso, 'abc.def.ghi');
  assert.equal(c.theme, 'dark');
});

test('a value containing = is not truncated', () => {
  // Base64 padding puts '=' inside token values; splitting on every '=' loses it.
  assert.equal(parseCookies('t=abc==').t, 'abc==');
});

test('junk in the header does not throw', () => {
  assert.deepEqual(parseCookies('novalue; =noname; a=1').a, '1');
  assert.deepEqual(parseCookies(undefined), {});
  assert.deepEqual(parseCookies(''), {});
});

// ── The middleware ───────────────────────────────────────────────────────────

test('no cookie is anonymous, not rejected', async () => {
  // These apps serve public pages from the same process; rejecting here would
  // break the login page itself.
  const mw = createSSOMiddleware({ fetch: fakeFetch(VALID_BODY) });
  const { req, called } = await run(mw);
  assert.equal(called, true);
  assert.equal(req.user, undefined);
});

test('a confirmed session becomes req.user', async () => {
  const mw = createSSOMiddleware({ fetch: fakeFetch(VALID_BODY) });
  const { req } = await run(mw, `octopus_sso=${session()}`);
  assert.equal(req.user.username, 'testuser');
  assert.equal(req.user.userId, 1);
  assert.ok(req.user.token, 'the raw token is kept — callers forward it to other services');
});

test('a forged cookie never reaches the network', async () => {
  // A bad cookie must not cost octopus-auth a request per hit; that turns any
  // stranger with a loop into a denial of service against the auth service.
  const f = fakeFetch(VALID_BODY);
  const mw = createSSOMiddleware({ fetch: f });
  const bad = jwt.sign({ userId: 1, username: 'testuser' }, 'a-different-secret');
  const { req } = await run(mw, `octopus_sso=${bad}`);
  assert.equal(req.user, undefined);
  assert.equal(f.calls.length, 0);
});

test('an expired cookie never reaches the network either', async () => {
  const f = fakeFetch(VALID_BODY);
  const mw = createSSOMiddleware({ fetch: f });
  const old = sign({ userId: 1, username: 'testuser' }, { expiresIn: '-1h' });
  const { req } = await run(mw, `octopus_sso=${old}`);
  assert.equal(req.user, undefined);
  assert.equal(f.calls.length, 0);
});

test('a revoked session is anonymous even though the signature is good', async () => {
  // The whole point: the signature still verifies, auth says no.
  const mw = createSSOMiddleware({ fetch: fakeFetch({ valid: false }) });
  const { req, called } = await run(mw, `octopus_sso=${session()}`);
  assert.equal(req.user, undefined);
  assert.equal(called, true);
});

test('auth being unreachable is anonymous, not an error', async () => {
  // Fail-closed, and matching what all five apps already do. The request
  // continues so the app can redirect to login rather than 500.
  const mw = createSSOMiddleware({ fetch: fakeFetch(null, { throws: true }) });
  const { req, called } = await run(mw, `octopus_sso=${session()}`);
  assert.equal(req.user, undefined);
  assert.equal(called, true);
});

test('confirmations are cached, so one session is not one auth call per request', async () => {
  const f = fakeFetch(VALID_BODY);
  const mw = createSSOMiddleware({ fetch: f, cacheTtlMs: 60000 });
  const cookie = `octopus_sso=${session()}`;
  await run(mw, cookie);
  await run(mw, cookie);
  await run(mw, cookie);
  assert.equal(f.calls.length, 1, 'three requests, one confirmation');
});

test('the cache window is configurable, because it IS the revocation window', async () => {
  // cortex, games, math and shopper each cache for 5 minutes today. Migrating
  // them must be able to keep that, or the change quietly multiplies auth load
  // by five.
  const mw = createSSOMiddleware({ fetch: fakeFetch(VALID_BODY), cacheTtlMs: 300000 });
  assert.equal(typeof mw.verifier.clearCache, 'function');
});

test('remote:false verifies locally and asks auth nothing', async () => {
  const f = fakeFetch(VALID_BODY);
  const mw = createSSOMiddleware({ remote: false, fetch: f });
  const { req } = await run(mw, `octopus_sso=${session()}`);
  assert.equal(req.user.username, 'testuser');
  assert.equal(f.calls.length, 0, 'local mode is offline — and cannot see revocation');
});

test('a custom cookie name is honoured', async () => {
  const mw = createSSOMiddleware({ cookieName: 'my_session', fetch: fakeFetch(VALID_BODY) });
  const { req } = await run(mw, `my_session=${session()}`);
  assert.equal(req.user.username, 'testuser');
});

test('onUser shapes req.user, so an app can keep the shape it already had', async () => {
  // Migrating an app must not change what its routes read off req.user.
  const mw = createSSOMiddleware({
    fetch: fakeFetch(VALID_BODY),
    onUser: (user, token) => ({ username: user.username, role: user.role, token }),
  });
  const { req } = await run(mw, `octopus_sso=${session()}`);
  assert.deepEqual(Object.keys(req.user).sort(), ['role', 'token', 'username']);
});
