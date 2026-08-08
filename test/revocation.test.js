// Revocation contract.
//
// A signature check cannot see a revoked session — octopus-auth invalidates
// tokens by bumping a per-user epoch, and only octopus-auth knows the current
// one. These are the rules for the remote-verification mode that closes that
// gap, and the reasons each one is the way it is.
//
// Run with: npm test

const { test } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-secret-do-not-use-anywhere-real';
const SECRET = process.env.JWT_SECRET;

const { createAuthMiddleware, createRemoteVerifier, remoteVerifyEnabled } = require('..');

const sign = (payload, opts = {}) => jwt.sign(payload, SECRET, { expiresIn: '7d', ...opts });
const session = (over = {}) => sign({ userId: 1, username: 'testuser', role: 'user', epoch: 1, ...over });

const VALID_BODY = { success: true, valid: true, user: { userId: 1, username: 'testuser', role: 'user' } };
const REVOKED_BODY = { success: false, valid: false, error: 'Session has been revoked' };

// A fetch double that records calls and replays queued responses.
function fakeFetch(responses) {
  const calls = [];
  const queue = Array.isArray(responses) ? [...responses] : null;
  const fn = async (url, init) => {
    calls.push({ url, init });
    const next = queue ? (queue.length > 1 ? queue.shift() : queue[0]) : responses;
    if (typeof next === 'function') return next();
    if (next instanceof Error) throw next;
    return { ok: next.ok ?? true, json: async () => next.body };
  };
  fn.calls = calls;
  return fn;
}

function fakeRes() {
  return {
    statusCode: null, body: null,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
  };
}
async function run(mw, req) {
  const res = fakeRes();
  let nexted = false;
  await mw(req, res, () => { nexted = true; });
  return { res, nexted };
}
const bearer = t => ({ headers: { authorization: `Bearer ${t}` } });

// ── createRemoteVerifier ─────────────────────────────────────────────────────

test('returns the user when auth confirms the session', async () => {
  const verify = createRemoteVerifier({ fetch: fakeFetch({ body: VALID_BODY }) });
  assert.deepStrictEqual(await verify('tok'), VALID_BODY.user);
});

test('returns null when auth says the session was revoked', async () => {
  const verify = createRemoteVerifier({ fetch: fakeFetch({ ok: false, body: REVOKED_BODY }) });
  assert.strictEqual(await verify('tok'), null);
});

test('calls auth at /api/auth/verify with the token as a bearer header', async () => {
  const f = fakeFetch({ body: VALID_BODY });
  const verify = createRemoteVerifier({ fetch: f, baseUrl: 'http://auth:3002/' });
  await verify('tok123');
  assert.strictEqual(f.calls[0].url, 'http://auth:3002/api/auth/verify');
  assert.strictEqual(f.calls[0].init.headers.Authorization, 'Bearer tok123');
});

test('caches a confirmation instead of asking again', async () => {
  const f = fakeFetch({ body: VALID_BODY });
  const verify = createRemoteVerifier({ fetch: f });
  await verify('tok'); await verify('tok'); await verify('tok');
  assert.strictEqual(f.calls.length, 1, 'should have hit auth exactly once');
});

// The cache TTL is the revocation window. Once it lapses the answer must be
// re-fetched, or a revocation would never land at all.
test('re-asks auth once the cache TTL has lapsed', async () => {
  let clock = 1000;
  const f = fakeFetch([{ body: VALID_BODY }, { ok: false, body: REVOKED_BODY }]);
  const verify = createRemoteVerifier({ fetch: f, cacheTtlMs: 60000, now: () => clock });

  assert.deepStrictEqual(await verify('tok'), VALID_BODY.user);
  clock += 59999;
  assert.deepStrictEqual(await verify('tok'), VALID_BODY.user, 'still inside the window');
  assert.strictEqual(f.calls.length, 1);

  clock += 2;
  assert.strictEqual(await verify('tok'), null, 'revocation must land once the window passes');
  assert.strictEqual(f.calls.length, 2);
});

// Without this, a client looping on a revoked token turns revocation into a load
// generator against auth.
test('caches the negative answer too', async () => {
  const f = fakeFetch({ ok: false, body: REVOKED_BODY });
  const verify = createRemoteVerifier({ fetch: f });
  await verify('tok'); await verify('tok');
  assert.strictEqual(f.calls.length, 1);
});

test('fails closed when auth is unreachable', async () => {
  const verify = createRemoteVerifier({ fetch: fakeFetch(new Error('ECONNREFUSED')) });
  assert.strictEqual(await verify('tok'), null);
});

// An outage is not a revocation. Caching it would extend a blip into a full TTL
// of rejections after auth is already back.
test('does not cache an outage', async () => {
  const f = fakeFetch([new Error('ECONNREFUSED'), { body: VALID_BODY }]);
  const verify = createRemoteVerifier({ fetch: f });
  assert.strictEqual(await verify('tok'), null);
  assert.deepStrictEqual(await verify('tok'), VALID_BODY.user, 'should recover on the next request');
  assert.strictEqual(f.calls.length, 2);
});

test('fails closed on a malformed response', async () => {
  const verify = createRemoteVerifier({ fetch: fakeFetch({ body: { success: true } }) });
  assert.strictEqual(await verify('tok'), null);
});

test('evicts oldest-first at the cache cap', async () => {
  const verify = createRemoteVerifier({ fetch: fakeFetch({ body: VALID_BODY }), maxCacheEntries: 3 });
  for (const t of ['a', 'b', 'c', 'd', 'e']) await verify(t);
  assert.ok(verify.cacheSize() <= 3, `cache grew to ${verify.cacheSize()}`);
});

// ── middleware in remote mode ────────────────────────────────────────────────

test('remote middleware passes a confirmed session through', async () => {
  const mw = createAuthMiddleware({ remote: true, fetch: fakeFetch({ body: VALID_BODY }) });
  const req = bearer(session());
  const { nexted } = await run(mw, req);
  assert.ok(nexted);
  assert.strictEqual(req.user.username, 'testuser');
});

test('remote middleware 401s a revoked session that still has a valid signature', async () => {
  const mw = createAuthMiddleware({ remote: true, fetch: fakeFetch({ ok: false, body: REVOKED_BODY }) });
  const { res, nexted } = await run(mw, bearer(session({ epoch: 1 })));
  assert.ok(!nexted, 'a revoked session must not reach the route');
  assert.strictEqual(res.statusCode, 401);
  assert.match(res.body.error, /revoked/i);
});

// The whole point: local mode cannot tell these two apart, remote mode can.
test('local middleware accepts the same revoked token remote mode rejects', async () => {
  const token = session({ epoch: 1 });
  const local = createAuthMiddleware();
  const req = bearer(token);
  const { nexted } = await run(local, req);
  assert.ok(nexted, 'local verification is expected to be blind to revocation');
  assert.strictEqual(req.user.username, 'testuser');
});

// Signature failures must not cost a network call — auth should never see a
// forged or expired token at all.
test('remote middleware rejects a bad signature without calling auth', async () => {
  const f = fakeFetch({ body: VALID_BODY });
  const mw = createAuthMiddleware({ remote: true, fetch: f });
  const { res } = await run(mw, bearer(jwt.sign({ username: 'x' }, 'wrong-secret')));
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(f.calls.length, 0, 'auth should not have been called');
});

test('remote middleware rejects an expired token without calling auth', async () => {
  const f = fakeFetch({ body: VALID_BODY });
  const mw = createAuthMiddleware({ remote: true, fetch: f });
  const { res } = await run(mw, bearer(sign({ username: 'x' }, { expiresIn: '-1s' })));
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(f.calls.length, 0);
});

test('remote middleware still rejects a purpose token', async () => {
  const f = fakeFetch({ body: VALID_BODY });
  const mw = createAuthMiddleware({ remote: true, fetch: f });
  const { res } = await run(mw, bearer(sign({ userId: 1, username: 'n', purpose: 'totp-enroll' })));
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(f.calls.length, 0, 'a challenge token should never reach auth');
});

test('remote middleware 401s when auth is unreachable', async () => {
  const mw = createAuthMiddleware({ remote: true, fetch: fakeFetch(new Error('down')) });
  const { res, nexted } = await run(mw, bearer(session()));
  assert.ok(!nexted);
  assert.strictEqual(res.statusCode, 401);
});

test('remote optional mode allows anonymous but not an unconfirmed session', async () => {
  const mw = createAuthMiddleware({ remote: true, optional: true, fetch: fakeFetch({ ok: false, body: REVOKED_BODY }) });

  const anon = { headers: {} };
  assert.ok((await run(mw, anon)).nexted, 'anonymous should pass');
  assert.strictEqual(anon.user, null);

  const { res, nexted } = await run(mw, bearer(session()));
  assert.ok(!nexted, 'optional must not upgrade a revoked session to a valid one');
  assert.strictEqual(res.statusCode, 401);
});

test('remote middleware takes role from auth, not from the token', async () => {
  // Token says admin; auth says the account has since been demoted.
  const mw = createAuthMiddleware({ remote: true, fetch: fakeFetch({ body: VALID_BODY }) });
  const req = bearer(session({ role: 'admin' }));
  await run(mw, req);
  assert.strictEqual(req.user.role, 'user', 'a stale role claim must not survive');
});

// ── opt-in switch ────────────────────────────────────────────────────────────

test('remote mode is off unless AUTH_REMOTE_VERIFY says otherwise', () => {
  const saved = process.env.AUTH_REMOTE_VERIFY;
  try {
    delete process.env.AUTH_REMOTE_VERIFY;
    assert.strictEqual(remoteVerifyEnabled(), false);
    assert.strictEqual(createAuthMiddleware().remote, false);

    for (const v of ['1', 'true', 'TRUE', 'yes']) {
      process.env.AUTH_REMOTE_VERIFY = v;
      assert.strictEqual(remoteVerifyEnabled(), true, `${v} should enable it`);
    }
    for (const v of ['0', 'false', '', 'no']) {
      process.env.AUTH_REMOTE_VERIFY = v;
      assert.strictEqual(remoteVerifyEnabled(), false, `${v} should not enable it`);
    }
  } finally {
    if (saved === undefined) delete process.env.AUTH_REMOTE_VERIFY;
    else process.env.AUTH_REMOTE_VERIFY = saved;
  }
});

test('an explicit remote option beats the env var', () => {
  const saved = process.env.AUTH_REMOTE_VERIFY;
  try {
    process.env.AUTH_REMOTE_VERIFY = '1';
    assert.strictEqual(createAuthMiddleware({ remote: false }).remote, false);
  } finally {
    if (saved === undefined) delete process.env.AUTH_REMOTE_VERIFY;
    else process.env.AUTH_REMOTE_VERIFY = saved;
  }
});
