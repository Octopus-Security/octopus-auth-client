// The Octopus auth contract.
//
// Every service on the platform trusts tokens signed with one shared JWT_SECRET,
// so the rules about what counts as a valid session live here rather than being
// re-derived (and occasionally got wrong) in each service. If you are writing
// auth for a new service, these are the cases it has to satisfy.
//
// Run with: npm test

const { test } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-secret-do-not-use-anywhere-real';
const SECRET = process.env.JWT_SECRET;

const { verifyToken, signToken, createAuthMiddleware, requireRole } = require('..');

const sign = (payload, opts = {}) => jwt.sign(payload, SECRET, { expiresIn: '7d', ...opts });
const session = (over = {}) => sign({ userId: 1, username: 'testuser', role: 'user', ...over });

// Minimal Express doubles — enough to see which branch the middleware took.
function fakeRes() {
  return {
    statusCode: null, body: null,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
  };
}
function run(mw, req) {
  const res = fakeRes();
  let nexted = false;
  mw(req, res, () => { nexted = true; });
  return { res, nexted };
}
const bearer = t => ({ headers: { authorization: `Bearer ${t}` } });

// ── verifyToken ──────────────────────────────────────────────────────────────

test('accepts a session token and normalises the user', () => {
  const user = verifyToken(session());
  assert.deepStrictEqual(user, { userId: 1, username: 'testuser', role: 'user' });
});

test('defaults role to "user" when the token omits it', () => {
  assert.strictEqual(verifyToken(sign({ userId: 2, username: 'x' })).role, 'user');
});

test('accepts `id` as an alias for `userId`', () => {
  assert.strictEqual(verifyToken(sign({ id: 7, username: 'x' })).userId, 7);
});

// The security rule this whole file exists for. octopus-auth signs its
// mid-login tokens with the same secret, so signature validity alone proves
// nothing about whether 2FA was completed.
test('rejects a totp-challenge token (2FA not yet completed)', () => {
  assert.throws(
    () => verifyToken(sign({ userId: 1, username: 'testuser', purpose: 'totp-challenge' })),
    /Not a session token/,
  );
});

test('rejects a totp-enroll token (2FA enrolment not yet completed)', () => {
  assert.throws(
    () => verifyToken(sign({ userId: 1, username: 'testuser', purpose: 'totp-enroll' })),
    /Not a session token/,
  );
});

test('rejects any future purpose token, not just the two we know about', () => {
  assert.throws(() => verifyToken(sign({ username: 'x', purpose: 'password-reset' })), /Not a session token/);
});

test('rejects an expired token', () => {
  assert.throws(() => verifyToken(sign({ username: 'x' }, { expiresIn: '-1s' })), /jwt expired/);
});

test('rejects a token signed with a different secret', () => {
  assert.throws(() => verifyToken(jwt.sign({ username: 'x' }, 'some-other-secret')), /invalid signature/);
});

test('rejects an unsigned ("alg: none") token', () => {
  const unsigned = jwt.sign({ username: 'x' }, null, { algorithm: 'none' });
  assert.throws(() => verifyToken(unsigned));
});

test('refuses to run at all when JWT_SECRET is unset', () => {
  const saved = process.env.JWT_SECRET;
  delete process.env.JWT_SECRET;
  try {
    assert.throws(() => verifyToken(session()), /JWT_SECRET is not set/);
  } finally {
    process.env.JWT_SECRET = saved;
  }
});

test('signToken round-trips through verifyToken', () => {
  assert.strictEqual(verifyToken(signToken({ userId: 3, username: 'rt' })).username, 'rt');
});

// ── createAuthMiddleware ─────────────────────────────────────────────────────

test('middleware passes a valid session through and populates req.user', () => {
  const req = bearer(session());
  const { nexted } = run(createAuthMiddleware(), req);
  assert.ok(nexted);
  assert.strictEqual(req.user.username, 'testuser');
});

test('middleware 401s a purpose token', () => {
  const { res, nexted } = run(createAuthMiddleware(), bearer(sign({ username: 'n', purpose: 'totp-challenge' })));
  assert.ok(!nexted, 'a 2FA challenge token must not reach the route');
  assert.strictEqual(res.statusCode, 401);
});

test('middleware 401s when the header is missing', () => {
  const { res, nexted } = run(createAuthMiddleware(), { headers: {} });
  assert.ok(!nexted);
  assert.strictEqual(res.statusCode, 401);
});

test('middleware 401s a non-Bearer scheme', () => {
  const { res } = run(createAuthMiddleware(), { headers: { authorization: `Basic ${session()}` } });
  assert.strictEqual(res.statusCode, 401);
});

test('middleware 401s garbage', () => {
  const { res } = run(createAuthMiddleware(), bearer('not-a-jwt'));
  assert.strictEqual(res.statusCode, 401);
});

test('optional mode continues anonymously with no token', () => {
  const req = { headers: {} };
  const { nexted } = run(createAuthMiddleware({ optional: true }), req);
  assert.ok(nexted);
  assert.strictEqual(req.user, null);
});

// Optional means "anonymous is allowed", never "a bad token is allowed".
test('optional mode still 401s a purpose token', () => {
  const { res, nexted } = run(
    createAuthMiddleware({ optional: true }),
    bearer(sign({ username: 'n', purpose: 'totp-enroll' })),
  );
  assert.ok(!nexted);
  assert.strictEqual(res.statusCode, 401);
});

// ── requireRole ──────────────────────────────────────────────────────────────

test('requireRole allows a matching role', () => {
  assert.ok(run(requireRole('editor'), { user: { role: 'editor' } }).nexted);
});

test('requireRole always allows admin', () => {
  assert.ok(run(requireRole('editor'), { user: { role: 'admin' } }).nexted);
});

test('requireRole 403s a mismatched role', () => {
  const { res, nexted } = run(requireRole('editor'), { user: { role: 'user' } });
  assert.ok(!nexted);
  assert.strictEqual(res.statusCode, 403);
});

test('requireRole 401s an unauthenticated request', () => {
  assert.strictEqual(run(requireRole('editor'), {}).res.statusCode, 401);
});
