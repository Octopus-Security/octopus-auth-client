// The local pre-check must never be the thing that refuses a session.
//
// This is the outage that actually happened. octopus-auth started signing RS256
// while the verifying services still held only JWT_SECRET. Every real session
// then failed an HMAC check against an RSA token, and both middlewares read that
// failure as "forged" and dropped the request — BEFORE asking the remote
// verifier, which held the truth and would have said yes. Nobody could log in,
// including into the admin panel you would use to undo it.
//
// The bug is a category error, not a missing key: `verifyToken` answers "does
// this check out against a key I hold", and the callers were reading it as "is
// this token valid". Where a remote verifier sits behind the pre-check, the two
// differ exactly when the pre-check holds no key for the token's algorithm — and
// that is the case that must defer instead of refuse.
//
// Run with: npm test

const { test } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');

process.env.JWT_SECRET = 'test-secret-do-not-use-anywhere-real';
const SECRET = process.env.JWT_SECRET;

const { canPreCheck, createSSOMiddleware, createAuthMiddleware } = require('..');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUB  = publicKey.export({ type: 'spki', format: 'pem' });
const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' });

const CLAIMS = { userId: 1, username: 'testuser', role: 'user' };
const rsaToken  = () => jwt.sign(CLAIMS, PRIV,   { algorithm: 'RS256', expiresIn: '7d' });
const hmacToken = () => jwt.sign(CLAIMS, SECRET, { expiresIn: '7d' });

const VALID_BODY = { success: true, valid: true, user: CLAIMS };

/** Run with a specific environment, restoring whatever was there. */
function withEnv(vars, fn) {
  const saved = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try { return fn(); }
  finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

function countingFetch(body = VALID_BODY, { ok = true } = {}) {
  const fn = async () => { fn.calls++; return { ok, json: async () => body }; };
  fn.calls = 0;
  return fn;
}

// ── canPreCheck ──────────────────────────────────────────────────────────────

test('an algorithm we hold no key for defers — the outage, in one line', () => {
  withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, () => {
    assert.equal(canPreCheck(rsaToken()), false,
      'holding only an HMAC secret says NOTHING about an RS256 token');
  });
});

test('an algorithm we do hold a key for is checked locally', () => {
  withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, () => {
    assert.equal(canPreCheck(hmacToken()), true);
  });
  withEnv({ JWT_SECRET: undefined, AUTH_PUBLIC_KEY: PUB }, () => {
    assert.equal(canPreCheck(rsaToken()), true);
  });
});

test('mid-migration, holding both keys, both kinds of token are checked locally', () => {
  // The whole point of the overlap: seven-day sessions issued before the switch
  // must keep working, and neither kind should be paying for a network call.
  withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: PUB }, () => {
    assert.equal(canPreCheck(hmacToken()), true);
    assert.equal(canPreCheck(rsaToken()), true);
  });
});

test('junk is rejected locally, so it cannot cost auth a request per hit', () => {
  withEnv({ JWT_SECRET: SECRET }, () => {
    assert.equal(canPreCheck('not.a.jwt'), true);
    assert.equal(canPreCheck(''), true);
  });
});

test('alg:none is refused locally, never deferred', () => {
  // An unsigned token is an outright forgery attempt. Deferring would let it
  // bounce a request off octopus-auth; there is nothing to think about here.
  const unsigned = jwt.sign(CLAIMS, '', { algorithm: 'none' });
  withEnv({ JWT_SECRET: SECRET }, () => {
    assert.equal(canPreCheck(unsigned), true);
  });
});

test('holding no key at all, there is no standing to judge anything', () => {
  withEnv({ JWT_SECRET: undefined, AUTH_PUBLIC_KEY: undefined }, () => {
    assert.equal(canPreCheck(hmacToken()), false);
    assert.equal(canPreCheck('not.a.jwt'), false);
  });
});

// ── The SSO cookie path ──────────────────────────────────────────────────────

test('SSO: an RS256 cookie survives a service that holds only JWT_SECRET', async () => {
  await withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, async () => {
    const fetch = countingFetch();
    const mw = createSSOMiddleware({ fetch });
    const req = { headers: { cookie: `octopus_sso=${rsaToken()}` } };
    await mw(req, {}, () => {});

    assert.equal(req.user?.username, 'testuser',
      'this is the lockout: the session was dropped before auth was asked');
    assert.equal(fetch.calls, 1, 'and auth must actually have been asked');
  });
});

test('SSO: a forged HMAC cookie is still rejected without touching the network', async () => {
  await withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, async () => {
    const fetch = countingFetch();
    const mw = createSSOMiddleware({ fetch });
    const forged = jwt.sign(CLAIMS, 'wrong-secret', { expiresIn: '7d' });
    const req = { headers: { cookie: `octopus_sso=${forged}` } };
    await mw(req, {}, () => {});

    assert.equal(req.user, undefined);
    assert.equal(fetch.calls, 0, 'the optimisation still has to be an optimisation');
  });
});

test('SSO: an expired cookie is still rejected locally', async () => {
  await withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, async () => {
    const fetch = countingFetch();
    const mw = createSSOMiddleware({ fetch });
    const expired = jwt.sign(CLAIMS, SECRET, { expiresIn: '-1h' });
    const req = { headers: { cookie: `octopus_sso=${expired}` } };
    await mw(req, {}, () => {});

    assert.equal(req.user, undefined);
    assert.equal(fetch.calls, 0);
  });
});

test('SSO: deferring is not trusting — auth still gets to say no', async () => {
  await withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, async () => {
    const fetch = countingFetch({ success: true, valid: false }, { ok: true });
    const mw = createSSOMiddleware({ fetch });
    const req = { headers: { cookie: `octopus_sso=${rsaToken()}` } };
    await mw(req, {}, () => {});

    assert.equal(req.user, undefined,
      'a deferred token is decided by the authority, not waved through');
  });
});

test('SSO: remote:false is constructible on an RSA public key alone', async () => {
  // Previously this asked getSecret() and threw, even though the service held a
  // perfectly good verification key — the state the whole estate ends up in once
  // JWT_SECRET is retired from the verifiers.
  await withEnv({ JWT_SECRET: undefined, AUTH_PUBLIC_KEY: PUB }, async () => {
    const mw = createSSOMiddleware({ remote: false });
    const req = { headers: { cookie: `octopus_sso=${rsaToken()}` } };
    await mw(req, {}, () => {});
    assert.equal(req.user?.username, 'testuser');
  });
});

// ── The Bearer path ──────────────────────────────────────────────────────────

test('Bearer remote: an RS256 token survives an HMAC-only service', async () => {
  await withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, async () => {
    const fetch = countingFetch();
    const mw = createAuthMiddleware({ remote: true, fetch });
    const req = { headers: { authorization: `Bearer ${rsaToken()}` } };
    let nexted = false;
    await mw(req, { status: () => ({ json: () => {} }) }, () => { nexted = true; });

    assert.ok(nexted, 'the pre-check 401d a session the verifier would have accepted');
    assert.equal(req.user.username, 'testuser');
  });
});

test('Bearer local: no remote behind it, so it must still refuse', async () => {
  // The deliberate asymmetry. Deferring here defers to nothing, and the only
  // alternative to refusing would be admitting an unverified session.
  await withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: undefined }, async () => {
    const mw = createAuthMiddleware({ remote: false });
    const req = { headers: { authorization: `Bearer ${rsaToken()}` } };
    let code = null;
    let nexted = false;
    await mw(req, { status: c => { code = c; return { json: () => {} }; } }, () => { nexted = true; });

    assert.equal(code, 401);
    assert.equal(nexted, false);
  });
});

test('a purpose token is still not a session, deferred or not', async () => {
  // REQUIRE_2FA depends on this: a totp-challenge token means the password was
  // accepted and the second factor was not. Nothing in this change may soften it.
  await withEnv({ JWT_SECRET: SECRET, AUTH_PUBLIC_KEY: PUB }, async () => {
    const challenge = jwt.sign({ ...CLAIMS, purpose: 'totp-challenge' }, PRIV,
      { algorithm: 'RS256', expiresIn: '5m' });
    const fetch = countingFetch();
    const mw = createSSOMiddleware({ fetch });
    const req = { headers: { cookie: `octopus_sso=${challenge}` } };
    await mw(req, {}, () => {});

    assert.equal(req.user, undefined);
    assert.equal(fetch.calls, 0, 'and it is caught locally, since we hold the RSA key');
  });
});
