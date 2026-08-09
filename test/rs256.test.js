// RS256 sessions.
//
// HS256 is symmetric: the key that VERIFIES a token also MINTS one. Six stacks
// hold JWT_SECRET and five of them only need to check tokens — so compromising
// the essay writer lets you forge an admin session for the whole estate. RS256
// splits those capabilities: auth holds the private key and is the only thing
// that can issue a session.
//
// These cover the two ways that migration goes wrong: locking everybody out
// mid-switch, and the algorithm-confusion attack that would make a PUBLIC key
// into a minting key.
//
// Run with: npm test

const { test } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');

process.env.JWT_SECRET = 'test-secret-do-not-use-anywhere-real';
const SECRET = process.env.JWT_SECRET;

const { verifyToken, signToken, parsePublicKeys, verificationKeys, signingKey, asymmetricReady, kidOf } = require('..');

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    pub:  publicKey.export({ type: 'spki',  format: 'pem' }),
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

const A = keypair();
const B = keypair();

const CLAIMS = { userId: 1, username: 'testuser', role: 'admin', epoch: 1 };
const rsaToken  = (priv, opts = {}) => jwt.sign(CLAIMS, priv, { algorithm: 'RS256', expiresIn: '7d', ...opts });
const hmacToken = (opts = {}) => jwt.sign(CLAIMS, SECRET, { expiresIn: '7d', ...opts });

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

// ── Parsing what the stack env gives us ──────────────────────────────────────

test('a PEM survives being carried through an env var', () => {
  // Env vars routinely arrive with \n escaped rather than as real newlines, and
  // a PEM that keeps the escapes is not a PEM.
  const escaped = A.pub.replace(/\n/g, '\\n');
  const [key] = parsePublicKeys(escaped);
  assert.ok(key.key.includes('\n'), 'escaped newlines must be restored');
  assert.doesNotThrow(() => jwt.verify(rsaToken(A.priv), key.key, { algorithms: ['RS256'] }));
});

test('several keys can be held at once, which is what makes rotation possible', () => {
  const two = parsePublicKeys(`${A.pub},${B.pub}`);
  assert.equal(two.length, 2);
  const asJson = parsePublicKeys(JSON.stringify({ 'k-2026-08': A.pub, 'k-2026-11': B.pub }));
  assert.deepEqual(asJson.map(k => k.kid), ['k-2026-08', 'k-2026-11']);
});

test('no key material is an empty list, not a crash', () => {
  assert.deepEqual(parsePublicKeys(''), []);
  assert.deepEqual(parsePublicKeys(undefined), []);
});

// ── The migration window ─────────────────────────────────────────────────────

test('during the switch, BOTH old and new sessions verify', () => {
  // The whole point. A seven-day session issued the day before the switch has to
  // keep working, or flipping the algorithm logs out every user at once.
  withEnv({ AUTH_PUBLIC_KEY: A.pub }, () => {
    assert.equal(verifyToken(rsaToken(A.priv)).username, 'testuser', 'new RS256 session');
    assert.equal(verifyToken(hmacToken()).username, 'testuser', 'old HS256 session still valid');
  });
});

test('after JWT_SECRET is removed, HS256 sessions stop being accepted', () => {
  // Phase 3: this is the actual security win, and it must be a real cutoff.
  withEnv({ AUTH_PUBLIC_KEY: A.pub, JWT_SECRET: undefined }, () => {
    assert.equal(verifyToken(rsaToken(A.priv)).username, 'testuser');
    assert.throws(() => verifyToken(hmacToken()));
  });
});

test('before the public key arrives, HS256 still works alone', () => {
  // Phase 1 deploys the capability with no key present. Nothing may change yet.
  withEnv({ AUTH_PUBLIC_KEY: undefined }, () => {
    assert.equal(verifyToken(hmacToken()).username, 'testuser');
    assert.equal(asymmetricReady(), false);
  });
});

// ── Algorithm confusion ──────────────────────────────────────────────────────

test('a public key is never accepted as an HMAC secret', () => {
  // THE attack on this migration. The public key is public — if an HS256 token
  // signed WITH it were accepted, anyone holding it could mint admin sessions,
  // and publishing it is the entire point.
  //
  // Honest note: jsonwebtoken@9 already refuses this on its own, by inferring
  // the permitted algorithms from the key's type. Removing our explicit
  // `algorithms` pin does NOT make this test fail — verified by running exactly
  // that control. So this asserts the outcome we depend on, and the test below
  // covers the part that is actually ours.
  withEnv({ AUTH_PUBLIC_KEY: A.pub, JWT_SECRET: undefined }, () => {
    const forged = jwt.sign(CLAIMS, A.pub, { algorithm: 'HS256' });
    assert.throws(() => verifyToken(forged), 'a public key must never mint a session');
  });
});

test('every key is offered for exactly one algorithm family', () => {
  // This IS ours, and it is what keeps the guarantee above from resting on a
  // library's inference. An RSA key offered for HS256 — or a shared secret
  // offered for RS256 — is the confusion attack re-introduced by bookkeeping,
  // and it would not show up as a failing signature anywhere else.
  withEnv({ AUTH_PUBLIC_KEY: `${A.pub},${B.pub}` }, () => {
    for (const k of verificationKeys()) {
      const isPem = String(k.key).includes('BEGIN');
      assert.deepEqual(k.algorithms, isPem ? ['RS256'] : ['HS256'],
        isPem ? 'a public key must only ever be tried as RS256'
              : 'a shared secret must only ever be tried as HS256');
      assert.equal(k.algorithms.length, 1, 'never more than one algorithm per key');
    }
  });
});

test('an unsigned token is refused', () => {
  withEnv({ AUTH_PUBLIC_KEY: A.pub }, () => {
    assert.throws(() => verifyToken(jwt.sign(CLAIMS, null, { algorithm: 'none' })));
  });
});

test('a token from an unknown key is refused, not merely unmatched', () => {
  withEnv({ AUTH_PUBLIC_KEY: A.pub, JWT_SECRET: undefined }, () => {
    assert.throws(() => verifyToken(rsaToken(B.priv)));
  });
});

// ── Rotation ─────────────────────────────────────────────────────────────────

test('rotation: both keys accepted while the old sessions drain', () => {
  withEnv({ AUTH_PUBLIC_KEY: `${A.pub},${B.pub}` }, () => {
    assert.equal(verifyToken(rsaToken(A.priv)).username, 'testuser', 'outgoing key');
    assert.equal(verifyToken(rsaToken(B.priv)).username, 'testuser', 'incoming key');
  });
});

test('a kid picks its key, and an unknown kid still falls back to trying all', () => {
  withEnv({ AUTH_PUBLIC_KEY: JSON.stringify({ old: A.pub, new: B.pub }) }, () => {
    const t = rsaToken(B.priv, { keyid: 'new' });
    assert.equal(kidOf(t), 'new');
    assert.equal(verifyToken(t).username, 'testuser');
    // Tokens predate kid support; naming a key we do not hold must not be fatal
    // on its own — the signature decides.
    assert.equal(verifyToken(rsaToken(A.priv, { keyid: 'retired-name' })).username, 'testuser');
  });
});

// ── Signing ──────────────────────────────────────────────────────────────────

test('a private key makes this service a signer; without one it signs HS256', () => {
  withEnv({ AUTH_PRIVATE_KEY: A.priv, AUTH_KEY_ID: 'k1' }, () => {
    const s = signingKey();
    assert.equal(s.algorithm, 'RS256');
    const t = signToken(CLAIMS);
    assert.equal(kidOf(t), 'k1', 'signed tokens name their key so rotation can be surgical');
    withEnv({ AUTH_PUBLIC_KEY: A.pub }, () => assert.equal(verifyToken(t).username, 'testuser'));
  });
  withEnv({ AUTH_PRIVATE_KEY: undefined }, () => {
    assert.equal(signingKey().algorithm, 'HS256');
  });
});

test('no key at all refuses to sign rather than signing with nothing', () => {
  withEnv({ AUTH_PRIVATE_KEY: undefined, JWT_SECRET: undefined }, () => {
    assert.throws(() => signingKey(), /No signing key/);
  });
});

// ── The rule RS256 must not quietly drop ─────────────────────────────────────

test('a purpose token is still refused, whichever algorithm signed it', () => {
  // A half-finished login (password accepted, 2FA not yet given) must never be
  // accepted as a session — that is what REQUIRE_2FA rests on. Changing who can
  // mint tokens must not change what a token is allowed to BE.
  withEnv({ AUTH_PRIVATE_KEY: A.priv, AUTH_PUBLIC_KEY: A.pub }, () => {
    const challenge = jwt.sign({ ...CLAIMS, purpose: 'totp-challenge' }, A.priv, { algorithm: 'RS256' });
    assert.throws(() => verifyToken(challenge), /Not a session token/);
  });
});

test('verification prefers RSA, so the common path is not a doomed HMAC check first', () => {
  withEnv({ AUTH_PUBLIC_KEY: A.pub }, () => {
    const order = verificationKeys();
    assert.deepEqual(order[0].algorithms, ['RS256']);
    assert.equal(order[order.length - 1].legacy, true);
  });
});
