const jwt = require('jsonwebtoken');
const { verificationKeys, signingKey, asymmetricReady } = require('./keys');

function getSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error('JWT_SECRET is not set');
  return s;
}

// A session token and a "purpose" token are both signed with the same shared
// secret, so a signature check alone does NOT tell you someone is logged in.
// octopus-auth issues short-lived purpose tokens part-way through login —
// `totp-challenge` (password accepted, 2FA code not yet supplied) and
// `totp-enroll` (2FA-less account being forced to enrol). Accepting one as a
// session lets a caller who only has a password through, defeating REQUIRE_2FA,
// which exists precisely to survive a stolen password. Real sessions carry no
// `purpose`; auth applies this same rule before it issues the SSO cookie.
//
// This rule is applied AFTER the signature, for every algorithm. RS256 changes
// who can mint a token; it does not change what a token is allowed to be.
function assertIsSession(decoded) {
  if (decoded.purpose) {
    const err = new Error(`Not a session token (purpose: ${decoded.purpose})`);
    err.code = 'NOT_A_SESSION_TOKEN';
    throw err;
  }
  return {
    userId: decoded.userId ?? decoded.id ?? null,
    username: decoded.username,
    role: decoded.role || 'user',
  };
}

/** The kid this token names, if any, read WITHOUT trusting the token. */
function kidOf(token) {
  const decoded = jwt.decode(token, { complete: true });
  return decoded?.header?.kid || null;
}

/**
 * Verify against every key this service holds.
 *
 * During the RS256 migration a service legitimately holds both an RSA public key
 * and the old shared secret, and tokens of both kinds are in circulation — a
 * seven-day session issued the day before the switch has to keep working. Trying
 * each key is what makes the change survivable without logging everyone out.
 *
 * `algorithms` is pinned per key. Without it a caller could hand us an HS256
 * token and have it checked against the RSA PUBLIC key as if that were an HMAC
 * secret — the public key is public, so anyone could then mint sessions. That is
 * the classic JWT confusion attack and the pinning is what prevents it.
 */
function verifyToken(token) {
  const keys = verificationKeys();
  if (!keys.length) throw new Error('No verification key: set AUTH_PUBLIC_KEY or JWT_SECRET');

  const named = kidOf(token);
  // A token naming a key we hold is checked against that one only. An unknown
  // kid falls through to trying everything rather than failing, so a token from
  // a key we have not been given yet fails on its signature and not on
  // bookkeeping.
  const ordered = named ? [...keys.filter(k => k.kid === named), ...keys.filter(k => k.kid !== named)] : keys;

  let lastErr;
  for (const k of ordered) {
    try {
      return assertIsSession(jwt.verify(token, k.key, { algorithms: k.algorithms }));
    } catch (err) {
      // A token that verified but is the wrong KIND is a definite answer — stop
      // rather than reporting a signature failure from some later key.
      if (err.code === 'NOT_A_SESSION_TOKEN') throw err;
      lastErr = err;
    }
  }
  throw lastErr || new Error('invalid token');
}

/**
 * Is the local pre-check entitled to an opinion about THIS token?
 *
 * Only relevant where a remote verifier sits behind it. `verifyToken` answers
 * one question — "does this check out against a key I hold" — and callers have
 * been reading a `false` from it as "forged". Those are not the same thing, and
 * the difference caused a total lockout: octopus-auth started signing RS256
 * while the verifiers still held only JWT_SECRET, so every real session failed
 * an HMAC check against an RSA token and was dropped BEFORE the remote verifier
 * — which would have said yes — was ever asked. A pre-check that is documented
 * as an optimisation must never be the thing that refuses.
 *
 * So: defer to the remote verifier when, and only when, this service holds no
 * key that could speak to the token's algorithm. Everything else is still
 * decided locally and for free.
 *
 *   - No keys at all  → no standing to judge anything; defer.
 *   - Not a JWT       → no key is needed to know that; reject locally, so junk
 *                       cookies cannot each cost octopus-auth a request.
 *   - `alg: none`     → unsigned, i.e. an outright forgery attempt. Reject
 *                       locally; never dignify it with a network call.
 *   - alg we hold a key for → check it; the answer is definitive.
 *   - alg we hold no key for → defer. This is the fix.
 *
 * Deliberately keyed on ALGORITHM and not on `kid`. An unknown kid within an
 * algorithm we do hold is key rotation, and keys.js already answers that by
 * accepting several public keys at once so the new one is published before it is
 * used. Deferring on kid as well would let anyone bounce a request off auth
 * simply by inventing one.
 */
function canPreCheck(token, env = process.env) {
  const keys = verificationKeys(env);
  if (!keys.length) return false;

  const alg = jwt.decode(token, { complete: true })?.header?.alg;
  if (!alg) return true;
  if (String(alg).toLowerCase() === 'none') return true;

  return keys.some(k => (k.algorithms || []).includes(alg));
}

/**
 * Sign a session. Uses AUTH_PRIVATE_KEY when present, otherwise the shared
 * secret — so octopus-auth switches algorithm by gaining a key, and every other
 * service is simply never able to do this.
 */
function signToken(payload, opts = {}) {
  const { key, algorithm, kid } = signingKey();
  const options = { expiresIn: '7d', algorithm, ...opts };
  if (kid) options.keyid = kid;
  return jwt.sign(payload, key, options);
}

module.exports = { verifyToken, signToken, getSecret, kidOf, canPreCheck, asymmetricReady };
