'use strict';

/**
 * keys.js — what this service can verify with, and what it can sign with.
 *
 * ── Why this exists ──────────────────────────────────────────────────────────
 * Sessions are signed HS256 with a shared secret, which means the key that
 * VERIFIES a token also MINTS one. Six stacks hold JWT_SECRET — auth, author,
 * budget, ee, health, planner — and five of them only ever need to check
 * tokens. Compromise the essay writer and you can forge an admin session for
 * the whole estate.
 *
 * RS256 splits those capabilities: octopus-auth holds the private key and is the
 * only thing that can issue a session; everyone else holds the public key,
 * verifies offline, and cannot forge anything.
 *
 * RS256 rather than EdDSA because jsonwebtoken@9 does not implement EdDSA —
 * verified, not assumed. Using it would mean replacing the JWT library in the
 * two most safety-critical repos to save 250 bytes a cookie.
 *
 * ── Migrating without logging anybody out ────────────────────────────────────
 * A live estate cannot switch algorithms atomically. So verification accepts
 * EVERY key it has been given: the RSA public key, and the HS256 secret while it
 * is still configured. Tokens signed before the switch keep working until they
 * expire on their own, and JWT_SECRET is removed from the verifiers afterwards
 * as a separate, reversible step.
 *
 * ── Rotation ─────────────────────────────────────────────────────────────────
 * AUTH_PUBLIC_KEY accepts SEVERAL keys, separated by a comma or given as JSON.
 * Rotation is then: publish the new key alongside the old, switch auth to sign
 * with the new one, and retire the old after the session lifetime. No flag day,
 * no window where a valid session is rejected. A `kid` header picks the right
 * key directly when present; without one every candidate is tried, so a token
 * issued before kid existed still verifies.
 */

const ALG_RSA  = ['RS256'];
const ALG_HMAC = ['HS256'];

/** A PEM may arrive with real newlines or the \n-escaped form env vars carry. */
function normalisePem(value) {
  return String(value || '').replace(/\\n/g, '\n').trim();
}

/**
 * Public keys this service will verify with, newest first.
 * Accepts a JSON array, a JSON object of kid -> pem, or comma/semicolon separated
 * PEMs. Returns [{ kid, key }] — kid null when the caller did not name one.
 */
function parsePublicKeys(raw) {
  const value = String(raw || '').trim();
  if (!value) return [];

  if (value.startsWith('{') || value.startsWith('[')) {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) {
        return parsed.map(e => (typeof e === 'string'
          ? { kid: null, key: normalisePem(e) }
          : { kid: e.kid ?? null, key: normalisePem(e.key ?? e.pem) })).filter(k => k.key);
      }
      return Object.entries(parsed).map(([kid, key]) => ({ kid, key: normalisePem(key) })).filter(k => k.key);
    } catch { /* not JSON after all — fall through to the separated form */ }
  }

  // Splitting on commas cannot break a PEM: base64 has no commas, and the
  // BEGIN/END lines have none either.
  return value.split(/[,;]/).map(p => ({ kid: null, key: normalisePem(p) })).filter(k => k.key);
}

/**
 * Everything this service can verify a token with, in the order to try.
 *
 * RSA first: once the estate is on RS256 that is the hit, and trying a secret
 * first would mean every request runs a doomed HMAC check before the real one.
 */
function verificationKeys(env = process.env) {
  const keys = parsePublicKeys(env.AUTH_PUBLIC_KEY).map(k => ({ ...k, algorithms: ALG_RSA }));
  const secret = env.JWT_SECRET;
  if (secret) keys.push({ kid: null, key: secret, algorithms: ALG_HMAC, legacy: true });
  return keys;
}

/**
 * What octopus-auth signs with. Private key if it has one, else the shared
 * secret. Only auth should ever have a private key.
 */
function signingKey(env = process.env) {
  const priv = normalisePem(env.AUTH_PRIVATE_KEY);
  if (priv) {
    return { key: priv, algorithm: 'RS256', kid: env.AUTH_KEY_ID || null };
  }
  if (env.JWT_SECRET) return { key: env.JWT_SECRET, algorithm: 'HS256', kid: null };
  throw new Error('No signing key: set AUTH_PRIVATE_KEY (preferred) or JWT_SECRET');
}

/** True once this service can verify RS256 — i.e. a public key reached it. */
function asymmetricReady(env = process.env) {
  return parsePublicKeys(env.AUTH_PUBLIC_KEY).length > 0;
}

module.exports = {
  parsePublicKeys, verificationKeys, signingKey, asymmetricReady, normalisePem,
  ALG_RSA, ALG_HMAC,
};
