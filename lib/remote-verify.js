/**
 * Remote session verification.
 *
 * A locally-verified JWT answers "was this signed by us and has it expired yet",
 * which is not the same question as "is this session still valid". Sessions can
 * be revoked — a password reset, an admin cutting off an account, someone
 * pressing "sign out everywhere" — and none of that changes the signature or the
 * expiry, so a local check keeps waving a dead session through for up to the full
 * seven days.
 *
 * Asking octopus-auth is the only way to see it. That costs a network round trip,
 * so answers are cached briefly: the cache TTL is exactly the window in which a
 * revocation has not taken effect yet, and shortening it trades requests for
 * tighter revocation.
 *
 * Failures are treated as "not authenticated", never as "probably fine" — a
 * revocation check that opens the gate when it cannot reach the authority is not
 * a revocation check. This does mean an octopus-auth outage locks these routes,
 * which matches what every service on the platform already does with the SSO
 * cookie.
 */

const DEFAULT_TTL_MS     = 60 * 1000;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_ENTRIES = 5000;

function defaultBaseUrl() {
  return (process.env.AUTH_SERVICE_URL || process.env.AUTH_INTERNAL_URL || 'http://octopus-auth:3002')
    .replace(/\/$/, '');
}

/**
 * Build a cached `token -> user | null` verifier.
 *
 * Negative results are cached too, and for the same TTL. Without that, a client
 * looping on a revoked token turns every request into a fresh call to auth —
 * revocation would become a way to generate load rather than to stop it.
 */
function createRemoteVerifier(options = {}) {
  const baseUrl    = (options.baseUrl || defaultBaseUrl()).replace(/\/$/, '');
  const ttlMs      = options.cacheTtlMs ?? DEFAULT_TTL_MS;
  const timeoutMs  = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxEntries = options.maxCacheEntries ?? DEFAULT_MAX_ENTRIES;
  const fetchImpl  = options.fetch || globalThis.fetch;
  const now        = options.now || (() => Date.now());

  const cache = new Map(); // token -> { user: object|null, exp: number }

  function cacheGet(token) {
    const hit = cache.get(token);
    if (!hit) return undefined;
    if (hit.exp <= now()) { cache.delete(token); return undefined; }
    return hit;
  }

  function cacheSet(token, user) {
    const t = now();
    for (const [k, v] of cache) if (v.exp <= t) cache.delete(k);
    // Map iterates in insertion order, so this evicts oldest-first.
    while (cache.size >= maxEntries) cache.delete(cache.keys().next().value);
    cache.set(token, { user, exp: t + ttlMs });
  }

  async function verify(token) {
    const hit = cacheGet(token);
    if (hit) return hit.user;

    let user = null;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const r = await fetchImpl(`${baseUrl}/api/auth/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: '{}',
          signal: controller.signal,
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.valid && data.user) user = data.user;
      } finally {
        clearTimeout(timer);
      }
    } catch {
      // Unreachable, timed out, or malformed — indistinguishable from here, and
      // all three mean we cannot confirm the session. Deliberately not cached:
      // an outage should not be remembered as a revocation for a full TTL.
      return null;
    }

    cacheSet(token, user);
    return user;
  }

  verify.clearCache = () => cache.clear();
  verify.cacheSize  = () => cache.size;
  return verify;
}

// Whether a service opts into remote verification. An env var rather than a code
// change so it can be turned on per-service from the Portainer stack env, and
// turned back off just as fast if auth becomes a bottleneck.
function remoteVerifyEnabled() {
  return /^(1|true|yes)$/i.test(String(process.env.AUTH_REMOTE_VERIFY || ''));
}

module.exports = { createRemoteVerifier, remoteVerifyEnabled };
