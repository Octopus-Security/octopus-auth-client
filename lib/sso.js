'use strict';

/**
 * sso.js — the browser half of Octopus Auth.
 *
 * createAuthMiddleware handles a `Authorization: Bearer` header, which is what a
 * service-to-service caller sends. A person in a browser does not send one: they
 * carry the `octopus_sso` cookie that octopus-auth sets on .octopustechnology.net.
 *
 * The package never covered that case, so every browser-facing app wrote its own
 * — cortex, games, math, planner and shopper each have a near-identical copy of
 * "parse the cookie, POST it to /api/auth/verify, cache the answer". That is
 * five implementations of one security decision, five places a fix has to land,
 * and the reason revocation could not be rolled out fleet-wide. This is the
 * missing piece, not a new idea.
 *
 * Behaviour matches what those five already do, deliberately: confirm the token
 * with octopus-auth and cache the answer. It is therefore fail-closed — if auth
 * cannot be reached, sessions are not confirmed and requests are anonymous. That
 * is already true of every one of those apps today; it is not a new risk being
 * introduced here.
 */

const { createRemoteVerifier } = require('./remote-verify');
const { verifyToken, getSecret } = require('./verify');

const DEFAULT_COOKIE = 'octopus_sso';

/**
 * Parse a Cookie header. Kept here rather than requiring cookie-parser, because
 * these services mount this before any body/cookie middleware and the package
 * should not dictate their middleware order.
 */
function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (!k) continue;
    // A cookie value can legitimately contain '='; only the first splits.
    let v = part.slice(i + 1).trim();
    try { v = decodeURIComponent(v); } catch { /* leave it as-is */ }
    out[k] = v;
  }
  return out;
}

/**
 * Express middleware that sets `req.user` from the SSO cookie, or leaves it
 * undefined. It never rejects a request — the apps using this decide separately
 * what needs a login, and several serve public pages from the same app.
 *
 * Options:
 *   cookieName  — default 'octopus_sso'
 *   remote      — confirm with octopus-auth (default true; false verifies the
 *                 signature locally and cannot see revocation)
 *   cacheTtlMs  — how long a confirmation is reused, and so this service's
 *                 revocation window (default 60000)
 *   baseUrl     — auth service URL (default AUTH_SERVICE_URL)
 *   onUser      — map the verified user onto req.user; default keeps
 *                 userId/username/role and the raw token
 */
function createSSOMiddleware(options = {}) {
  const cookieName = options.cookieName || DEFAULT_COOKIE;
  const remote     = options.remote !== false;
  const verify     = options.verifier || (remote ? createRemoteVerifier(options) : null);
  const onUser     = options.onUser || ((user, token) => ({
    userId:   user.userId ?? null,
    username: user.username,
    role:     user.role || 'user',
    token,
  }));

  // Whether this service can check a signature at all.
  //
  // The local pre-check needs JWT_SECRET, and not every consumer has it — cortex
  // deliberately does not, because it holds every other credential on the estate
  // and giving it the signing secret would let that one box MINT sessions rather
  // than only read them. It verifies remotely and always has.
  //
  // So the pre-check is an optimisation, not a requirement, and its absence must
  // not reject every cookie. Resolved once at construction rather than per
  // request: a service either has the secret or it does not, and a try/catch per
  // request would hide a genuine misconfiguration as a silent slow path.
  let canCheckLocally = true;
  try { getSecret(); } catch { canCheckLocally = false; }
  if (!remote && !canCheckLocally) {
    throw new Error('createSSOMiddleware: remote:false needs JWT_SECRET to verify anything');
  }

  const mw = async function ssoSession(req, _res, next) {
    const token = parseCookies(req.headers?.cookie)[cookieName];
    if (!token) return next();

    let user = null;
    if (remote) {
      // Local check first WHERE POSSIBLE: an expired or forged cookie is then
      // rejected without a network call, and junk cannot cost auth a request
      // per hit. Without the secret this is skipped and auth does the work,
      // which is exactly what these services do today.
      if (canCheckLocally) {
        try { verifyToken(token); } catch { return next(); }
      }
      try { user = await verify(token); } catch { user = null; }
    } else {
      try { user = verifyToken(token); } catch { user = null; }
    }

    if (user) req.user = onUser(user, token);
    next();
  };

  mw.remote          = remote;
  mw.verifier        = verify;
  mw.localPreCheck   = remote && canCheckLocally;
  return mw;
}

module.exports = { createSSOMiddleware, parseCookies, DEFAULT_COOKIE };
