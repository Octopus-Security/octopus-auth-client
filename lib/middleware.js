const { verifyToken } = require('./verify');
const { createRemoteVerifier, remoteVerifyEnabled } = require('./remote-verify');

/**
 * Bearer-token gate.
 *
 * By default this verifies the signature locally, which is fast and offline but
 * cannot see revocation — octopus-auth invalidates sessions by bumping a
 * per-user epoch, and only octopus-auth knows the current one. Pass
 * `{ remote: true }` (or set AUTH_REMOTE_VERIFY=1 in the service's environment)
 * to confirm each token with /api/auth/verify, cached for `cacheTtlMs`.
 *
 * Local verification still runs first in remote mode: it costs nothing and means
 * an expired or forged token is rejected without a network call.
 *
 * Options:
 *   optional         — allow anonymous requests through with req.user = null
 *   remote           — confirm sessions with octopus-auth (default: AUTH_REMOTE_VERIFY)
 *   baseUrl          — auth service URL (default: AUTH_SERVICE_URL)
 *   cacheTtlMs       — how long a confirmation is reused, and so the revocation
 *                      window for this service (default 60000)
 *   timeoutMs        — per-request timeout when calling auth (default 5000)
 */
function createAuthMiddleware(options = {}) {
  const remote = options.remote ?? remoteVerifyEnabled();
  if (!remote) return createLocalMiddleware(options);

  const remoteVerify = options.verifier || createRemoteVerifier(options);

  const mw = async function authenticate(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!token) {
      if (options.optional) { req.user = null; return next(); }
      return res.status(401).json({ success: false, error: 'Authentication token required' });
    }
    try {
      verifyToken(token);
    } catch {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }

    let user;
    try {
      user = await remoteVerify(token);
    } catch {
      user = null;
    }
    // "Optional" means anonymous is allowed, never that an unconfirmed session is
    // allowed — a revoked token must not be upgraded to a valid one by the route
    // happening to tolerate anonymity.
    if (!user) {
      return res.status(401).json({ success: false, error: 'Session is invalid, expired or revoked' });
    }

    req.user = { userId: user.userId ?? null, username: user.username, role: user.role || 'user' };
    next();
  };
  mw.remote = true;
  mw.verifier = remoteVerify;
  return mw;
}

function createLocalMiddleware(options) {
  const mw = function authenticate(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!token) {
      if (options.optional) { req.user = null; return next(); }
      return res.status(401).json({ success: false, error: 'Authentication token required' });
    }
    try {
      req.user = verifyToken(token);
      next();
    } catch {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
  };
  mw.remote = false;
  return mw;
}

function requireRole(role) {
  return function (req, res, next) {
    if (!req.user) return res.status(401).json({ success: false, error: 'Not authenticated' });
    if (req.user.role !== role && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    }
    next();
  };
}

module.exports = { createAuthMiddleware, requireRole };
