const { verifyToken } = require('./verify');

function createAuthMiddleware(options = {}) {
  return function authenticate(req, res, next) {
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
