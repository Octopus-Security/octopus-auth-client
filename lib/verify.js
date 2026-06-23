const jwt = require('jsonwebtoken');

function getSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error('JWT_SECRET is not set');
  return s;
}

function verifyToken(token) {
  const decoded = jwt.verify(token, getSecret());
  return {
    userId: decoded.userId ?? decoded.id ?? null,
    username: decoded.username,
    role: decoded.role || 'user',
  };
}

function signToken(payload, opts = {}) {
  return jwt.sign(payload, getSecret(), { expiresIn: '7d', ...opts });
}

module.exports = { verifyToken, signToken, getSecret };
