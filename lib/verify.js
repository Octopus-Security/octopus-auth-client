const jwt = require('jsonwebtoken');

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
function verifyToken(token) {
  const decoded = jwt.verify(token, getSecret());
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

function signToken(payload, opts = {}) {
  return jwt.sign(payload, getSecret(), { expiresIn: '7d', ...opts });
}

module.exports = { verifyToken, signToken, getSecret };
