class AuthClient {
  constructor(baseUrl = process.env.AUTH_SERVICE_URL || 'http://octopus-auth:3002') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async _post(path, body, token) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const r = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST', headers, body: JSON.stringify(body || {}),
    });
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data };
  }

  login(username, password) {
    return this._post('/api/auth/login', { username, password });
  }

  register(username, password, email, inviteCode) {
    return this._post('/api/auth/register', { username, password, email, inviteCode });
  }

  verify(token) {
    return this._post('/api/auth/verify', {}, token);
  }

  refresh(token) {
    return this._post('/api/auth/refresh', {}, token);
  }
}

module.exports = { AuthClient };
