const { test } = require('node:test');
const assert = require('node:assert');
const { createRemoteVerifier } = require('../lib/remote-verify');

function mk(handler) {
  let calls = 0;
  const fetch = async (...a) => { calls++; return handler(calls, ...a); };
  const ok = (user) => ({ ok: true, json: async () => ({ valid: true, user }) });
  return { fetch, ok, calls: () => calls };
}

test('concurrent verifies of one token make one auth call', async () => {
  const m = mk(async () => { await new Promise((r) => setTimeout(r, 20)); return m.ok({ username: 'a' }); });
  const v = createRemoteVerifier({ baseUrl: 'http://x', fetch: m.fetch });
  const r = await Promise.all(Array.from({ length: 10 }, () => v('t1')));
  assert.strictEqual(m.calls(), 1);
  assert.ok(r.every((u) => u.username === 'a'));
  assert.strictEqual(v.inflightSize(), 0);
});

test('different tokens are not merged', async () => {
  const m = mk(async (n, url, opts) => m.ok({ username: opts.headers.Authorization }));
  const v = createRemoteVerifier({ baseUrl: 'http://x', fetch: m.fetch });
  const [a, b] = await Promise.all([v('t1'), v('t2')]);
  assert.strictEqual(m.calls(), 2);
  assert.notStrictEqual(a.username, b.username);
});

test('a failure is shared by concurrent callers but not cached', async () => {
  const m = mk(async (n) => { if (n === 1) throw new Error('down'); return m.ok({ username: 'a' }); });
  const v = createRemoteVerifier({ baseUrl: 'http://x', fetch: m.fetch });
  const r = await Promise.all([v('t'), v('t'), v('t')]);
  assert.deepStrictEqual(r, [null, null, null]);
  assert.strictEqual(m.calls(), 1);
  assert.strictEqual((await v('t')).username, 'a');
  assert.strictEqual(m.calls(), 2);
});

test('after settle the cache serves; a negative answer is shared too', async () => {
  const m = mk(async () => ({ ok: false, json: async () => ({}) }));
  const v = createRemoteVerifier({ baseUrl: 'http://x', fetch: m.fetch });
  assert.deepStrictEqual(await Promise.all([v('bad'), v('bad')]), [null, null]);
  await v('bad');
  assert.strictEqual(m.calls(), 1);
});
