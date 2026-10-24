const { test } = require('node:test');
const assert = require('node:assert');
const { AuthClient } = require('..');

function capture() {
  const calls = [];
  global.fetch = async (url, init) => { calls.push({ url, body: JSON.parse(init.body) }); return { ok: true, status: 201, json: async () => ({}) }; };
  return calls;
}

test('register passes ageConfirmed through to the request body', async () => {
  const calls = capture();
  await new AuthClient('http://auth').register('u', 'p', 'e@x.y', 'code', { ageConfirmed: true });
  assert.strictEqual(calls[0].url, 'http://auth/api/auth/register');
  assert.strictEqual(calls[0].body.ageConfirmed, true);
  assert.strictEqual(calls[0].body.inviteCode, 'code');
});

test('register without the option sends no ageConfirmed (existing callers unchanged)', async () => {
  const calls = capture();
  await new AuthClient('http://auth').register('u', 'p', 'e@x.y', 'code');
  assert.ok(!('ageConfirmed' in calls[0].body));
});
