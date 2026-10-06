import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { emittedHtml, startFixture } from './fixtures/hub.mjs';

for (const name of ['RANDOM_UUID_POLYFILL', 'TAB_SESSION_SNIPPET', 'USER_BADGE_SNIPPET', 'TAB_LOGIN_PAGE']) {
  test(`${name}: browser receives valid JavaScript after template evaluation`, () => {
    const scripts = [...emittedHtml(name).matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
    assert.ok(scripts.length);
    for (const script of scripts) new vm.Script(script[1], { filename: name });
  });
}

test('both login paths issue independent sessions; switches retain the asset cookie and tab tokens beat cookies', async () => {
  const fixture = await startFixture();
  try {
    const tokens = {};
    let assetCookie;
    for (const [path, user] of [['/hub/login', 'alice'], ['/hub/tab-login', 'bob']]) {
      const page = await fetch(fixture.origin + path);
      assert.ok((await page.text()).includes('tab-login-form'));
      const login = await fetch(fixture.origin + path, {
        method: 'POST', body: new URLSearchParams({ username: user, password: 'fixture-only' }),
        headers: assetCookie ? { cookie: assetCookie } : {},
      });
      assert.equal(login.status, 200);
      if (assetCookie) assert.equal(login.headers.get('set-cookie'), null);
      else {
        assert.ok(login.headers.get('set-cookie'));
        assetCookie = login.headers.get('set-cookie').split(';')[0];
      }
      const data = await login.json();
      assert.equal(data.user, user);
      tokens[user] = data.tabSession;
    }
    const asset = await fetch(fixture.origin + '/static/app.js', { headers: { cookie: assetCookie } });
    assert.equal(asset.status, 200);
    assert.match(asset.headers.get('content-type'), /javascript/);
    for (const user of ['alice', 'bob']) {
      const refresh = await fetch(fixture.origin + '/api/whoami?__dsh_hub_session=' + tokens[user], {
        headers: { cookie: fixture.cookieFor(user === 'alice' ? 'bob' : 'alice') },
      });
      assert.equal((await refresh.json()).user, user);
      const me = await fetch(fixture.origin + '/hub/me', {
        headers: { 'x-dsh-hub-session': tokens[user], cookie: fixture.cookieFor('bob') },
      });
      assert.equal((await me.json()).user, user);
    }
  } finally { await fixture.close(); }
});
