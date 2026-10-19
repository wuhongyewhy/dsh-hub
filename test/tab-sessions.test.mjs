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

test('media subresources carry the tab token; blob/data/cross-origin URLs stay untouched', () => {
  const scripts = [...emittedHtml('TAB_SESSION_SNIPPET').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
  assert.equal(scripts.length, 1);

  class FakeElement {
    constructor(tag) { this.tagName = tag; this.nodeType = 1; this._attrs = {}; }
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(this._attrs, name) ? this._attrs[name] : null; }
  }
  class Element extends FakeElement {}
  Element.prototype.setAttribute = function (name, value) { this._attrs[name] = String(value); };
  const accessor = (name) => ({
    configurable: true,
    get() { return this._attrs[name] ?? ''; },
    set(value) { this._attrs[name] = String(value); },
  });
  class HTMLScriptElement extends Element { constructor() { super('SCRIPT'); } }
  Object.defineProperty(HTMLScriptElement.prototype, 'src', accessor('src'));
  class HTMLLinkElement extends Element { constructor() { super('LINK'); } }
  Object.defineProperty(HTMLLinkElement.prototype, 'href', accessor('href'));
  const media = {};
  for (const tag of ['IMG', 'VIDEO', 'AUDIO', 'SOURCE']) {
    const ctor = class extends Element { constructor() { super(tag); } };
    Object.defineProperty(ctor.prototype, 'src', accessor('src'));
    media[tag] = ctor;
  }

  let observerCallback = null;
  class MutationObserver {
    constructor(callback) { this.callback = callback; }
    observe() { observerCallback = this.callback; }
  }

  const store = { 'dsh-hub-tab-session-v1': 'tab-token' };
  const sandbox = {
    URL, URLSearchParams,
    sessionStorage: {
      getItem: (key) => (key in store ? store[key] : null),
      setItem: (key, value) => { store[key] = String(value); },
      removeItem: (key) => { delete store[key]; },
    },
    location: { href: 'http://hub.test:3080/wuhy/', origin: 'http://hub.test:3080', host: 'hub.test:3080' },
    history: { state: null, pushState() {}, replaceState() {} },
    document: { documentElement: new Element('HTML'), addEventListener() {} },
    navigator: {},
    Element, MutationObserver, HTMLScriptElement, HTMLLinkElement,
    HTMLImageElement: media.IMG, HTMLVideoElement: media.VIDEO,
    HTMLAudioElement: media.AUDIO, HTMLSourceElement: media.SOURCE,
    fetch: () => Promise.resolve({ ok: false }),
  };
  const context = vm.createContext(sandbox);
  vm.runInContext('this.window = this;', context);
  new vm.Script(scripts[0][1], { filename: 'TAB_SESSION_SNIPPET' }).runInContext(context);

  const tokenOf = (url) => new URL(url, sandbox.location.href).searchParams.getAll('__dsh_hub_session');

  const img = new media.IMG();
  img.setAttribute('src', '/sidebar/file?sessionId=s1&path=%2Fpublic%2Fx.png');
  assert.equal(img._attrs.src, 'http://hub.test:3080/sidebar/file?sessionId=s1&path=%2Fpublic%2Fx.png&__dsh_hub_session=tab-token');

  const video = new media.VIDEO();
  video.src = '/media/a.mp4';
  assert.equal(video._attrs.src, 'http://hub.test:3080/media/a.mp4?__dsh_hub_session=tab-token');

  const script = new HTMLScriptElement();
  script.setAttribute('src', '/plugins/x.js');
  assert.deepEqual(tokenOf(script._attrs.src), ['tab-token']);

  for (const untouched of [
    'blob:http://hub.test:3080/550e8400-e29b-41d4-a716-446655440000',
    'data:image/png;base64,YWJj',
    'https://elsewhere.test/x.png',
    '/hub/login',
  ]) {
    const probe = new media.IMG();
    probe.setAttribute('src', untouched);
    assert.equal(probe._attrs.src, untouched);
  }

  const idempotent = new media.IMG();
  idempotent.setAttribute('src', '/x.png?__dsh_hub_session=tab-token');
  assert.equal(idempotent._attrs.src, '/x.png?__dsh_hub_session=tab-token');

  const stale = new media.IMG();
  stale.setAttribute('src', '/x.png?__dsh_hub_session=stale-token');
  assert.deepEqual(tokenOf(stale._attrs.src), ['tab-token']);

  assert.equal(typeof observerCallback, 'function');
  const inner = new media.IMG();
  inner._attrs.src = '/sidebar/file?path=%2Finner.png';
  observerCallback([{ type: 'childList', addedNodes: [inner] }]);
  assert.deepEqual(tokenOf(inner._attrs.src), ['tab-token']);
  observerCallback([{ type: 'attributes', target: inner }]);
  assert.deepEqual(tokenOf(inner._attrs.src), ['tab-token']);

  const late = new media.IMG();
  late._attrs.src = '/late.png';
  observerCallback([{ type: 'attributes', target: late }]);
  assert.deepEqual(tokenOf(late._attrs.src), ['tab-token']);

  delete store['dsh-hub-tab-session-v1'];
  const anonymous = new media.IMG();
  anonymous.setAttribute('src', '/anon.png');
  assert.equal(anonymous._attrs.src, '/anon.png');
});
