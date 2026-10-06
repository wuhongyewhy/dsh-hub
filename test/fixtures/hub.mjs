import fs from 'node:fs';
import vm from 'node:vm';
import http from 'node:http';
import crypto from 'node:crypto';

const source = fs.readFileSync(new URL('../../src/index.mjs', import.meta.url), 'utf8');
const context = vm.createContext({
  crypto, Buffer, URL, URLSearchParams,
  SECRET: crypto.randomBytes(32),
  CFG: { cookieName: 'dshhub_session', sessionTtlMs: 3600000, allowUsers: [], userBadge: true },
  TAB_SESSION_HEADER: 'x-dsh-hub-session',
  TAB_SESSION_QUERY: '__dsh_hub_session',
  TAB_SESSION_STORAGE_KEY: 'dsh-hub-tab-session-v1',
  lookupUser: (user) => ['alice', 'bob'].includes(user) ? { name: user } : null,
  pamAuthenticate: async (_user, password) => password === 'fixture-only',
  rateLimited: () => false,
  recordFailure: () => {},
});

export function emittedHtml(name) {
  const expression = source.match(new RegExp(
    'const ' + name + ' = (?:CFG\\.userBadge \\? )?((?:String\\.raw)?`[\\s\\S]*?`)(?:\\s*:\\s*\'\')?;'
  ))?.[1];
  if (!expression) throw new Error(`Missing ${name}`);
  return vm.runInContext(expression, context);
}

for (const name of ['RANDOM_UUID_POLYFILL', 'TAB_SESSION_SNIPPET', 'USER_BADGE_SNIPPET', 'TAB_LOGIN_PAGE']) {
  context[name] = emittedHtml(name);
}
for (const name of ['sign', 'makeCookie', 'parseCookie', 'sessionUser', 'makeTabSession',
  'parseTabSession', 'stripTabSessionFromReferer', 'clientIp', 'readBody', 'urlencoded',
  'sendHtml', 'sendJson', 'handleTabLogin', 'handleLogout']) {
  const definition = source.match(new RegExp('(?:async )?function ' + name + '\\([\\s\\S]*?\\n}'))?.[0];
  if (!definition) throw new Error(`Missing function ${name}`);
  vm.runInContext(definition, context);
}
// Use the production routing code through the login/me/logout endpoints.
const routeStart = source.indexOf('async function route(req, res) {');
const routeEnd = source.indexOf('\n  const user = sessionUser(req);\n  if (!user)', routeStart);
vm.runInContext(source.slice(routeStart, routeEnd) + '\n}', context);
const upgradeStart = source.indexOf("server.on('upgrade', (req, socket, head) => {");
const upgradeBody = source.indexOf('\n', upgradeStart);
const upgradeEnd = source.indexOf('  const be = backends.get(user);', upgradeBody);
vm.runInContext('function prepareUpgrade(req, socket, head) {' +
  source.slice(upgradeBody, upgradeEnd) + '\nreturn user;\n}', context);

export async function startFixture(port = 0) {
  const sockets = new Set();
  const server = http.createServer(async (req, res) => {
    try {
      await context.route(req, res);
      if (res.writableEnded) return;
      if (req.url === '/__fixture/cookie/bob') {
        res.writeHead(200, { 'set-cookie': `dshhub_session=${context.makeCookie('bob')}; Path=/; HttpOnly` });
        res.end('legacy cookie changed');
        return;
      }
      const user = context.sessionUser(req);
      if (!user) { res.writeHead(303, { location: '/hub/login' }); res.end(); return; }
      if (req.url === '/static/app.js') {
        res.writeHead(200, { 'content-type': 'application/javascript' });
        res.end("document.getElementById('static-loaded').textContent='loaded';");
        return;
      }
      if (req.url === '/api/whoami') { context.sendJson(res, 200, { user }); return; }
      context.sendHtml(res, 200, `<!doctype html><html><head><meta charset="utf-8">
        ${context.RANDOM_UUID_POLYFILL}${context.TAB_SESSION_SNIPPET}${context.USER_BADGE_SNIPPET}
        </head><body style="padding:120px 24px;font-family:system-ui">
        <h1>Hub isolated browser check</h1><p>Document user: <b id="document-user">${user}</b></p>
        <p>HTTP user: <b id="http-user">loading</b></p><p>WebSocket user: <b id="ws-user">loading</b></p>
        <p>Native static script: <b id="static-loaded">loading</b></p><script src="/static/app.js"></script>
        <button id="navigate">SPA navigation</button><button id="set-shared-cookie">Set legacy cookie to bob</button>
        <script>
        fetch('/api/whoami').then(r=>r.json()).then(d=>document.getElementById('http-user').textContent=d.user);
        var socket=new WebSocket('ws://'+location.host+'/whoami');
        socket.onmessage=e=>document.getElementById('ws-user').textContent=JSON.parse(e.data).user;
        document.getElementById('navigate').onclick=()=>history.replaceState({},'', '/room/demo');
        document.getElementById('set-shared-cookie').onclick=()=>fetch('/__fixture/cookie/bob').then(()=>document.getElementById('set-shared-cookie').textContent='Legacy cookie is bob');
        </script></body></html>`, { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
    } catch (error) { res.writeHead(500); res.end(error.message); }
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
  });
  server.on('upgrade', (req, socket, head) => {
    const user = context.prepareUpgrade(req, socket, head);
    if (!user) return;
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    const payload = Buffer.from(JSON.stringify({ user }));
    socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
    socket.on('data', (data) => { if ((data[0] & 15) === 8) socket.end(Buffer.from([0x88, 0])); });
  });
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    cookieFor: (user) => `dshhub_session=${context.makeCookie(user)}`,
    close: async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); },
  };
}
