// dsh-hub — a JupyterHub-style front for DeepSeek Harness (dsh).
//
// Architecture (mirrors JupyterHub):
//   Authenticator  — PAM (system accounts), login page, HMAC-signed cookie and per-tab sessions
//   Spawner        — on first authenticated request, spawn `dsh web --port <N>`
//                    as that OS user (uid/gid), with DSH_HOME isolated per user,
//                    plus an iptables loopback owner-guard so OTHER local users
//                    cannot reach the unauthenticated dsh port.
//   Proxy          — routes HTTP + WebSocket by cookie or per-tab session to the user's backend
//                    (single shared hostname; no path rewriting needed).
//   Culler         — stops idle backends after IDLE_CULL_MS and removes guards.
//
// dsh itself is NOT modified — it stays on 127.0.0.1, single-user, untouched,
// so upstream upgrades and plugin installs keep working.
//
// Run as root (systemd) for PAM + setuid + iptables. Non-root runs in degraded
// dev mode (no setuid spawn, no iptables guard, PAM may fail without shadow access).

import http from 'node:http';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { networkInterfaces } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import httpProxy from 'http-proxy';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- config ----

function int(v, dflt) { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : dflt; }
function intOrZero(v, dflt) { const n = Number(v); return Number.isInteger(n) && n >= 0 ? n : dflt; }

// Trust modes:
//  - 'origin-rewrite' (default): proxy rewrites Host (changeOrigin) and Origin
//    to loopback; CSRF protection is carried by the hub's SameSite=Lax cookie.
//    This is the ONLY mode that works behind a loopback-binding proxy: dsh's
//    RPC host empties trustedHosts for loopback-authority /api channels
//    (rpc-host.ts: `authority === 'loopback' ? [] : trustedHosts`), so
//    --trusted-host cannot grant non-loopback Hosts there.
//  - 'trusted-host': spawn dsh with its official `--trusted-host` flag and
//    forward Host/Origin untouched. Only works when the fence actually feeds
//    the flag to the channel (direct LAN binds), kept for future dsh support
//    of proxied deployments.
const TRUST_MODE = process.env.TRUST_MODE === 'trusted-host' ? 'trusted-host' : 'origin-rewrite';

function lanIpv4s() {
  return Object.values(networkInterfaces()).flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
    .map((i) => i.address);
}

const TRUSTED_HOSTS = [
  ...lanIpv4s(),
  ...(process.env.TRUSTED_HOSTS ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
];

function detectDshBin() {
  if (process.env.DSH_BIN) return process.env.DSH_BIN;
  const candidates = [
    path.join(process.cwd(), 'deepseek-harness/apps/cli/lib/bin.js'),
    path.resolve(__dirname, '../../deepseek-harness/apps/cli/lib/bin.js'),
    '/usr/local/lib/dsh/apps/cli/lib/bin.js',
  ];
  for (const c of candidates) {
    try { fs.accessSync(c, fs.constants.X_OK); return c; } catch { /* next */ }
  }
  console.error(
    '[hub] FATAL: dsh binary not found. Set DSH_BIN to the dsh CLI entry\n' +
    '[hub] (a built checkout: <repo>/apps/cli/lib/bin.js). Detected candidates:\n' +
    candidates.map((c) => `        ${c}`).join('\n'));
  process.exit(1);
}

const CFG = {
  hubHost: process.env.HUB_HOST ?? '0.0.0.0',
  hubPort: int(process.env.HUB_PORT, 3080),
  dshBin: detectDshBin(),
  sessionTtlMs: int(process.env.SESSION_TTL_MS, 7 * 24 * 3600 * 1000),
  // 0 disables culling entirely — backends keep running with the browser
  // closed, JupyterHub/tmux-style. Pick a positive value to reap idle ones.
  idleCullMs: intOrZero(process.env.IDLE_CULL_MS, 4 * 3600 * 1000),
  spawnTimeoutMs: int(process.env.SPAWN_TIMEOUT_MS, 60_000),
  cookieName: 'dshhub_session',
  // Optional comma-separated allow-list of usernames. Empty = all system users.
  allowUsers: (process.env.ALLOW_USERS ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
  userBadge: process.env.HUB_USER_BADGE === '1',
  logDir: process.env.HUB_LOG_DIR ?? '/var/log/dsh-hub',
};

const TAB_SESSION_HEADER = 'x-dsh-hub-session';
const TAB_SESSION_QUERY = '__dsh_hub_session';
const TAB_SESSION_STORAGE_KEY = 'dsh-hub-tab-session-v1';

const IS_ROOT = process.getuid?.() === 0;
const IPTABLES = IS_ROOT && hasBin('iptables');

function hasBin(name) {
  const { statSync } = fs;
  for (const dir of ['/usr/sbin', '/usr/bin', '/sbin', '/bin']) {
    try { statSync(`${dir}/${name}`); return true; } catch { /* keep looking */ }
  }
  return false;
}

// ----------------------------------------------------------- cookie secret --

const SECRET_PATH = process.env.COOKIE_SECRET_FILE ?? path.join(__dirname, '..', '.cookie-secret');
let SECRET;
{
  try {
    SECRET = fs.readFileSync(SECRET_PATH);
  } catch {
    SECRET = crypto.randomBytes(32);
    fs.writeFileSync(SECRET_PATH, SECRET, { mode: 0o600 });
  }
}

function sign(user, exp) {
  return crypto.createHmac('sha256', SECRET).update(`${user}.${exp}`).digest('base64url');
}

function makeCookie(user) {
  const exp = Date.now() + CFG.sessionTtlMs;
  return `${user}.${exp}.${sign(user, exp)}`;
}

function parseCookie(req) {
  const raw = req.headers.cookie ?? '';
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === CFG.cookieName) return rest.join('=');
  }
  return null;
}

function sessionUser(req) {
  const tabSession = req.headers[TAB_SESSION_HEADER];
  if (typeof tabSession === 'string' && tabSession) return parseTabSession(tabSession);
  const val = parseCookie(req);
  if (!val) return null;
  const m = /^(.+)\.(\d+)\.(.+)$/.exec(val);
  if (!m) return null;
  const [, user, expStr, sig] = m;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  const expect = sign(user, exp);
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return user;
}

function makeTabSession(user) {
  const exp = Date.now() + CFG.sessionTtlMs;
  const nonce = crypto.randomBytes(12).toString('base64url');
  const payload = `${user}.${exp}.${nonce}`;
  const sig = crypto.createHmac('sha256', SECRET).update(`tab.${payload}`).digest('base64url');
  return `${payload}.${sig}`;
}

function parseTabSession(token) {
  const m = /^([a-z_][a-z0-9_-]{0,31})\.(\d+)\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})$/i.exec(token);
  if (!m) return null;
  const [, user, expStr, nonce, sig] = m;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  const payload = `${user}.${exp}.${nonce}`;
  const expected = crypto.createHmac('sha256', SECRET).update(`tab.${payload}`).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return user;
}

// ------------------------------------------------------------- user lookup --

const passwdCache = new Map(); // user -> {uid, gid, home, shell} | null

function lookupUser(user) {
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user)) return null;
  if (passwdCache.has(user)) return passwdCache.get(user);
  let info = null;
  try {
    const out = execFileSync('getent', ['passwd', user], { timeout: 3000 }).toString();
    const [name, , uid, gid, , home, shell] = out.trim().split(':');
    if (name === user) info = { uid: +uid, gid: +gid, home, shell };
  } catch { /* unknown user */ }
  passwdCache.set(user, info);
  return info;
}

// ----------------------------------------------------------------- PAM ------

const LOGIN_ATTEMPTS = new Map(); // ip -> {count, until}
function rateLimited(ip) {
  const now = Date.now();
  const rec = LOGIN_ATTEMPTS.get(ip);
  if (!rec) return false;
  if (rec.until > now) return true;
  if (rec.until !== 0 && rec.until <= now) LOGIN_ATTEMPTS.delete(ip);
  return false;
}
function recordFailure(ip) {
  const rec = LOGIN_ATTEMPTS.get(ip) ?? { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= 5) { rec.until = Date.now() + 60_000; rec.count = 0; }
  LOGIN_ATTEMPTS.set(ip, rec);
}

// Two PAM paths:
//  1. native `authenticate-pam` (optionalDependency; needs libpam0g-dev to build)
//  2. `su` fallback: spawn `su <user> -c 'exit 0'` as an unprivileged uid —
//     su then verifies the TARGET user's password through PAM. Zero native
//     deps; failed attempts land in the normal auth log.
let pamNative = null;
try { pamNative = (await import('authenticate-pam')).default; } catch { /* optional */ }

function pamAuthenticate(user, password) {
  if (pamNative) {
    return new Promise((resolve) => {
      pamNative.authenticate(user, password, (err) => resolve(!err));
    });
  }
  return new Promise((resolve) => {
    const opts = { stdio: ['pipe', 'ignore', 'ignore'] };
    if (IS_ROOT) opts.uid = 65534; // nobody: non-root su prompts via PAM
    const child = spawn('su', [user, '-c', 'exit 0'], opts);
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false); }, 10_000);
    child.on('error', () => finish(false));
    child.on('exit', (code) => finish(code === 0));
    child.stdin.write(`${password}\n`);
    child.stdin.end();
  });
}

// -------------------------------------------------------------- backends ----

/** @type {Map<string, Backend>} */
const backends = new Map();

class Backend {
  constructor(user, info, port) {
    this.user = user;
    this.info = info;
    this.port = port;
    this.child = null;
    this.ready = null;      // promise resolved when TCP accepts
    this.lastActivity = Date.now();
    this.starting = false;
    this.launchUrl = null;
    this.authCookie = '';
  }
}

function randomFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function waitTcp(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    (function tryOnce() {
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => { sock.destroy(); resolve(); });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) reject(new Error(`backend did not come up within ${timeoutMs}ms`));
        else setTimeout(tryOnce, 300);
      });
    })();
  });
}

function redactLaunchToken(text) {
  return text.replace(/([?&]token=)[^&#\s]+/gu, '$1[REDACTED]');
}

// DSH >= 0.1.2 requires a per-process launch-token exchange before serving its UI.
function captureDshLaunchUrl(child, expectedPort, log, timeoutMs) {
  return new Promise((resolve, reject) => {
    let pending = '';
    let settled = false;
    const finish = (err, url) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(url);
    };
    const consumeLine = (line) => {
      const match = /\bdsh web:\s+(https?:\/\/\S+)/u.exec(line);
      if (match) {
        try {
          const url = new URL(match[1]);
          const tokens = url.searchParams.getAll('token');
          if (url.protocol === 'http:' && url.hostname === '127.0.0.1'
              && Number(url.port) === expectedPort && tokens.length === 1 && tokens[0]) {
            finish(null, url);
          }
        } catch { /* ignore unrelated startup output */ }
      }
      if (log !== 'ignore') log.write(`${redactLaunchToken(line)}\n`);
    };
    const timer = setTimeout(() => {
      finish(new Error(`dsh did not publish its authenticated launch URL within ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      pending += chunk;
      let newline;
      while ((newline = pending.indexOf('\n')) !== -1) {
        const line = pending.slice(0, newline).replace(/\r$/u, '');
        pending = pending.slice(newline + 1);
        consumeLine(line);
      }
    });
    child.stdout.once('end', () => { if (pending) consumeLine(pending); });
    child.once('error', (err) => finish(err));
    child.once('exit', (code, signal) => {
      if (!settled) finish(new Error(`dsh exited before publishing its launch URL (code=${code} signal=${signal})`));
    });
  });
}

function exchangeDshLaunchToken(launchUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err, cookie) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(cookie);
    };
    const req = http.request({
      hostname: launchUrl.hostname,
      port: Number(launchUrl.port),
      method: 'GET',
      path: `${launchUrl.pathname}${launchUrl.search}`,
      headers: { host: launchUrl.host, connection: 'close' },
    }, (res) => {
      const setCookies = res.headers['set-cookie'];
      const cookiePairs = (Array.isArray(setCookies) ? setCookies : setCookies ? [setCookies] : [])
        .map((value) => value.split(';', 1)[0].trim())
        .filter((value) => value.includes('='));
      res.resume();
      res.once('end', () => {
        if (res.statusCode !== 303 || cookiePairs.length === 0) {
          finish(new Error(`dsh launch-token exchange failed (HTTP ${res.statusCode})`));
          return;
        }
        finish(null, cookiePairs.join('; '));
      });
    });
    const timer = setTimeout(() => req.destroy(new Error('dsh launch-token exchange timed out')), timeoutMs);
    req.once('error', (err) => finish(err));
    req.end();
  });
}

function backendCookieHeader(be, incomingCookie) {
  const authPairs = String(be.authCookie ?? '').split(';').map((part) => part.trim()).filter((part) => part.includes('='));
  const authNames = new Set(authPairs.map((part) => part.slice(0, part.indexOf('=')).trim()));
  const callerPairs = String(incomingCookie ?? '').split(';').map((part) => part.trim()).filter((part) => {
    const equals = part.indexOf('=');
    if (equals < 1) return false;
    const name = part.slice(0, equals).trim();
    return name !== CFG.cookieName && !authNames.has(name);
  });
  const merged = [...callerPairs, ...authPairs].join('; ');
  return merged || undefined;
}

// iptables loopback owner-guard: only the backend's own uid (and root) may
// connect to the backend port on lo. Other local users get DROPped. This closes
// the "dsh has no auth and loopback is shared" hole on multi-user machines.
function addGuard(port, uid) {
  if (!IPTABLES) return;
  // Insert in reverse so final order is: ACCEPT(root), ACCEPT(uid), DROP.
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-j', 'DROP']);
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT']);
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT']);
}
function removeGuard(port, uid) {
  if (!IPTABLES) return;
  for (const args of [
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-j', 'DROP'],
  ]) {
    try {
      const bin = fs.existsSync('/usr/sbin/iptables') ? '/usr/sbin/iptables' : '/usr/bin/iptables';
      execFileSync(bin, ['-D', 'OUTPUT', ...args], { stdio: 'ignore', timeout: 5000 });
    } catch { /* already gone */ }
  }
}
function runIptables(args, tolerate = false) {
  const bin = '/usr/sbin/iptables';
  try {
    execFileSync(fs.existsSync(bin) ? bin : '/usr/bin/iptables', args, { stdio: 'ignore', timeout: 5000 });
  } catch (err) {
    if (!tolerate) console.error('[hub] iptables failed:', args.join(' '), err.message);
  }
}

function logStreamFor(user) {
  try {
    fs.mkdirSync(CFG.logDir, { recursive: true });
    fs.accessSync(CFG.logDir, fs.constants.W_OK);
    const stream = fs.createWriteStream(path.join(CFG.logDir, `${user}.log`), { flags: 'a' });
    stream.on('error', (e) => console.error(`[hub] backend log for ${user} unavailable:`, e.message));
    return stream;
  } catch {
    return 'ignore';
  }
}

async function getOrCreateBackend(user) {
  let be = backends.get(user);
  if (be?.starting && be.ready) {
    await be.ready;
    return be;
  }
  if (be && be.child && be.child.exitCode === null) return be;

  const info = lookupUser(user);
  if (!info) throw new Error(`unknown system user: ${user}`);
  if (CFG.allowUsers.length && !CFG.allowUsers.includes(user)) {
    throw new Error(`user ${user} is not on the allow-list`);
  }

  const port = await randomFreePort();
  be = new Backend(user, info, port);
  be.starting = true;
  backends.set(user, be);

  const home = info.home;
  const env = {
    HOME: home,
    DSH_HOME: path.join(home, '.dsh'),   // per-user data root: sessions, keys, settings
    PATH: '/usr/local/bin:/usr/bin:/bin',
    LANG: process.env.LANG ?? 'en_US.UTF-8',
    TERM: 'xterm-256color',
    DSH_HUB_API_KEY: (() => {
      try { return fs.readFileSync('/var/lib/dsh-hub/dsh-hub-api-key-api-key', 'utf8').trim(); }
      catch { return ''; }
    })(),
  };

  // Per-user default workspace: if ~/.dsh/hub-default-workspace names an
  // existing directory, spawn the backend there instead of home. The dsh web
  // sidebar is workspace-scoped, so landing in the user's data workspace makes
  // their sessions visible immediately (no directory-picker navigation, which
  // cannot traverse home symlinks).
  let cwd = home;
  try {
    const dflt = fs.readFileSync(path.join(home, '.dsh', 'hub-default-workspace'), 'utf8').trim();
    if (dflt && fs.statSync(dflt).isDirectory()) cwd = dflt;
  } catch { /* no default workspace configured — keep home */ }

  const opts = {
    cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  };
  if (IS_ROOT) { opts.uid = info.uid; opts.gid = info.gid; }
  else console.warn('[hub] non-root: spawning dsh as hub user (dev mode, no isolation)');

  console.log(`[hub] spawning dsh for ${user} (uid ${info.uid}) on 127.0.0.1:${port}, DSH_HOME=${env.DSH_HOME}`);
  const args = [CFG.dshBin, 'web', '--port', String(port)];
  if (TRUST_MODE === 'trusted-host') {
    for (const authority of TRUSTED_HOSTS) args.push('--trusted-host', authority);
  }
  const child = spawn(process.execPath, args, opts);
  be.child = child;
  const log = logStreamFor(user);
  const launchUrlReady = captureDshLaunchUrl(child, port, log, CFG.spawnTimeoutMs);
  if (log !== 'ignore') child.stderr.pipe(log, { end: false });
  else child.stderr.resume();

  addGuard(port, info.uid);

  child.once('exit', (code, signal) => {
    console.log(`[hub] dsh for ${user} exited (code=${code} signal=${signal})`);
    removeGuard(port, info.uid);
    if (backends.get(user) === be) backends.delete(user);
  });

  be.ready = launchUrlReady.then(async (launchUrl) => {
    be.launchUrl = launchUrl;
    await waitTcp(port, CFG.spawnTimeoutMs);
    be.authCookie = await exchangeDshLaunchToken(launchUrl, CFG.spawnTimeoutMs);
  }).finally(() => { be.starting = false; });
  try {
    await be.ready;
  } catch (err) {
    be.child?.kill('SIGTERM');
    setTimeout(() => be.child?.kill('SIGKILL'), 5000).unref();
    throw err;
  }
  prewarmSessionList(user, be); // warm the session-list cache after DSH browser auth
  return be;
}

async function stopBackend(user) {
  const be = backends.get(user);
  if (!be) return;
  console.log(`[hub] culling dsh for ${user} (port ${be.port})`);
  be.child?.kill('SIGTERM');
  setTimeout(() => be.child?.kill('SIGKILL'), 5000).unref();
}

// Idle culler. 0 = never cull (JupyterHub-style always-on backends; the
// browser-closed conversation keeps running indefinitely, tmux-style).
if (CFG.idleCullMs > 0) {
  setInterval(() => {
    const now = Date.now();
    for (const [user, be] of backends) {
      if (now - be.lastActivity > CFG.idleCullMs) stopBackend(user);
    }
  }, 60_000).unref();
}

// ---------------------------------------------------------------- proxy -----

// dsh's web UI calls the browser-global `crypto.randomUUID()` (e.g. provider
// catalog / draft attachments). Browsers only expose that API in SECURE
// contexts (https or localhost), so bare `http://<server-ip>:3080` breaks with
// "crypto.randomUUID is not a function". `crypto.getRandomValues` IS available
// in insecure contexts, so we inject a complete v4-UUID polyfill into every
// proxied HTML page — no dsh modification needed, upgrades keep working.
const RANDOM_UUID_POLYFILL = `<script>(function(){
if (typeof crypto!=='undefined'&&typeof crypto.randomUUID==='function')return;
function uuid4(){
  var b=crypto.getRandomValues(new Uint8Array(16));
  b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;
  var s='';for(var i=0;i<16;i++)s+=b[i].toString(16).padStart(2,'0');
  return s.slice(0,8)+'-'+s.slice(8,12)+'-'+s.slice(12,16)+'-'+s.slice(16,20)+'-'+s.slice(20);
}
try{Object.defineProperty(crypto,'randomUUID',{value:uuid4,writable:true,configurable:true});}
catch(e){try{crypto.randomUUID=uuid4;}catch(e2){}}
})();</script>`;

// Cookies are shared by every tab in a browser profile. Give each tab its own
// signed session token in sessionStorage and attach it to same-origin requests.
// The Hub strips these credentials before forwarding requests to dsh.
const TAB_SESSION_SNIPPET = `<script>(function(){
var storageKey='${TAB_SESSION_STORAGE_KEY}';
var headerName='${TAB_SESSION_HEADER}';
var queryName='${TAB_SESSION_QUERY}';
function readToken(){try{return sessionStorage.getItem(storageKey)||'';}catch(e){return '';}}
function writeToken(value){try{if(value)sessionStorage.setItem(storageKey,value);else sessionStorage.removeItem(storageKey);}catch(e){}}
function sameOrigin(value){try{return new URL(value instanceof Request?value.url:value,location.href).origin===location.origin;}catch(e){return false;}}
if(!window.__dshHubTabSessionWrapped){
  window.__dshHubTabSessionWrapped=true;
  if(typeof window.fetch==='function'){
    var nativeFetch=window.fetch;
    window.fetch=function(input,init){
      var token=readToken();
      if(!token||!sameOrigin(input)||(input instanceof Request&&input.mode==='no-cors')||(init&&init.mode==='no-cors'))return nativeFetch.apply(this,arguments);
      var headers=new Headers(input instanceof Request?input.headers:undefined);
      if(init&&init.headers)new Headers(init.headers).forEach(function(v,k){headers.set(k,v);});
      headers.set(headerName,token);
      return nativeFetch.call(this,input,Object.assign({},init||{},{headers:headers}));
    };
  }
  if(window.XMLHttpRequest){
    var xhrOpen=XMLHttpRequest.prototype.open,xhrSend=XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open=function(method,url){this.__dshHubSameOrigin=sameOrigin(url);return xhrOpen.apply(this,arguments);};
    XMLHttpRequest.prototype.send=function(){var token=readToken();if(token&&this.__dshHubSameOrigin)try{this.setRequestHeader(headerName,token);}catch(e){}return xhrSend.apply(this,arguments);};
  }
  if(window.WebSocket){
    var NativeWebSocket=window.WebSocket;
    function HubWebSocket(url,protocols){
      var token=readToken(),target=url;
      if(token)try{
        var parsed=new URL(url,location.href);
        if(parsed.host===location.host&&(parsed.protocol==='ws:'||parsed.protocol==='wss:'||parsed.protocol==='http:'||parsed.protocol==='https:')){
          if(parsed.protocol==='http:')parsed.protocol='ws:';
          if(parsed.protocol==='https:')parsed.protocol='wss:';
          parsed.searchParams.set(queryName,token);target=parsed.href;
        }
      }catch(e){}
      return protocols===undefined?new NativeWebSocket(target):new NativeWebSocket(target,protocols);
    }
    HubWebSocket.prototype=NativeWebSocket.prototype;
    try{Object.setPrototypeOf(HubWebSocket,NativeWebSocket);}catch(e){}
    window.WebSocket=HubWebSocket;
  }
}
window.__dshHubTabSessionReady=fetch('/hub/me',{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}})
  .then(function(r){if(!r.ok)throw new Error('session lookup failed');return r.json();})
  .then(function(data){if(data&&typeof data.tabSession==='string'&&data.tabSession)writeToken(data.tabSession);else if(readToken())writeToken('');return data;})
  .catch(function(){return null;});
})();</script>`;

const USER_BADGE_SNIPPET = CFG.userBadge ? `<style id="dsh-hub-user-badge-style">
#dsh-hub-user-badge{position:fixed!important;left:12px;top:12px;right:auto!important;bottom:auto!important;z-index:2147483647!important;display:flex;flex-direction:column;align-items:stretch;gap:0;padding:4px;border:1px solid rgba(15,23,42,.12);border-radius:12px;background:rgba(255,255,255,.96);box-shadow:0 3px 12px rgba(15,23,42,.1);backdrop-filter:blur(10px);cursor:grab;touch-action:none;user-select:none;-webkit-user-select:none}
#dsh-hub-user-badge.dsh-hub-dragging{cursor:grabbing}
#dsh-hub-user-badge a,#dsh-hub-user-badge span{box-sizing:border-box;display:block;max-width:200px;color:#1f2937!important;font:600 12px/1.25 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:inherit}
#dsh-hub-user-badge a{padding:5px 9px;border-radius:8px;text-decoration:none!important;white-space:pre-line;text-align:center;line-height:1.15;transition:background .15s ease}
#dsh-hub-user-badge a:hover{background:#f1f5f9}
#dsh-hub-user-badge span{padding:5px 9px;border-top:1px solid rgba(15,23,42,.1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#dsh-hub-user-badge span[hidden]{display:none}
@media(prefers-color-scheme:dark){
#dsh-hub-user-badge{background:rgba(24,27,33,.96);border-color:rgba(255,255,255,.14);box-shadow:0 3px 12px rgba(0,0,0,.3)}
#dsh-hub-user-badge a,#dsh-hub-user-badge span{color:#f3f4f6!important}
#dsh-hub-user-badge a:hover{background:rgba(255,255,255,.09)}
#dsh-hub-user-badge span{border-top-color:rgba(255,255,255,.14)}
}</style><script>(function(){
var id='dsh-hub-user-badge';
var positionKey='dsh-hub-user-badge-position-v1';
function mount(){
  if(!document.body)return false;
  var badge=document.getElementById(id);
  if(badge){if(badge.parentNode!==document.body)document.body.appendChild(badge);return true;}
  badge=document.createElement('div');badge.id=id;
  badge.title='按住徽章拖动可移动位置';
  var link=document.createElement('a');link.href='/hub/tab-login';link.textContent='切换\\n用户';
  link.addEventListener('click',function(){try{sessionStorage.setItem('dsh-hub-tab-return',location.pathname+location.search+location.hash);}catch(e){}});
  var label=document.createElement('span');label.hidden=true;label.setAttribute('aria-label','当前用户名');
  badge.appendChild(link);badge.appendChild(label);document.body.appendChild(badge);

  function place(x,y){
    var maxX=Math.max(4,window.innerWidth-badge.offsetWidth-4);
    var maxY=Math.max(4,window.innerHeight-badge.offsetHeight-4);
    badge.style.left=Math.max(4,Math.min(maxX,x))+'px';
    badge.style.top=Math.max(4,Math.min(maxY,y))+'px';
  }
  function savePosition(){
    try{var r=badge.getBoundingClientRect();localStorage.setItem(positionKey,JSON.stringify({x:r.left,y:r.top}));}catch(e){}
  }
  function keepVisible(){
    var r=badge.getBoundingClientRect();place(r.left,r.top);savePosition();
  }
  try{
    var saved=JSON.parse(localStorage.getItem(positionKey)||'null');
    if(saved&&Number.isFinite(saved.x)&&Number.isFinite(saved.y))place(saved.x,saved.y);
  }catch(e){}

  var active=null;
  var suppressClickUntil=0;
  function move(e){
    if(!active||e.pointerId!==active.pointerId)return;
    var dx=e.clientX-active.x,dy=e.clientY-active.y;
    if(!active.moved&&Math.hypot(dx,dy)<4)return;
    if(!active.moved){
      active.moved=true;
      if(badge.setPointerCapture)try{badge.setPointerCapture(e.pointerId);}catch(err){}
    }
    place(active.left+dx,active.top+dy);
    if(e.cancelable)e.preventDefault();
  }
  function finish(e){
    if(!active||e.pointerId!==active.pointerId)return;
    var moved=active.moved;
    active=null;
    badge.classList.remove('dsh-hub-dragging');
    window.removeEventListener('pointermove',move);
    window.removeEventListener('pointerup',finish);
    window.removeEventListener('pointercancel',finish);
    if(moved){savePosition();suppressClickUntil=Date.now()+800;}
  }
  badge.addEventListener('pointerdown',function(e){
    suppressClickUntil=0;
    if(active||e.isPrimary===false||(e.pointerType==='mouse'&&e.button!==0))return;
    var r=badge.getBoundingClientRect();
    active={pointerId:e.pointerId,x:e.clientX,y:e.clientY,left:r.left,top:r.top,moved:false};
    badge.classList.add('dsh-hub-dragging');
    window.addEventListener('pointermove',move,{passive:false});
    window.addEventListener('pointerup',finish);
    window.addEventListener('pointercancel',finish);
  });
  document.addEventListener('click',function(e){
    if(Date.now()>suppressClickUntil)return;
    suppressClickUntil=0;
    e.preventDefault();e.stopImmediatePropagation();
  },true);
  window.addEventListener('resize',keepVisible);

  Promise.resolve(window.__dshHubTabSessionReady)
    .then(function(data){if(data&&typeof data.user==='string'&&data.user){label.textContent=data.user;label.hidden=false;keepVisible();}})
    .catch(function(){});
  return true;
}
if(mount())return;
if(!document.documentElement){document.addEventListener('DOMContentLoaded',mount,{once:true});return;}
var observer=new MutationObserver(function(){if(mount())observer.disconnect();});
observer.observe(document.documentElement,{childList:true,subtree:true});
})();</script>` : '';

// dsh's settings/credentials plane is browser-gated: connection.isLoopback is
// computed from location.hostname (packages/client/connection), so a page
// served from a LAN hostname reports "settings are unavailable in this
// browser" even though the hub's origin-rewrite already passes the server-side
// loopback fence. Location members are [LegacyUnforgeable] (own non-
// configurable accessors on the location instance), so no polyfill can spoof
// them — instead we patch the served connection plugin bundle in flight:
//
//   isLoopback: pageLocation === void 0 || isLoopbackHostname(pageLocation.hostname),
//   → isLoopback: true,
//
// The trust boundary moves to the hub exactly like origin-rewrite: the PAM
// session cookie or signed tab session decides who reaches the backend at all. The patch is
// pattern-based against the unminified bundle and FAILS LOUD (startup log) if
// upstream renames the expression, so upgrades surface immediately instead of
// silently regressing settings.
const CONNECTION_LOOPBACK_PATCH = /isLoopback:[^,\n]*isLoopbackHostname\([^)]*\)/;
const patchedJsCache = new Map(); // url+etag -> patched body
let loopbackPatchMissing = false;

const proxy = httpProxy.createProxyServer({
  ws: true,
  // trusted-host mode keeps the browser's real Host so dsh's own fence (fed by
  // --trusted-host at spawn) makes the decision. origin-rewrite mode masquerades
  // as a loopback same-origin client instead.
  changeOrigin: TRUST_MODE === 'origin-rewrite',
  proxyTimeout: 120_000,
  selfHandleResponse: true, // we own the response so we can rewrite HTML
});

proxy.on('proxyRes', (proxyRes, req, res) => {
  const ct = String(proxyRes.headers['content-type'] ?? '');
  const url = String(req.url ?? '');
  // Plugin bundles: patch the connection client's isLoopback gate in flight.
  const isPluginJs = /^\/plugins\/.+\.js(\?|$)/.test(url);
  if (isPluginJs) {
    const chunks = [];
    proxyRes.on('data', (c) => chunks.push(c));
    proxyRes.on('error', () => res.destroy());
    proxyRes.on('end', () => {
      const headers = { ...proxyRes.headers };
      const cacheKey = `${url}|${String(headers.etag ?? '')}`;
      const cached = patchedJsCache.get(cacheKey);
      let body = cached;
      if (body === undefined) {
        let js = Buffer.concat(chunks).toString('utf-8');
        if (CONNECTION_LOOPBACK_PATCH.test(js)) {
          js = js.replace(CONNECTION_LOOPBACK_PATCH, 'isLoopback: true');
          console.log(`[hub] patched connection isLoopback gate in ${url.split('?')[0]}`);
        } else if (/isLoopback/.test(js) && !loopbackPatchMissing) {
          loopbackPatchMissing = true;
          console.warn(`[hub] WARNING: ${url.split('?')[0]} mentions isLoopback but the patch pattern did not match — settings will report "unavailable in this browser". Update CONNECTION_LOOPBACK_PATCH for this dsh version.`);
        }
        body = Buffer.from(js, 'utf-8');
        if (patchedJsCache.size > 64) patchedJsCache.clear();
        patchedJsCache.set(cacheKey, body);
      }
      delete headers['content-length'];
      delete headers['content-encoding'];
      res.writeHead(proxyRes.statusCode, headers);
      res.end(body);
    });
    return;
  }
  if (!/text\/html/i.test(ct)) {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
    return;
  }
  const chunks = [];
  proxyRes.on('data', (c) => chunks.push(c));
  proxyRes.on('error', () => res.destroy());
  proxyRes.on('end', () => {
    const headers = { ...proxyRes.headers };
    delete headers['content-length'];
    delete headers['content-encoding'];
    delete headers['etag'];
    delete headers['last-modified'];
    headers['cache-control'] = 'no-store';
    res.writeHead(proxyRes.statusCode, headers);
    const html = Buffer.concat(chunks).toString('utf-8');
    const injected = /<head[^>]*>/i.test(html)
      ? html.replace(/<head[^>]*>/i, (m) => m + RANDOM_UUID_POLYFILL + TAB_SESSION_SNIPPET + USER_BADGE_SNIPPET)
      : RANDOM_UUID_POLYFILL + TAB_SESSION_SNIPPET + USER_BADGE_SNIPPET + html;
    res.end(Buffer.from(injected, 'utf-8'));
  });
});

proxy.on('error', (err, req, res) => {
  console.error('[hub] proxy error:', err.message);
  if (res instanceof http.ServerResponse) {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('dsh-hub: backend unavailable\n');
  } else if (res?.destroy) {
    res.destroy();
  }
});

// ---------------------------------------------------------------- pages -----

function sendHtml(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

function sendJson(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store, no-cache, must-revalidate, private',
    pragma: 'no-cache',
    expires: '0',
  });
  res.end(JSON.stringify(body));
}

const LOGIN_PAGE = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dsh-hub login</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background: #101418; color: #e6e6e6;
         display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .card { background: #1a2027; padding: 2.2rem 2.6rem; border-radius: 12px; width: 22rem;
          box-shadow: 0 8px 40px rgba(0,0,0,.45); }
  h1 { font-size: 1.25rem; margin: 0 0 .3rem; }
  p.sub { color: #8b97a3; font-size: .85rem; margin: 0 0 1.6rem; }
  label { display: block; font-size: .8rem; color: #8b97a3; margin: .9rem 0 .25rem; }
  input { width: 100%; box-sizing: border-box; padding: .55rem .7rem; border-radius: 8px;
          border: 1px solid #2c3641; background: #101418; color: inherit; font-size: .95rem; }
  button { margin-top: 1.5rem; width: 100%; padding: .6rem; border: 0; border-radius: 8px;
           background: #3b82f6; color: #fff; font-size: .95rem; cursor: pointer; }
  button:hover { background: #2f6fe0; }
  .err { color: #f87171; font-size: .85rem; min-height: 1.2em; margin-top: 1rem; }
</style>
</head>
<body>
  <form class="card" method="post" action="/hub/login">
    <h1>DeepSeek Harness</h1>
    <p class="sub">使用服务器系统账号登录(每用户独立隔离实例)</p>
    <label for="u">用户名</label>
    <input id="u" name="username" autocomplete="username" autofocus required>
    <label for="p">密码</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
    <div class="err">__MSG__</div>
    <button type="submit">登录</button>
  </form>
</body>
</html>`;

const TAB_LOGIN_PAGE = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>切换当前标签页用户</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background: #101418; color: #e6e6e6;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #1a2027; padding: 2.2rem 2.6rem; border-radius: 12px; width: min(22rem, calc(100vw - 4rem));
          box-shadow: 0 8px 40px rgba(0,0,0,.45); }
  h1 { font-size: 1.25rem; margin: 0 0 .3rem; }
  p.sub { color: #8b97a3; font-size: .85rem; margin: 0 0 1.6rem; }
  label { display: block; font-size: .8rem; color: #8b97a3; margin: .9rem 0 .25rem; }
  input { width: 100%; box-sizing: border-box; padding: .55rem .7rem; border-radius: 8px;
          border: 1px solid #2c3641; background: #101418; color: inherit; font-size: .95rem; }
  button { margin-top: 1.5rem; width: 100%; padding: .6rem; border: 0; border-radius: 8px;
           background: #3b82f6; color: #fff; font-size: .95rem; cursor: pointer; }
  .err { color: #f87171; font-size: .85rem; min-height: 1.2em; margin-top: 1rem; }
  .back { display: block; margin-top: 1rem; color: #aab4c0; text-align: center; font-size: .9rem; }
</style>
</head>
<body>
  <form class="card" id="tab-login-form">
    <h1>切换当前标签页用户</h1>
    <p class="sub">只切换这个标签页，不影响其他标签页。</p>
    <label for="tab-login-u">用户名</label>
    <input id="tab-login-u" name="username" autocomplete="username" autofocus required>
    <label for="tab-login-p">密码</label>
    <input id="tab-login-p" name="password" type="password" autocomplete="current-password" required>
    <div class="err" id="tab-login-error" role="status"></div>
    <button type="submit">登录并切换</button>
    <a class="back" href="/">返回</a>
  </form>
<script>
(function(){
  var form=document.getElementById('tab-login-form'),error=document.getElementById('tab-login-error');
  form.addEventListener('submit',function(e){
    e.preventDefault();
    var button=form.querySelector('button');button.disabled=true;error.textContent='';
    fetch('/hub/tab-login',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},body:new URLSearchParams(new FormData(form)).toString()})
      .then(function(r){return r.json().then(function(data){if(!r.ok)throw new Error(data.error||'登录失败');return data;});})
      .then(function(data){sessionStorage.setItem('${TAB_SESSION_STORAGE_KEY}',data.tabSession);form.querySelector('[type=password]').value='';var back='/';try{var saved=sessionStorage.getItem('dsh-hub-tab-return');if(saved&&saved.charAt(0)==='/'&&saved.slice(0,2)!=='//')back=saved;sessionStorage.removeItem('dsh-hub-tab-return');}catch(e){}location.replace(back);})
      .catch(function(err){error.textContent=err.message||'登录失败';button.disabled=false;});
  });
})();
</script>
</body>
</html>`;

// -------------------------------------------------------------- handlers ----

function clientIp(req) {
  return req.socket.remoteAddress ?? '?';
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function urlencoded(body) {
  const params = new URLSearchParams(body);
  return { username: params.get('username') ?? '', password: params.get('password') ?? '' };
}

async function handleLogin(req, res) {
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    sendHtml(res, 429, LOGIN_PAGE.replace('__MSG__', '尝试过多,请 1 分钟后再试'));
    return;
  }
  const { username, password } = urlencoded(await readBody(req));
  if (!username || !password) {
    sendHtml(res, 401, LOGIN_PAGE.replace('__MSG__', '请输入用户名和密码'));
    return;
  }
  const info = lookupUser(username);
  const ok = info && await pamAuthenticate(username, password)
    && !(CFG.allowUsers.length && !CFG.allowUsers.includes(username));
  if (!ok) {
    recordFailure(ip);
    sendHtml(res, 401, LOGIN_PAGE.replace('__MSG__', '用户名或密码错误'));
    return;
  }
  const token = makeCookie(username);
  res.writeHead(303, {
    'set-cookie': `${CFG.cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(CFG.sessionTtlMs / 1000)}`,
    location: '/',
  });
  res.end();
}

async function handleTabLogin(req, res) {
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    sendJson(res, 429, { error: '尝试过多，请 1 分钟后再试' });
    return;
  }
  const { username, password } = urlencoded(await readBody(req));
  if (!username || !password) {
    sendJson(res, 400, { error: '请输入用户名和密码' });
    return;
  }
  const info = lookupUser(username);
  const ok = info && await pamAuthenticate(username, password)
    && !(CFG.allowUsers.length && !CFG.allowUsers.includes(username));
  if (!ok) {
    recordFailure(ip);
    sendJson(res, 401, { error: '用户名或密码错误' });
    return;
  }
  sendJson(res, 200, { user: username, tabSession: makeTabSession(username) });
}

function handleLogout(req, res) {
  res.writeHead(303, {
    'set-cookie': `${CFG.cookieName}=; Path=/; HttpOnly; Max-Age=0`,
    location: '/hub/login',
  });
  res.end();
}

const STARTING_PAGE = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="3"><title>starting…</title>
<style>body{font-family:system-ui;background:#101418;color:#e6e6e6;display:flex;
justify-content:center;padding-top:12rem}p{color:#8b97a3}</style></head>
<body><p>正在为你的账号启动 dsh 实例,首次约需 10 秒,即将自动刷新…</p></body></html>`;

// ------------------------------------------- /api/session.list response cache --
// dsh's session.list recomputes projections for every session (zstd-decode of
// large logs + projection apply); on this deployment it routinely takes
// 40-66s — far past the web client's 30s unary timeout, so the sidebar renders
// no history whenever the cache is cold. This cache makes the sidebar always
// instant: once a 200 response exists for a key it is served forever
// (serve-stale), with one throttled background revalidation refreshing it.
// A cached hit never spawns the backend, so idle culling keeps working.
// Revalidation failures keep the stale entry and back off, so a dead backend
// never empties the sidebar. Only 200 responses are cached; keys are per
// user + request-body hash so different payloads never mix.
const SESSION_LIST_PATH = '/api/session.list';
const RPC_CACHE_REVALIDATE_MS = 60_000;   // min gap between background refreshes (12MB responses; keep the hub event loop free)
const RPC_CACHE_FAIL_BACKOFF_MS = 30_000; // pause after a failed refresh
const rpcCache = new Map(); // key -> { status, headers, body, nextRevalidateAt, inflight }
const RPC_CACHE_MAX = 500;
const prewarmInflight = new Set();
// Cache survives hub restarts: entries persist under <hub>/cache/session-list-<hash>.json.
const CACHE_DIR = path.join(__dirname, '..', 'cache');
const CACHE_PERSIST_GAP_MS = 300_000;     // throttle disk writes per key (16MB base64 files; async, off the hot path)
const STANDARD_SESSION_LIST_BODY = Buffer.from(JSON.stringify({
  type: 'client-request', rpcId: 'hub-prewarm', method: 'session.list', payload: {},
}));

function sessionListCacheKey(user, body) {
  // Hash only the payload (not rpcId), so hub prewarm and browser requests share a key.
  let payload = body;
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    if (parsed !== null && typeof parsed === 'object' && 'payload' in parsed) {
      payload = Buffer.from(JSON.stringify(parsed.payload));
    }
  } catch {
    /* keep full-body hash */
  }
  const hash = crypto.createHash('sha256').update(payload).digest('hex').slice(0, 16);
  return `${user}:session.list:${hash}`;
}

function cacheFilePathFor(key) {
  return path.join(CACHE_DIR, `${crypto.createHash('sha256').update(key).digest('hex')}.json`);
}

function persistCacheEntry(key, entry) {
  const now = Date.now();
  if (entry.lastPersistAt !== undefined && now - entry.lastPersistAt < CACHE_PERSIST_GAP_MS) return;
  // Async write: a 16MB base64 payload must never block the event loop — the
  // hub proxies the browser's WebSocket event streams, and a sync disk write
  // here stalls them long enough to break the app's 3s readiness handshake.
  entry.lastPersistAt = now;
  fs.promises.mkdir(CACHE_DIR, { recursive: true })
    .then(() => fs.promises.writeFile(cacheFilePathFor(key), JSON.stringify({
      key,
      status: entry.status,
      contentType: entry.headers['content-type'] ?? 'application/json',
      bodyB64: entry.body.toString('base64'),
      nextRevalidateAt: entry.nextRevalidateAt,
    })))
    .catch((err) => console.error('[hub] session.list cache persist failed:', err.message));
}

function loadPersistedCache() {
  try {
    const files = fs.readdirSync(CACHE_DIR).filter((f) => f.endsWith('.json'));
    files.sort((a, b) => {
      const sa = fs.statSync(path.join(CACHE_DIR, a)).mtimeMs;
      const sb = fs.statSync(path.join(CACHE_DIR, b)).mtimeMs;
      return sa - sb;
    });
    const keep = files.slice(-RPC_CACHE_MAX);
    for (const file of files) {
      if (!keep.includes(file)) {
        try { fs.unlinkSync(path.join(CACHE_DIR, file)); } catch { /* best-effort */ }
      }
    }
    for (const file of keep) {
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(CACHE_DIR, file), 'utf8'));
        if (typeof raw.key !== 'string' || typeof raw.bodyB64 !== 'string' || raw.status !== 200) continue;
        rpcCache.set(raw.key, {
          status: raw.status,
          headers: { 'content-type': raw.contentType },
          body: Buffer.from(raw.bodyB64, 'base64'),
          nextRevalidateAt: raw.nextRevalidateAt ?? 0, // past → revalidate on first hit
          inflight: false,
        });
      } catch (err) {
        console.error('[hub] session.list cache load failed for', file, err.message);
      }
    }
  } catch (err) {
    if (err.code !== 'ENOENT') console.error('[hub] session.list cache dir read failed:', err.message);
  }
  if (rpcCache.size > 0) console.log(`[hub] loaded ${rpcCache.size} persisted session.list cache entries`);
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sanitizeForwardHeaders(headers, bePort) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (key === TAB_SESSION_HEADER
        || ['connection', 'transfer-encoding', 'upgrade', 'keep-alive', 'proxy-connection', 'te', 'content-length', 'host'].includes(key)) continue;
    out[k] = v;
  }
  out.host = `127.0.0.1:${bePort}`;
  return out;
}

function forwardSessionList(be, headers, body) {
  return new Promise((resolve, reject) => {
    const requestHeaders = sanitizeForwardHeaders(headers, be.port);
    const cookie = backendCookieHeader(be, headers.cookie);
    if (cookie) requestHeaders.cookie = cookie;
    else delete requestHeaders.cookie;
    const req = http.request({
      host: '127.0.0.1',
      port: be.port,
      method: 'POST',
      path: SESSION_LIST_PATH,
      headers: { ...requestHeaders, 'content-length': body.length, connection: 'close' },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

function serveCachedSessionList(res, entry) {
  if (res.destroyed || res.writableEnded) return;
  try {
    res.writeHead(entry.status, {
      'content-type': entry.headers['content-type'] ?? 'application/json',
      'content-length': entry.body.length,
    });
    res.end(entry.body);
  } catch {
    /* client already gone — nothing to serve */
  }
}

/** A cacheable session.list payload: non-empty 200 whose envelope parses and carries an items array. */
function isCacheableSessionList(captured) {
  if (captured.status !== 200 || captured.body.length === 0) return false;
  try {
    const parsed = JSON.parse(captured.body.toString('utf8'));
    return parsed?.result?.ok === true && Array.isArray(parsed.result.value?.items);
  } catch {
    return false;
  }
}

async function revalidateSessionList(user, be, body, key) {
  const now = Date.now();
  try {
    const captured = await forwardSessionList(be, { accept: 'application/json', 'content-type': 'application/json' }, body);
    if (isCacheableSessionList(captured)) {
      const entry = { ...captured, nextRevalidateAt: now + RPC_CACHE_REVALIDATE_MS, inflight: false };
      rpcCache.set(key, entry);
      persistCacheEntry(key, entry);
    } else {
      // Half-started backends answer 200 with an empty/partial body; never
      // let that clobber a good snapshot — keep the old entry and back off.
      const entry = rpcCache.get(key);
      if (entry) entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
    }
  } catch (err) {
    console.error(`[hub] session.list revalidate failed for ${user}:`, err.message);
    // Keep serving the stale snapshot; back off so a dead backend is not hammered.
    const entry = rpcCache.get(key);
    if (entry) entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
  } finally {
    const entry = rpcCache.get(key);
    if (entry) entry.inflight = false;
  }
}

/** Warm the session-list cache right after a backend spawn, without a browser request. */
function prewarmSessionList(user, be) {
  const key = sessionListCacheKey(user, STANDARD_SESSION_LIST_BODY);
  if (rpcCache.has(key) || prewarmInflight.has(key)) return;
  prewarmInflight.add(key);
  revalidateSessionList(user, be, STANDARD_SESSION_LIST_BODY, key)
    .catch((err) => console.error(`[hub] session.list prewarm failed for ${user}:`, err.message))
    .finally(() => prewarmInflight.delete(key));
}

async function route(req, res) {
  const url = new URL(req.url, 'http://x');
  url.searchParams.delete(TAB_SESSION_QUERY);
  req.url = `${url.pathname}${url.search}`;

  if (url.pathname === '/hub/login' && req.method === 'GET') {
    sendHtml(res, 200, LOGIN_PAGE.replace('__MSG__', ''));
    return;
  }
  if (url.pathname === '/hub/tab-login' && req.method === 'GET') {
    sendHtml(res, 200, TAB_LOGIN_PAGE, { 'cache-control': 'no-store' });
    return;
  }
  if (url.pathname === '/hub/tab-login' && req.method === 'POST') {
    await handleTabLogin(req, res);
    return;
  }
  if (url.pathname === '/hub/tab-login') {
    res.writeHead(405, { allow: 'GET, POST' });
    res.end('Method Not Allowed');
    return;
  }
  if (url.pathname === '/hub/login' && req.method === 'POST') {
    await handleLogin(req, res);
    return;
  }
  if (url.pathname === '/hub/me' && req.method === 'GET') {
    const user = sessionUser(req);
    const tabSession = user
      ? (req.headers[TAB_SESSION_HEADER] || makeTabSession(user))
      : null;
    sendJson(res, 200, { user, tabSession });
    return;
  }
  if (url.pathname === '/hub/logout') {
    handleLogout(req, res);
    return;
  }

  const user = sessionUser(req);
  if (!user) {
    res.writeHead(303, { location: '/hub/login' });
    res.end();
    return;
  }
  if (!lookupUser(user)) {  // account deleted since login
    handleLogout(req, res);
    return;
  }
  delete req.headers[TAB_SESSION_HEADER];

  // Session-list RPC cache: serve the last known snapshot forever (serve-stale),
  // refresh it in the background on a throttle (see block above).
  if (req.method === 'POST' && url.pathname === SESSION_LIST_PATH) {
    const body = await readRequestBody(req);
    const key = sessionListCacheKey(user, body);
    const entry = rpcCache.get(key);
    const now = Date.now();
    if (entry) {
      serveCachedSessionList(res, entry);
      if (now >= entry.nextRevalidateAt && !entry.inflight) {
        entry.inflight = true;
        const be = backends.get(user);
        if (be?.port) {
          revalidateSessionList(user, be, body, key).catch((err) =>
            console.error(`[hub] session.list revalidate failed for ${user}:`, err.message));
        } else {
          entry.inflight = false;
          entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
        }
      }
      return;
    }
    // No snapshot yet: forward (capturing), cache 200s, respond.
    let be;
    try {
      be = await getOrCreateBackend(user);
    } catch (err) {
      console.error(`[hub] spawn failed for ${user}:`, err.message);
      sendHtml(res, 503, `<pre>dsh-hub: 无法启动你的实例\n${err.message}</pre>`);
      return;
    }
    be.lastActivity = Date.now();
    req.headers.origin = `http://127.0.0.1:${be.port}`;
    req.headers['accept-encoding'] = 'identity';
    let captured;
    try {
      captured = await forwardSessionList(be, req.headers, body);
    } catch (err) {
      // Backend died between spawn and forward (cull/restart race): fall back
      // to the streaming proxy, which re-triggers the spawn-on-demand path.
      console.error(`[hub] session.list forward failed for ${user}:`, err.message);
      req.headers.cookie = backendCookieHeader(be, req.headers.cookie);
      proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
      return;
    }
    if (isCacheableSessionList(captured)) {
      if (rpcCache.size >= RPC_CACHE_MAX) {
        const oldest = rpcCache.keys().next().value;
        if (oldest !== undefined) rpcCache.delete(oldest);
      }
      const entry = {
        ...captured,
        nextRevalidateAt: now + RPC_CACHE_REVALIDATE_MS,
        inflight: false,
      };
      rpcCache.set(key, entry);
      persistCacheEntry(key, entry);
    }
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(captured.status, {
      'content-type': captured.headers['content-type'] ?? 'application/json',
      'content-length': captured.body.length,
    });
    res.end(captured.body);
    return;
  }

  // Fast path: spawn already in progress — show the "starting" page instead
  // of blocking the request for the full spawn duration.
  const existing = backends.get(user);
  if (existing?.starting) {
    sendHtml(res, 200, STARTING_PAGE);
    return;
  }

  let be;
  try {
    be = await getOrCreateBackend(user);
  } catch (err) {
    console.error(`[hub] spawn failed for ${user}:`, err.message);
    sendHtml(res, 503, `<pre>dsh-hub: 无法启动你的实例\n${err.message}</pre>`);
    return;
  }
  be.lastActivity = Date.now();
  if (TRUST_MODE === 'origin-rewrite') {
    // Legacy fallback: align Origin with the loopback Host changeOrigin sends;
    // cross-site protection is carried by the hub's SameSite cookie instead.
    // Also inject Origin when the browser omitted it entirely (service-worker
    // or extension re-fetches drop Origin/Sec-Fetch-* headers): plugin guards
    // like task-board's browser-marker check need one of the two, and this
    // request already passed the hub's PAM cookie authentication.
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  // Hub auth is handled above; add this user's DSH browser cookie before proxying.
  req.headers.cookie = backendCookieHeader(be, req.headers.cookie);
  // Force identity encoding so the HTML rewrite below sees plain text.
  req.headers['accept-encoding'] = 'identity';
  if (String(req.headers.accept ?? '').includes('text/html')) {
    delete req.headers['if-none-match'];
    delete req.headers['if-modified-since'];
  }
  proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
}

loadPersistedCache(); // restore session-list cache entries across hub restarts

const server = http.createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error('[hub] handler error:', err);
    if (!res.headersSent) res.writeHead(500);
    res.end('dsh-hub: internal error');
  });
});

// WebSocket upgrade (dsh event streams) — routed by the same cookie/tab session as HTTP.
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  const tabTokens = url.searchParams.getAll(TAB_SESSION_QUERY);
  if (tabTokens.length) req.headers[TAB_SESSION_HEADER] = tabTokens.length === 1 ? tabTokens[0] : 'invalid';
  url.searchParams.delete(TAB_SESSION_QUERY);
  req.url = `${url.pathname}${url.search}`;
  const user = sessionUser(req);
  if (!user) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  delete req.headers[TAB_SESSION_HEADER];
  const be = backends.get(user);
  if (!be || !be.child || be.child.exitCode !== null) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
    socket.destroy();
    return;
  }
  be.lastActivity = Date.now();
  if (TRUST_MODE === 'origin-rewrite') {
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  const backendCookie = backendCookieHeader(be, req.headers.cookie);
  if (backendCookie) req.headers.cookie = backendCookie;
  else delete req.headers.cookie;
  proxy.ws(req, socket, head, { target: `http://127.0.0.1:${be.port}` });
});

// ------------------------------------------------------------------ boot ----

try { fs.mkdirSync(CFG.logDir, { recursive: true }); } catch { /* non-root dev run */ }
server.listen(CFG.hubPort, CFG.hubHost, () => {
  console.log(`[hub] dsh-hub listening on ${CFG.hubHost}:${CFG.hubPort}`);
  console.log(`[hub] dsh binary: ${CFG.dshBin}`);
  console.log(`[hub] trust mode: ${TRUST_MODE}` +
    (TRUST_MODE === 'trusted-host' ? ` (authorities: ${TRUSTED_HOSTS.join(', ') || 'none detected — set TRUSTED_HOSTS'})` : ''));
  console.log(`[hub] running as ${IS_ROOT ? 'root (full isolation mode)' : `uid ${process.getuid?.()} (dev mode — no setuid/iptables)`}`);
  if (!IPTABLES) console.warn('[hub] WARNING: iptables unavailable — loopback ports of user instances are NOT guarded against other local users');
  if (CFG.allowUsers.length) console.log(`[hub] allow-list: ${CFG.allowUsers.join(', ')}`);
  console.log(CFG.idleCullMs === 0
    ? '[hub] idle culling DISABLED — backends run until stopped'
    : `[hub] idle cull after ${Math.round(CFG.idleCullMs / 60000)} min`);
});

// Clean up per-user backends and loopback firewall guards on service stop.
let shutdownRequested = false;
async function shutdownHub(signal) {
  if (shutdownRequested) return;
  shutdownRequested = true;
  console.log(`[hub] received ${signal}; stopping user backends`);
  server.close();
  const waits = [];
  for (const be of [...backends.values()]) {
    const child = be.child;
    if (!child || child.exitCode !== null) {
      removeGuard(be.port, be.info.uid);
      continue;
    }
    waits.push(new Promise((resolve) => {
      const forceKill = setTimeout(() => child.kill('SIGKILL'), 5000);
      child.once('exit', () => {
        clearTimeout(forceKill);
        removeGuard(be.port, be.info.uid);
        resolve();
      });
      child.kill('SIGTERM');
    }));
  }
  await Promise.all(waits);
  process.exit(0);
}
process.once('SIGTERM', () => { void shutdownHub('SIGTERM'); });
process.once('SIGINT', () => { void shutdownHub('SIGINT'); });
