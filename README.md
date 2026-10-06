# dsh-hub

## Fork-specific changes / 本 Fork 的修改

This fork is based on [Mpaperlee/dsh-hub](https://github.com/Mpaperlee/dsh-hub) and adds the following changes.

本 Fork 基于上游 [Mpaperlee/dsh-hub](https://github.com/Mpaperlee/dsh-hub)，增加和调整了以下功能。

### Runtime and authentication / 运行与认证

- **Authenticated DSH startup / DSH 启动认证:** The Hub captures DSH's short-lived launch URL, validates it, exchanges its one-time token for a backend session cookie, and redacts the token from logs.
  Hub 捕获并校验 DSH 的短时启动 URL，用一次性令牌换取后端会话 Cookie，并在日志中隐藏令牌。
- **Per-user proxy cookies / 按用户转发 Cookie:** The matching user's backend Cookie is forwarded with that user's HTTP and WebSocket requests.
  代理会在该用户的 HTTP 和 WebSocket 请求中转发对应后端 Cookie。
- **Session-list cache / 会话列表缓存:** Valid session-list responses are persisted; cached results are served quickly while background refresh keeps them current.
  有效的会话列表响应会持久缓存，先快速返回缓存结果，再由后台刷新。
- **Backend lifecycle / 后端生命周期:** Concurrent startup requests share one readiness wait, and shutdown stops child backends and removes their firewall guards.
  并发启动请求会等待同一个就绪流程；服务退出时会停止子后端并清理防火墙规则。

### Draggable user badge / 可拖动用户徽标

Set `HUB_USER_BADGE=1` to show a badge with the signed-in username and a “Switch user” link. The username comes from `/hub/me`; the link opens `/hub/logout`. Drag it with a mouse or touch, and its position is saved in the browser.

设置 `HUB_USER_BADGE=1` 后，会显示当前用户名和“切换用户”入口。用户名由 `/hub/me` 按当前会话读取，入口跳转到 `/hub/logout`。徽标支持鼠标或触屏拖动，位置保存在浏览器中。

### Optional Unsloth key / 可选 Unsloth 密钥

When `/var/lib/dsh-hub/unsloth-api-key` exists, its contents are passed to child DSH processes as `DSH_UNSLOTH_API_KEY`. The key file is not part of this repository and should remain root-only.

如果 `/var/lib/dsh-hub/unsloth-api-key` 存在，Hub 会将其内容作为 `DSH_UNSLOTH_API_KEY` 传给子 DSH 进程。密钥文件不属于本仓库，应仅允许 root 访问。

---


[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-green.svg)](https://nodejs.org)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#)
[![dsh](https://img.shields.io/badge/works%20with-DeepSeek%20Harness%20(dsh)-8A2BE2.svg)](https://github.com/deepseek-ai/deepseek-harness)

A [JupyterHub](https://jupyterhub.readthedocs.io)-style multi-user front for
[DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness) —
PAM login, one isolated dsh instance per system user, and a cookie-routed
HTTP/WebSocket proxy. **Zero modifications to dsh**: upstream upgrades and
per-user plugin installs keep working.

> **中文简介**:[dsh-hub](README.md) 是 [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness) 的多用户网关,思路完全对标
> JupyterHub:服务器系统账号(PAM)登录,每个用户一个完全隔离的 dsh 实例
> (独立 uid/gid、独立数据目录、iptables 端口防护),浏览器直接访问
> `http://<服务器IP>:3080` 即可使用。**不修改 dsh 任何代码**——上游升级、
> 每用户自行安装插件均不受影响。

```
browser ──http://<server-ip>:3080──▶ dsh-hub ──cookie──▶ 127.0.0.1:<port> ──▶ dsh (user A)
                                        │                127.0.0.1:<port> ──▶ dsh (user B)
                                        └─ spawn as uid/gid + iptables owner-guard
```

## Architecture (the JupyterHub analogy)

| JupyterHub | dsh-hub |
|---|---|
| Authenticator (PAM) | PAM via `authenticate-pam` (optional) with a `su`-based fallback; HMAC-signed session cookie |
| Spawner | `dsh web --port <random>` spawned with the user's uid/gid and a per-user `DSH_HOME` |
| Configurable HTTP proxy | `http-proxy` routes HTTP + WebSocket by session cookie |
| Idle culler (jupyterhub-idle-culler) | built-in culler, `IDLE_CULL_MS` (0 = never, tmux-style always-on) |
| Single-user server trusts the hub | loopback proxying with SameSite-cookie CSRF protection (JupyterHub's trust split) |

### Trust model

dsh's web server enforces a browser trust fence (`Origin`/`Host` authority
checks) against DNS-rebinding and CSRF. dsh-hub's proxy (default
`TRUST_MODE=origin-rewrite`) presents itself as a loopback same-origin client:
Host and Origin are rewritten to the backend's loopback authority, and
cross-site protection is carried by the hub's `SameSite=Lax` session cookie —
the same trust split JupyterHub uses between its proxy and single-user servers.

`TRUST_MODE=trusted-host` spawns instances with dsh's official
`--trusted-host` flag and forwards Host/Origin untouched. Note: as of current
dsh, the RPC host empties `trustedHosts` for loopback-authority `/api`
channels, so this mode only works when the fence actually consumes the flag
(direct LAN binds). It is kept for future upstream support of proxied
deployments.

### Insecure-context polyfill

Browsers only expose `crypto.randomUUID()` in secure contexts (HTTPS or
localhost). On bare `http://<server-ip>:3080`, dsh-hub injects a self-guarding
v4-UUID polyfill into every proxied HTML page (a no-op once dsh fixes its
remaining direct call or you serve over HTTPS).

### Remote settings (the isLoopback gate)

dsh's settings/credentials plane (the Settings → Models page) is browser-gated
to loopback pages: `connection.isLoopback` is derived from `location.hostname`,
so a LAN-hostname page reports `settings are unavailable in this browser` even
though the hub's origin-rewrite already passes the server-side loopback fence.
`Location` members are `[LegacyUnforgeable]` own accessors — no polyfill can
spoof them — so dsh-hub instead rewrites the connection plugin bundle in
flight: `isLoopbackHostname(pageLocation.hostname)` becomes `true`. The patch
is pattern-based against dsh's unminified bundle, cached per bundle rev, and
fails loud in the hub log when an upstream upgrade renames the expression.
Trust stays with the hub: only PAM-authenticated users reach the backend at
all, and the SameSite=Lax session cookie still blocks cross-site requests.

### Authenticated dsh launch URLs

Newer dsh versions print a one-time token in their `dsh web:` startup URL. The Hub
captures and validates the loopback URL, exchanges the token for dsh's session
cookie, and attaches that cookie only to the user's proxied HTTP and WebSocket
requests. Token query strings are redacted from startup logs.

### User switch badge

Set `HUB_USER_BADGE=1` to inject the badge into proxied HTML. It gets the current
username from `/hub/me` and links to `/hub/logout`. Drag with a mouse or touch;
the position is saved in that browser. The badge is disabled by default.

### Optional Unsloth key

If `/var/lib/dsh-hub/unsloth-api-key` exists, the Hub passes it to spawned dsh
processes as `DSH_UNSLOTH_API_KEY`. Keep the root-managed key file out of the
repository and restrict its permissions.

## Isolation guarantees (run as root)

- Each dsh instance runs as the user's own **uid/gid** with `DSH_HOME=~/.dsh`
- Instances bind `127.0.0.1:<random port>`; an **iptables owner-guard**
  (loopback, `--uid-owner`) DROPs connections from other local users
- Login rate-limiting (5 failures → 1 min lockout per IP)
- Optional `ALLOW_USERS` allow-list

## Quick start

```bash
git clone https://github.com/Mpaperlee/dsh-hub.git /opt/dsh-hub
cd /opt/dsh-hub && npm install

# dev run (no root: no setuid/iptables, single-user semantics)
DSH_BIN=/path/to/deepseek-harness/apps/cli/lib/bin.js HUB_PORT=3080 \
  HUB_LOG_DIR=/tmp npm start
```

Production (root, systemd):

```bash
sudo cp dsh-hub.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now dsh-hub
```

Users browse to `http://<server-ip>:3080`, log in with their **system
username/password**, and get a private dsh instance.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `DSH_BIN` | *(required)* | dsh CLI entry (built checkout: `apps/cli/lib/bin.js`) |
| `HUB_HOST` / `HUB_PORT` | `0.0.0.0` / `3080` | hub listen address |
| `HUB_USER_BADGE` | `0` | Set to `1` to add the draggable user switch badge to proxied HTML |
| `TRUST_MODE` | `origin-rewrite` | `trusted-host` forwards Host/Origin untouched (see trust model above) |
| `TRUSTED_HOSTS` | auto (LAN IPv4s) | extra authorities for `--trusted-host` (hostnames/DNS names) |
| `IDLE_CULL_MS` | `14400000` (4h) | `0` disables culling — backends keep running with the browser closed |
| `SESSION_TTL_MS` | 7 days | cookie lifetime |
| `ALLOW_USERS` | *(all)* | comma-separated username allow-list |
| `HUB_LOG_DIR` | `/var/log/dsh-hub` | per-user backend logs |
| `COOKIE_SECRET_FILE` | `./.cookie-secret` | HMAC secret (auto-generated, `0600`) |

## Notes

- Conversations survive browser close: goal/server-side drivers keep running
  in the spawned dsh process; re-login reattaches to the same instance.
- `sudo systemctl restart dsh-hub` after config changes.
- Non-root runs are degraded (dev) mode: no setuid spawn, no iptables guard.

## License

MIT
