# VX Rate Limiter — WordPress security plugin

Stop brute-force logins, form spam and data scraping on WordPress with **per-IP sliding-window rate limits** for logins, AJAX actions and REST API routes.

![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759B?logo=wordpress&logoColor=white) ![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?logo=php&logoColor=white) ![License](https://img.shields.io/badge/license-GPL--2.0--or--later-blue)

## Why

Many sites expose a custom lookup, search or quote form through `admin-ajax.php` or the REST API. Without limits, a bot can call it thousands of times and download your whole database. This plugin adds rate limits **before** your code runs, so blocked requests never reach the database.

## Features

- 🔐 **Login protection** — lock out an IP after N failed logins in a time window (default 5 per 15 min)
- ⚙️ **AJAX limits per action** — e.g. `serial_lookup=3/1` (3 requests per minute)
- 🌐 **REST API limits** — a global limit for guests plus per-route limits (`/myplugin/v1/lookup=10/60`)
- ✅ **Allowlist / ⛔ blocklist** — single IPs or IPv4 CIDR ranges
- ☁️ **Cloudflare / proxy aware** — optionally trusts `CF-Connecting-IP` / `X-Forwarded-For` (off by default to prevent spoofing)
- 📋 **Lockout log** — see which IPs hit which rule
- 🧠 **Sliding window** stored in transients — works with Redis/Memcached object caches automatically
- Returns proper **HTTP 429** with `Retry-After`

## Installation

1. Copy the folder to `wp-content/plugins/` (or upload as ZIP) and activate **VX Rate Limiter**.
2. Go to **Settings → Rate Limiter**.
3. **Add your own IP to the allowlist first**, then set your limits.

## Example configuration

| Setting | Value | Meaning |
|---|---|---|
| Failed logins | `5/15` | 5 failed attempts per 15 minutes |
| REST API (guests) | `60/1` | 60 requests per minute |
| AJAX actions | `serial_lookup=3/1` | 3 lookups per minute per IP |
| REST routes | `/wc/store/v1/cart=30/1` | 30 cart requests per minute |

## How it works

```
request ─► blocklist? ─► 429
        └► allowlist? ─► allow
        └► count hits for (rule, IP) in the last N minutes
              ├─ under limit ─► record hit ─► your code runs
              └─ over limit  ─► log + 429 (your code never runs)
```

## License

GPL-2.0-or-later

---

Built by **[Vortaxis Studio](https://vortaxis.com)** — WordPress security, performance & custom development, UK.
