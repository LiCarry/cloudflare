# Cloudflare ASE Take-Home Assessment

Solution for the **Associate Solutions Engineer** take-home assessment. Everything runs on **free tiers**: origin on Railway, `clouddemo.cc.cd` on the Cloudflare Free plan.

| Part | Topic | Where it lives |
|------|-------|----------------|
| 1 | Application Services — origin on Railway, Cloudflare proxy, TLS, WAF, rate limiting, no direct origin access | `/` (this app) |
| 2 | Zero Trust — Cloudflare Tunnel, One-time-PIN SSO, Access policy on `/secure` | `lib/tunnel.js` + Zero Trust config |
| 3 | Developer Platform — Worker + private R2 bucket + D1 | `worker/` |

**Live**: `https://www.clouddemo.cc.cd` (app) · `/secure` (Worker) · `https://tunnel.clouddemo.cc.cd` (Tunnel)

## Architecture

```
                          ┌────────────────────────── Cloudflare edge ──────────────────────────┐
                          │                                                                      │
 visitor ──https──▶ www.clouddemo.cc.cd ─▶ WAF (managed + custom rules) · rate limiting · Access   │
                          │        │            │                                                 │
                          │        │            ├── / ─ /search /login …  ──── proxied origin ──┼──▶ Railway
                          │        │            ├── /secure /flags/* /flags-d1/* ── Worker ────┤   (Express app)
                          │        │            │                                    │ R2 ⬅ flags   │      │
                          │        │            └── tunnel.clouddemo.cc.cd ─ Cloudflare Tunnel │   D1 ⬅ flags   │ cloudflared
                          │                                     ▲ (outbound-only)         │                │ (child process)
                          └─────────────────────────────────────┴────────────────────────────┘        ▼
                                                                             http://localhost:8080 (same container)
```

- **Origin** (`server.js`): Express app on Railway. Serves the demo pages, a deliberately
  SQL-injectable search, a brute-force-able login endpoint — and blocks any request that did
  not arrive through Cloudflare (`REQUIRE_CLOUDFLARE=true` + shared-secret header, see below).
- **Tunnel** (`lib/tunnel.js`): `cloudflared` runs as a supervised child process on the origin
  and publishes it via an outbound-only connection — no inbound ports needed.
- **Worker** (`worker/src/index.js`): `/secure` verifies the Cloudflare Access JWT
  (RS256/ES256 via WebCrypto against the team JWKS) and renders
  `${EMAIL} authenticated at ${TIMESTAMP} from ${COUNTRY}`; `/flags/:CC` reads a private R2
  bucket via binding; `/flags-d1/:CC` reads D1 via binding. Routes are declared in
  `worker/wrangler.toml`.

## Repository layout

```
├── server.js               # origin app (Part 1 + 2)
├── lib/
│   ├── cf-only.js          # middleware: reject requests that bypass Cloudflare (IP ranges + shared secret)
│   ├── db.js               # in-memory SQLite for the SQLi demo (⚠ intentionally vulnerable)
│   ├── tunnel.js           # runs cloudflared as a child process (TUNNEL_TOKEN)
│   └── install-cloudflared.js
├── worker/
│   ├── wrangler.toml       # R2 + D1 bindings, Access team/AUD vars, routes
│   └── src/index.js        # Worker: /secure, /flags/:CC (R2), /flags-d1/:CC (D1)
├── scripts/
│   ├── download-flags.sh   # fetch flag SVGs (flag-icons) into flag-assets/
│   ├── upload-r2.js        # upload flags to the private R2 bucket (retries)
│   ├── schema.sql          # D1 table
│   ├── make-d1-seed.js     # generate chunked seed SQL (handles >100KB flags)
│   └── load-d1.sh          # load seed into D1 with retries + verify
```

## Quick start (local)

```bash
# Origin
npm install
npm start                      # http://localhost:3000  (REQUIRE_CLOUDFLARE defaults off)

# Worker (needs `npx wrangler login`)
cd worker && npm install
npx wrangler dev               # http://localhost:8787
```

## Environment variables (Railway)

| Variable | Required | Purpose |
|----------|----------|---------|
| `PORT` | auto (Railway) | HTTP port the app binds to (Railway injects 8080) |
| `REQUIRE_CLOUDFLARE` | recommended `true` | 403 any request that did not come through Cloudflare |
| `CF_SHARED_SECRET` | with the above | Value of the `X-Origin-Secret` header set by a Cloudflare Transform Rule — Railway normalises `X-Forwarded-For` to the visitor IP, so the edge IP alone is not visible |
| `TUNNEL_TOKEN` | for Part 2 | Remotely-managed Cloudflare Tunnel token — starts `cloudflared` automatically |

## Demo cheat-sheet (live endpoints)

```bash
# WAF blocks SQLi at the edge (custom rule matches the raw encoded query):
curl -si "https://www.clouddemo.cc.cd/search?q=%27%20OR%201%3D1%20--"      # → 403 (blocked at edge)
curl -si "https://www.clouddemo.cc.cd/search?q=hoodie"                    # → 200 (benign passes)

# Rate limiting trips after a burst (10 req / 10 s per IP → block 1 min):
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " -X POST https://www.clouddemo.cc.cd/api/login; done
# 401 401 401 401 401 401 401 401 401 429 429 …

# Direct origin access is refused:
curl -si https://<app>.up.railway.app/                                    # → 403 "Direct origin access is blocked"

# Worker endpoints (Access-protected /secure; flags are public images):
curl -si https://www.clouddemo.cc.cd/secure                               # → 302 to Access login
curl -si https://www.clouddemo.cc.cd/flags/cn                             # R2  → image/svg+xml
curl -si https://www.clouddemo.cc.cd/flags-d1/cn                          # D1  → image/svg+xml
```

## License

Apache-2.0 (see `LICENSE`). Flag SVGs come from the [flag-icons](https://github.com/lipis/flag-icons) project (MIT).
