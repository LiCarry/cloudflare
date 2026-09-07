# Cloudflare ASE Take-Home Assessment

Solution for the **Associate Solutions Engineer** take-home assessment. Everything runs on **free tiers only**.

| Part | Topic | Where it lives |
|------|-------|----------------|
| 1 | Application Services — origin on Render, Cloudflare proxy, TLS, WAF, rate limiting, no direct origin access | `/` (this app) |
| 2 | Zero Trust — Cloudflare Tunnel, SSO IdP, Access policy on `/secure` | `lib/tunnel.js` + Zero Trust config |
| 3 | Developer Platform — Worker + private R2 bucket + D1 | `worker/` |

**Full step-by-step setup guide: [`docs/SETUP.md`](docs/SETUP.md)** · Report: [`docs/REPORT.md`](docs/REPORT.md)

## Architecture

```
                          ┌────────────────────────── Cloudflare edge ──────────────────────────┐
                          │                                                                      │
 visitor ──https──▶ yourdomain.com  ──▶ WAF (managed rules) · rate limiting · Access (SSO)       │
                          │        │            │                                                 │
                          │        │            ├── / ─ /search /login …  ──── proxied origin ──┼──▶ Render.com
                          │        │            ├── /secure /flags/* /flags-d1/* ── Worker ────┤      (Express app)
                          │        │            │                                    │ R2 ⬅ flags   │        │
                          │        │            └── tunnel.yourdomain.com ── Cloudflare Tunnel │   D1 ⬅ flags   │ cloudflared
                          │                                     ▲ (outbound-only)         │                │ (child process)
                          └─────────────────────────────────────┴────────────────────────────┘        ▼
                                                                             http://localhost:PORT (same container)
```

- **Origin** (`server.js`): Express app on Render. Serves the demo pages, a deliberately
  SQL-injectable search, a brute-force-able login endpoint, and blocks any request that
  did not arrive through Cloudflare (`REQUIRE_CLOUDFLARE=true`).
- **Tunnel** (`lib/tunnel.js`): `cloudflared` runs as a child process on the origin and
  publishes it via an outbound-only connection — no inbound ports needed.
- **Worker** (`worker/src/index.js`): `/secure` verifies the Cloudflare Access JWT
  (ES256) and renders `${EMAIL} authenticated at ${TIMESTAMP} from ${COUNTRY}`;
  `/flags/:CC` reads a private R2 bucket via binding; `/flags-d1/:CC` reads D1 via binding.

## Repository layout

```
├── server.js               # origin app (Part 1 + 2)
├── lib/
│   ├── cf-only.js          # middleware: reject requests that bypass Cloudflare
│   ├── db.js               # in-memory SQLite for the SQLi demo (⚠ intentionally vulnerable)
│   ├── tunnel.js           # runs cloudflared as a child process (TUNNEL_TOKEN)
│   └── install-cloudflared.js
├── worker/
│   ├── wrangler.toml       # R2 + D1 bindings, Access team/AUD vars
│   └── src/index.js        # Worker: /secure, /flags/:CC (R2), /flags-d1/:CC (D1)
├── scripts/
│   ├── download-flags.sh   # fetch flag SVGs (flag-icons) into flag-assets/
│   ├── upload-r2.js        # upload flags to the private R2 bucket
│   ├── schema.sql          # D1 table
│   ├── make-d1-seed.js     # generate chunked seed SQL (handles >100KB flags)
│   └── load-d1.sh          # load seed into D1 with retries + verify
└── docs/
    ├── SETUP.md            # click-by-click setup guide
    └── REPORT.md           # written report (deliverable #2)
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

## Environment variables (Render)

| Variable | Required | Purpose |
|----------|----------|---------|
| `PORT` | auto (Render) | HTTP port the app binds to |
| `REQUIRE_CLOUDFLARE` | recommended `true` | 403 any request whose network peer is not Cloudflare/loopback |
| `TUNNEL_TOKEN` | for Part 2 | Remotely-managed Cloudflare Tunnel token — starts `cloudflared` automatically |

## Demo cheat-sheet

```bash
# WAF blocks SQLi at the edge (via the Cloudflare-proxied domain):
curl -i "https://YOUR-DOMAIN/search?q=' OR 1=1 --"          # → 403, cf-mitigated-header: block
curl -i "https://YOUR-DOMAIN/search?q=coffee"               # → 200

# Rate limiting trips after a burst:
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " -X POST https://YOUR-DOMAIN/api/login; done

# Direct origin access is refused:
curl -i https://YOUR-APP.onrender.com/                       # → 403 (when REQUIRE_CLOUDFLARE=true)

# Worker endpoints:
curl -i https://YOUR-DOMAIN/flags/cn                        # R2  → image/svg+xml
curl -i https://YOUR-DOMAIN/flags-d1/cn                     # D1  → image/svg+xml
```

## License

Apache-2.0 (see `LICENSE`). Flag SVGs come from the [flag-icons](https://github.com/lipis/flag-icons) project (MIT).
