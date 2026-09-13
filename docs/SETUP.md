# Setup Guide — step by step (as actually built)

This guide reflects the **real deployment**: origin on **Railway**, domain `clouddemo.cc.cd`
(free subdomain from a DNS-hosting provider), Cloudflare Free plan throughout.

Live endpoints:

| What | URL |
|---|---|
| Application (proxied, WAF + rate limiting) | `https://www.clouddemo.cc.cd/` |
| Origin via Cloudflare Tunnel | `https://tunnel.clouddemo.cc.cd/` |
| Worker: identity page / flags | `https://www.clouddemo.cc.cd/secure` · `/flags/:CC` · `/flags-d1/:CC` |

---

## Part 1 — Application Services

### 1.1 Deploy the origin on Railway

1. Push this repository to GitHub, then in [Railway](https://railway.app): **New Project →
   Deploy from GitHub repo**.
2. Service **Settings → Networking → Public Networking → Generate Domain**. Railway detects
   the listening port automatically (it injects `PORT=8080`; the app logs
   `[server] listening on 0.0.0.0:8080`). You get `https://<app>.up.railway.app`.
3. Smoke test: `curl https://<app>.up.railway.app/healthz` → `{"ok":true,...}`.

### 1.2 Put the domain behind Cloudflare

1. Cloudflare → **Add a domain** → `clouddemo.cc.cd` → Free plan.
2. At the domain provider's panel, switch the **NS records** to the two Cloudflare
   nameservers. Wait for the zone to become **Active**
   (`dig NS clouddemo.cc.cd +short` shows `*.ns.cloudflare.com`).

### 1.3 Publish the app on `www` — custom domain (the Error 1000 story)

A plain CNAME `www → <app>.up.railway.app` (orange cloud) works **only if** the platform
domain is not itself behind Cloudflare. (On Render, `*.onrender.com` resolves into
`cdn.cloudflare.net`, and proxying Cloudflare→Cloudflare fails with **Error 1000 — "DNS
points to prohibited IP"**. Railway is fine, but it needs to *know* the hostname.)

Railway's supported way to serve a proxied custom domain:

1. Railway → Service **Settings → Networking → Custom Domain** → add `www.clouddemo.cc.cd`.
2. Railway shows a **dedicated CNAME target** (e.g. `kay0oo0w.up.railway.app` — not the
   public app domain!) and a **TXT verification record**.
3. In Cloudflare DNS add:
   - `CNAME` `www` → the Railway-provided target, **Proxied (orange cloud)**
   - `TXT` `_railway-verify.www` → `railway-verify=<token from the Railway dialog>`
4. Railway verifies within a minute or two and issues the TLS certificate. Because the TXT
   record proves ownership, **the proxy can stay orange the whole time**.

Verify:

```bash
curl -sI https://www.clouddemo.cc.cd | grep -iE "HTTP|cf-ray|server"
# HTTP/2 200 · cf-ray: … · server: cloudflare
```

### 1.4 TLS — encryption mode

**SSL/TLS → Overview → Full (strict)** (+ enable *Always Use HTTPS*). Railway serves a valid
certificate for the custom domain, so strict validation works with zero configuration.
*Flexible* would leave the Cloudflare→origin leg in plaintext; the browser padlock would be
cosmetic. Compliance (PCI-DSS, HIPAA) assumes the whole path is encrypted.

### 1.5 WAF — Managed Ruleset + SQL injection demo

1. **Security → WAF → Managed rules**: confirm the *Cloudflare Free Managed Ruleset* is
   **Enabled** (Free plan ships it on by default).
2. Add a **custom rule** for a deterministic demo (Security → WAF → Custom rules → Create):
   - Expression:
     ```
     http.request.uri.query contains "%20OR%201%3D1" or http.request.uri.query contains "%20UNION%20SELECT" or http.request.uri.query contains "sleep("
     ```
   - Action: **Block**.
   - Note: the ruleset language matches the **raw (still URL-encoded) query string**, and on
     this plan `lower()`/`url.decode()` are not available in the editor — so the rule matches
     the encoded shapes the payloads actually travel in (`' OR 1=1 --` → `q=%27%20OR%201%3D1%20--`).
3. Demonstrate:
   ```bash
   curl -sI "https://www.clouddemo.cc.cd/search?q=%27%20OR%201%3D1%20--"     # → 403 (edge)
   curl -sI "https://www.clouddemo.cc.cd/search?q=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%20email%20FROM%20users%20--"   # → 403
   curl -s -o /dev/null -w "%{http_code}\n" "https://www.clouddemo.cc.cd/search?q=hoodie"   # → 200
   ```
   Via the tunnel hostname (or with the WAF rule disabled) the same payload executes on the
   origin and dumps every row — the before/after contrast is the demo. Security → Events
   shows the blocked requests with the matched rule.

### 1.6 Rate limiting

**Security → WAF → Rate limiting rules → Create rule** (Free plan includes one):

- Match: `URI Path equals /api/login`
- With the same characteristics: **IP source address**
- When rate exceeds **10 requests in 10 seconds** → **Block for 1 minute**

Demo — the "Fire 20 requests" button on `https://www.clouddemo.cc.cd/login`, or:

```bash
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " -X POST https://www.clouddemo.cc.cd/api/login; done
# 401 401 401 401 401 401 401 401 401 429 429 429 429 429 429 429 401 429 429 429
```

The first nine responses are the origin's JSON 401; after the threshold Cloudflare answers
429 and the origin sees nothing. (The lone 401 near the end is the sliding window expiring —
a nice detail to point out in the demo.)

### 1.7 No bypassing Cloudflare — IP check + shared secret

Two layers in `lib/cf-only.js` (`REQUIRE_CLOUDFLARE=true` on Railway):

1. **Peer-IP check**: walk `X-Forwarded-For` from the right (the unforgeable side) and allow
   only Cloudflare IP ranges or loopback (the tunnel).
2. **Shared-secret header** — necessary on Railway: its edge normalises `X-Forwarded-For` to
   the *original visitor IP*, so the Cloudflare edge IP never appears and rule 1 alone would
   block legitimate proxied traffic. Fix:
   - Cloudflare → **Rules → Transform Rules → Modify Request Header** → rule on all incoming
     requests: **Set static** header `X-Origin-Secret` = a long random value. (Cloudflare
     force-overwrites the header, and reserves the `x-cf-` prefix for itself — use another name.)
   - Railway variable `CF_SHARED_SECRET` = the same value.
   - The middleware then accepts requests carrying the matching secret; a direct visitor
     cannot know it.

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://<app>.up.railway.app/    # → 403 (direct)
curl -s -o /dev/null -w "%{http_code}\n" https://www.clouddemo.cc.cd/     # → 200 (via CF)
```

In production, prefer network-level controls: origin firewall allowlisting Cloudflare IPs,
Authenticated Origin Pulls (mTLS), or tunnel-only reachability.

---

## Part 2 — Zero Trust

### 2.1 Cloudflare Tunnel on the origin

1. Zero Trust → **Networks → Tunnels → Create a tunnel → Cloudflared**, name `origin-tunnel`;
   copy the **token**.
2. Railway → Variables → `TUNNEL_TOKEN` = token (redeploys automatically). The app downloads
   `cloudflared` at install time and runs it as a supervised child process (`lib/tunnel.js`);
   logs show `[cloudflared] … Registered tunnel connection` ×4 and the dashboard shows
   **HEALTHY**.
3. Tunnel → **Public Hostname** → Add: subdomain `tunnel`, domain `clouddemo.cc.cd`,
   service **HTTP** `localhost:8080` — the port must match the app's log line, *not* 3000.
4. Verify: `curl -s -o /dev/null -w "%{http_code}\n" https://tunnel.clouddemo.cc.cd/` → 200.

### 2.2 SSO IdP

Zero Trust → **Settings → Authentication → Login methods → Add → One-time PIN** (email +
code, zero external dependencies; Google/GitHub OAuth are drop-in alternatives).

### 2.3 Lock down `/secure`

Two self-hosted Access applications with the same policy — one per hostname:

1. `tunnel.clouddemo.cc.cd/secure` (protects the origin page)
2. `www.clouddemo.cc.cd/secure` (protects the Worker route from Part 3)

Policy (one Include rule, selectors are OR-ed): **Emails = your address** OR
**Email domain = `cloudflare.com`**.

Demo: incognito → `https://tunnel.clouddemo.cc.cd/secure` → Access login (OTP) → the origin
page greets you via `cf-access-authenticated-user-email`. Uninvited visitors get the Access
login page and never reach the origin. Copy the **AUD tag** of the `www` application for Part 3.

---

## Part 3 — Developer Platform (Worker + R2 + D1)

From `worker/`, after `npm install` and `npx wrangler login`:

```bash
# 1. Private R2 bucket (activate R2 once in the dashboard first)
npx wrangler r2 bucket create ase-flags
cd .. && bash scripts/download-flags.sh && node scripts/upload-r2.js   # 257 flags → flags/<cc>.svg
cd worker

# 2. D1 database — paste database_id into wrangler.toml
npx wrangler d1 create ase-flags-db
npx wrangler d1 execute FLAGS_DB --file ../scripts/schema.sql --remote
cd .. && node scripts/make-d1-seed.js && bash scripts/load-d1.sh       # → Rows: 257 (expected 257)
cd worker

# 3. Access identity in wrangler.toml [vars]:
#    ACCESS_TEAM_DOMAIN = "<team>.cloudflareaccess.com"   (Zero Trust → Settings → Custom Pages)
#    ACCESS_AUD         = "<AUD of the www /secure Access app>"

# 4. Deploy with routes (already in wrangler.toml)
npx wrangler deploy
```

JWT verification notes (learned the hard way): the Access JWT this team issues is **RS256**
(support both it and ES256), and Workers' WebCrypto requires the **hash to be stated
explicitly** when importing/verifying RSASSA-PKCS1-v1_5 keys — otherwise `TypeError: Missing
field "hash" in "algorithm"`.

End-to-end test: incognito → `https://www.clouddemo.cc.cd/secure` → OTP login → the page
renders `<email> authenticated at <timestamp> from <COUNTRY>` with the country linking to
`/flags/<COUNTRY>` (R2) and `/flags-d1/<COUNTRY>` (D1). Response header `x-flag-source`
tells you which store served the image.

---

## Troubleshooting (all of these were actually hit)

| Symptom | Cause / Fix |
|---|---|
| **Error 1000 — DNS points to prohibited IP** | Proxied CNAME ultimately resolves into Cloudflare's own network (e.g. Render's `*.onrender.com` → `cdn.cloudflare.net`). Use Railway's Custom Domain flow (dedicated CNAME + TXT verification), or a tunnel. |
| `"Application not found"` JSON 404 from `*.up.railway.app` | Railway doesn't know your hostname yet — register it as a Custom Domain. |
| WAF rule deploys but never matches | The ruleset language matches the **raw encoded** query string; `lower()`/`url.decode()` may not be available. Match encoded fragments (`%20OR%201%3D1`). |
| Everything 403 after `REQUIRE_CLOUDFLARE=true` | On Railway, XFF shows the visitor IP, not the Cloudflare edge — configure the shared-secret Transform Rule + `CF_SHARED_SECRET`. |
| Tunnel 502 Bad Gateway | Public hostname targets the wrong port — match `localhost:<PORT>` to the app's log line (8080 on Railway, not 3000). |
| `/secure` shows "unsupported alg RS256" | Worker only accepted ES256 — support both algorithms. |
| Error 1101 / `Missing field "hash" in "algorithm"` | Workers' WebCrypto needs `{name:"RSASSA-PKCS1-v1_5", hash:"SHA-256"}` on import/verify. |
| `SQLITE_TOOBIG` loading D1 | D1 caps statements ~100KB; Serbia's flag SVG alone is 181KB — the seed script chunks and assembles rows via `UPDATE … content || '…'`. |
| R2 uploads fail sporadically | Transient API errors under concurrency — `scripts/upload-r2.js` retries each object 3×; re-run, it's idempotent. |
