# Setup Guide — step by step

This guide walks through the entire assessment in order. Replace these placeholders as you go:

| Placeholder | Meaning | Example |
|---|---|---|
| `<your-domain>` | Your domain added to Cloudflare | `example.com` |
| `<app>.onrender.com` | Your Render service URL | `ase-demo.onrender.com` |
| `<team-name>` | Zero Trust team domain | `my-team.cloudflareaccess.com` |

> **Free-tier note:** Render free web services sleep after ~15 min of inactivity and take ~50s
> to cold-start. That is fine for the assessment — just warm it up before demoing.

---

## Part 1 — Application Services

### 1.1 Deploy the origin on Render

1. Push this repository to GitHub (it must be public or connected to Render).
2. On [Render](https://render.com): **New → Web Service → connect the repo**.
3. Settings:
   - **Runtime:** Node (auto-detected from `package.json` at the repo root)
   - **Build command:** `npm install`
   - **Start command:** `npm start`
   - **Instance type:** Free
4. Deploy, then smoke-test: `curl https://<app>.onrender.com/healthz` → `{"ok":true,...}`.
   The homepage renders at `/`, the SQLi demo at `/search`, the rate-limit demo at `/login`.

### 1.2 Put the domain behind Cloudflare (proxy ON)

1. Cloudflare dashboard → **Add a domain** (`<your-domain>`), Free plan. Change the
   nameservers at your registrar as instructed, wait for *Active*.
2. **DNS → Add record**: `CNAME` `www` (or `A @` on the apex) → `<app>.onrender.com`,
   **Proxy status: Proxied (orange cloud)**.
3. Verify traffic flows through Cloudflare:
   ```bash
   curl -sI https://<your-domain> | grep -iE "cf-ray|server"
   # cf-ray: …            ← you are behind Cloudflare
   # server: cloudflare
   ```

### 1.3 TLS between Cloudflare and the origin

**SSL/TLS → Overview → set encryption mode to Full (strict).**

| Mode | Edge→Visitor | CF→Origin | Verdict |
|---|---|---|---|
| Off / Flexible | HTTPS | **plain HTTP** | vulnerable to interception/tampering on the last mile |
| Full | HTTPS | HTTPS, cert **not validated** | MITM with any self-signed cert still possible |
| **Full (strict)** | HTTPS | HTTPS, cert **validated** | ✅ recommended |

Render issues a valid certificate for `*.onrender.com`, so strict validation works with zero
configuration. *Flexible* is the trap: the padlock in the browser means nothing if the last
mile is plaintext — a packet capture between Cloudflare and the origin would show everything.
(Demo: `curl -si http://<your-domain>` shows Cloudflare redirecting to HTTPS; with Flexible the
origin request itself would ride plain HTTP.)

### 1.4 WAF — Managed Rulesets + SQL injection demo

1. **Security → WAF → Managed rules**: enable the **Cloudflare Managed Ruleset** (on the Free
   plan this is the *Cloudflare Free Managed Ruleset*; it is on by default — confirm it shows *Enabled*).
2. Belt-and-braces for the demo, add a **custom rule** (Security → WAF → Custom rules):
   - Expression (use the visual editor or "Edit expression"):
     ```
     (http.request.uri.query contains "union select") or (http.request.uri.query contains "or 1=1") or (http.request.uri.query contains "sleep(")
     ```
   - Action: **Block**.
3. Demonstrate protection:
   ```bash
   # Blocked at the edge — never reaches the origin:
   curl -i "https://<your-domain>/search?q=' OR 1=1 --"
   #    HTTP/1.1 403 Forbidden
   #    cf-mitigated-header: block        ← Cloudflare blocked it
   curl -i "https://<your-domain>/search?q=' UNION SELECT id, username, password, email FROM users --"

   # Benign query passes:
   curl -i "https://<your-domain>/search?q=hoodie"     # HTTP 200
   ```
4. Contrast (what the origin would do without the WAF): open `/search` in a browser via the
   tunnel hostname from Part 2 (or temporarily set `REQUIRE_CLOUDFLARE=false` and use the
   onrender URL) — `q=' OR 1=1 --` dumps every row, the UNION payload leaks usernames and
   passwords. That difference *is* the value of managed rulesets: CVE-grade protections with
   zero code changes and rules maintained by Cloudflare researchers.

### 1.5 Rate limiting

1. **Security → WAF → Rate limiting rules → Create rule** (Free plan includes 1 rule):
   - **If incoming requests match:** `http.request.uri.path eq "/api/login"`
   - **With the same characteristics:** IP source address
   - **When rate exceeds:** 10 requests / 10 seconds
   - **Then take action:** Block · **For duration:** 1 minute
2. Demo — either press the **"Fire 20 requests"** button on `https://<your-domain>/login`, or:
   ```bash
   for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " -X POST https://<your-domain>/api/login; done
   # 401 401 401 … 401 429 429 429     ← Cloudflare starts blocking the burst
   ```
   The first responses are JSON from the origin (`"Invalid credentials"`); after the threshold,
   Cloudflare returns `429` and the origin sees nothing.

**Use case / risk mitigated:** `/api/login` is a textbook credential-stuffing / brute-force
target. The rule caps guess attempts per IP, protecting both the users' accounts and origin
capacity, without touching application code.

### 1.6 No bypassing Cloudflare

Free Render has no host firewall, so enforcement lives in the app (`lib/cf-only.js`):
with **`REQUIRE_CLOUDFLARE=true`** set on Render, every request whose actual network peer is
not in [Cloudflare's IP ranges](https://www.cloudflare.com/ips/) (and is not loopback — the
tunnel) receives a `403` explanation page.

```bash
# Direct hit on the origin — refused:
curl -i https://<app>.onrender.com/           # → 403 "Direct origin access is blocked"

# Same request through Cloudflare — fine:
curl -i https://<your-domain>/                # → 200
```

Why it matters: an attacker who discovers the origin IP can hit it directly and **skip the
WAF, rate limiting and bot management entirely**. In production you would prefer
network-level controls — firewall the origin to Cloudflare IPs only, **Authenticated Origin
Pulls** (mTLS), or make the origin unreachable except via Cloudflare Tunnel (which is what
Part 2 does for the protected path).

> After Part 2 you can flip this on for good: set `REQUIRE_CLOUDFLARE=true` in Render → Environment.

---

## Part 2 — Zero Trust

### 2.1 Cloudflare Tunnel on the origin

1. Cloudflare dashboard → **Zero Trust** (accept the free plan, pick a team domain →
   `<team-name>.cloudflareaccess.com`).
2. **Networks → Tunnels → Create a tunnel → Cloudflared connector**, name it e.g. `origin-tunnel`.
3. Copy the **token** shown in the install command (the long string after `--token`).
4. On Render → Environment: add **`TUNNEL_TOKEN`** = that token. Save (this redeploys).
   The app downloads/starts `cloudflared` automatically on boot
   (`lib/tunnel.js`); logs show `[cloudflared]` lines and the connector turns **Healthy**
   in the Zero Trust dashboard.
5. **Public Hostname** tab (still on the tunnel config): add
   `tunnel.<your-domain>` → Service **HTTP** `localhost:10000`
   (check the exact port in Render logs: `[server] listening on 0.0.0.0:PORT`).
   Cloudflare creates the DNS record automatically (proxied).
6. Verify: `https://tunnel.<your-domain>/` shows the same app — now served through an
   outbound-only tunnel; no inbound port is exposed on Render.

### 2.2 SSO Identity Provider

**Zero Trust → Settings → Authentication → Login methods → Add one**:

- **One-time PIN** — zero configuration (email + PIN code). Good enough for the assessment.
- *Optional:* **Google** or **GitHub** OAuth — create an OAuth app at the provider, paste
  Client ID/Secret into Cloudflare, and set the redirect URL Cloudflare shows.

### 2.3 Lock down `/secure`

**Zero Trust → Access → Applications → Add an application → Self-hosted**:

1. **Application configuration:**
   - Application name: `secure-origin`
   - Session Duration: e.g. 24 hours
   - **Application domain:** `tunnel.<your-domain>` — path: `secure`
2. **Add policies:** one *Include* rule:
   - Selector **Emails** → your email address
   - *also* Selector **Email domain** → `cloudflare.com`
   (within one Include rule, selectors are OR-ed: you **or** anyone with an
   @cloudflare.com address)
3. Save.

Demo: open `https://tunnel.<your-domain>/secure` in an incognito window → Cloudflare asks you
to authenticate (OTP to your email) → afterwards the origin page greets you with
`cf-access-authenticated-user-email: <you>`. Uninvited visitors never reach the origin at all.
Create a **second identical Access application** for `<your-domain>` path `secure` — that one
guards the Worker route in Part 3.

---

## Part 3 — Developer Platform (Worker + R2 + D1)

All commands run from `worker/` unless noted. Prereqs: `npm install` inside `worker/`,
then `npx wrangler login`.

### 3.1 Create the R2 bucket and upload flags (private)

```bash
cd worker
npx wrangler r2 bucket create ase-flags        # name must match wrangler.toml
cd ..
bash scripts/download-flags.sh                 # fetches flag SVGs into flag-assets/
node scripts/upload-r2.js                      # uploads 257 flags as flags/<cc>.svg
```

The bucket has **no public access** — no `r2.dev` subdomain enabled. Objects are readable
only through the Worker's R2 binding. Verify privacy: any direct object URL returns
`Unauthorized`; `GET /flags/cn` through the Worker works.

### 3.2 Create the D1 database and load flags

```bash
cd worker
npx wrangler d1 create ase-flags-db
# 📔 copy "database_id" into wrangler.toml → [[d1_databases]]

npx wrangler d1 execute FLAGS_DB --file ../scripts/schema.sql --remote   # create table
cd ..
node scripts/make-d1-seed.js                   # generates scripts/d1-seed/*.sql chunks
bash scripts/load-d1.sh                        # loads all chunks into remote D1 + verifies 257 rows
```

(The seed is chunked and oversized flags are assembled with `UPDATE … ||` appends because
D1 caps single SQL statements at 100KB — Serbia's coat of arms alone is 181KB.)

### 3.3 Configure Access identity + deploy the Worker

1. In the Access application protecting `<your-domain>/secure` (created in 2.3), copy the
   **AUD tag** (Application Configuration → Advanced).
2. Edit `worker/wrangler.toml`:
   - `ACCESS_TEAM_DOMAIN = "<team-name>.cloudflareaccess.com"`
   - `ACCESS_AUD = "<aud-tag>"`
3. Deploy and route it on your domain:
   ```bash
   cd worker && npx wrangler deploy
   ```
   Then dashboard → **Workers Routes** for `<your-domain>` → add route
   `*<your-domain>/secure*` (and `/flags/*`, `/flags-d1/*`) → service
   `ase-assessment-worker`. Or put the `routes` array in `wrangler.toml` (commented there).
   > Without a custom domain you can also enable **Access for the Worker by name**
   > (Workers & Pages → the worker → Settings → Cloudflare Access) and use the
   > `*.workers.dev` URL — the AUD comes from that Access app.

### 3.4 End-to-end test

1. Open `https://<your-domain>/secure` → redirected to the Access login (OTP) →
   the page shows exactly:
   > **you@example.com authenticated at 2026-09-07T12:34:56.789Z from CN**
   with **CN** rendered as a link (Worker validates the ES256 Access JWT against your team's
   public keys; country comes from `request.cf.country`).
2. Click the country → `/flags/CN` serves the flag SVG from the **private R2 bucket**
   (`Content-Type: image/svg+xml`).
3. `/flags-d1/CN` serves the same flag from **D1** (response header `x-flag-source` tells
   you which store served it).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Render deploys but URL gives 502 | app must bind `0.0.0.0:$PORT` (it does) — check Render logs for the port |
| Everything 403 after setting `REQUIRE_CLOUDFLARE=true` | you are testing the onrender URL directly — use the proxied domain; check `X-Forwarded-For` handling |
| Tunnel connector not healthy | `TUNNEL_TOKEN` set on Render? Check logs for `[cloudflared]` lines; re-copy the token |
| Tunnel returns 502 Bad Gateway | public hostname service port ≠ app port — match `localhost:<PORT>` to Render logs |
| `/secure` shows the unauthenticated card | you're not on the Access-protected hostname, or the Access app path doesn't cover `/secure` |
| Worker says `audience mismatch` | AUD tag in `wrangler.toml` ≠ the Access app's AUD — re-copy |
| `/flags/xx` 404 | run `scripts/upload-r2.js`; check bucket name matches `wrangler.toml` |
| `/flags-d1/xx` 404 | run `scripts/load-d1.sh`; check `database_id` matches |
| Rate-limit rule never trips | rules match on the exact path (`/api/login`) and count per IP — curl from one machine |
