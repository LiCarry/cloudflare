# Cloudflare ASE Take-Home Assessment — Report

> **Candidate:** `<your name>` · **Date:** 2026-09-XX · **Repo:** https://github.com/LiCarry/cloudflare
> **Live demo:** `https://<your-domain>` (origin via Render.com) · `https://<your-domain>/secure` (Worker) · `https://tunnel.<your-domain>` (Tunnel)

---

## 1. What I built

A small product-catalogue web application, published entirely through Cloudflare, that exercises
the three parts of the assessment:

- **Part 1 — Application Services:** the app runs on Render.com's free tier and is proxied
  through Cloudflare with TLS terminated end-to-end (**Full (strict)**), protected by the WAF
  (Cloudflare Managed Ruleset plus a SQL-injection demo rule) and a rate limiting rule on the
  login endpoint. Direct access to the origin is refused.
- **Part 2 — Zero Trust:** a Cloudflare Tunnel (`cloudflared` running next to the app on
  Render) publishes the origin with zero inbound ports, and a Cloudflare Access policy on
  `/secure` admits only my own identity and `@cloudflare.com` addresses via SSO (one-time PIN).
- **Part 3 — Developer Platform:** a Cloudflare Worker (built with Wrangler) serves
  `/secure` with the authenticated user's identity — *"`${EMAIL}` authenticated at
  `${TIMESTAMP}` from `${COUNTRY}`"* — where the country is a link to `/flags/${COUNTRY}`.
  Flags are served from a **private R2 bucket** (`/flags/:CC`) and, alternatively, from a
  **D1 database** (`/flags-d1/:CC`), both through Worker bindings.

```
visitor ──▶ Cloudflare edge (WAF · rate limiting · Access SSO)
              ├── /search /login …  ──────▶ proxied origin on Render.com (Express)
              ├── /secure /flags/*  ──────▶ Worker ──▶ R2 (private) & D1
              └── tunnel.<domain>/* ──────▶ Cloudflare Tunnel ──▶ cloudflared ──▶ localhost
```

## 2. Implementation, step by step

### 2.1 Origin on Render (Part 1.1–1.2)

I deployed a Node.js/Express application ([server.js](../server.js)) as a Render Web Service
(build `npm install`, start `npm start`, free instance). The app exposes:

| Route | Purpose |
|---|---|
| `/` | landing page + a request trace showing how the request arrived (`cf-ray`, `cf-connecting-ip`, peer IP decision) |
| `/search` | product search — **deliberately vulnerable to SQL injection** (string-concatenated SQL against in-memory SQLite) |
| `/login`, `POST /api/login` | fake login endpoint that always answers "invalid credentials" — a brute-force target for the rate limiting demo |
| `/secure` | shows the Cloudflare Access identity headers when reached through the tunnel |
| `/healthz` | liveness probe (exempt from the Cloudflare-only check) |

I then added my domain to Cloudflare (Free plan) and pointed a proxied (orange-cloud) DNS
record at the Render URL. `curl -sI https://<domain>` returning `cf-ray` confirmed all traffic
now traverses Cloudflare.

### 2.2 TLS — encryption mode recommendation (Part 1.4)

**Recommendation: Full (strict).** With *Flexible*, the browser shows a padlock but Cloudflare
reaches the origin over plain HTTP — the last mile is unencrypted and the padlock is cosmetic.
*Full* encrypts but doesn't validate the origin certificate, leaving room for a
man-in-the-middle with any self-signed certificate. *Full (strict)* both encrypts **and**
validates the certificate. Render provides a valid certificate for `*.onrender.com`, so
strict mode worked with no extra setup. This matters to customers because compliance
requirements (PCI-DSS, HIPAA…) assume the *entire* path is encrypted, not just the first hop.

### 2.3 WAF and the SQL injection demo (Part 1.5)

I enabled the **Cloudflare Managed Ruleset** (Security → WAF → Managed rules; on the Free plan
this is the *Cloudflare Free Managed Ruleset*) and added a custom rule matching classic SQLi
patterns in the query string (`union select`, `or 1=1`, `sleep(`) so the demo always triggers.
Demonstration: `curl "https://<domain>/search?q=' OR 1=1 --"` returns **403 with
`cf-mitigated-header: block`** — the attack is stopped at the edge and never reaches the
origin. The same payload sent to the origin directly (tunnel, or WAF bypassed) executes and
dumps every row; a `UNION SELECT` even leaks the users table. That before/after contrast is
the value of managed rulesets: research-grade protection, maintained by Cloudflare as new
CVEs appear, with zero application changes.

### 2.4 Rate limiting (Part 1.6)

One rule (Free plan): requests to `/api/login` from one IP exceeding **10 per 10 seconds**
are **blocked for 1 minute**. Use case: credential stuffing / brute-force protection on an
authentication endpoint — an attacker gets ~10 guesses per minute instead of thousands per
second, and the attack traffic never consumes origin capacity. Demo: the "Fire 20 requests"
button on `/login` (or a curl loop) shows the first requests returning the origin's JSON 401,
then Cloudflare's 429 block page — the count of requests the origin *saw* stops increasing.

### 2.5 Preventing Cloudflare bypass (Part 1.7)

Render's free tier has no host firewall, so I enforce this in the application
([lib/cf-only.js](../lib/cf-only.js)): with `REQUIRE_CLOUDFLARE=true`, every request whose
**actual network peer** (the last, unforgeable entry of `X-Forwarded-For`, or the socket
address) is outside [Cloudflare's published ranges](https://www.cloudflare.com/ips/) — and not
loopback (the tunnel) — receives a 403 explanation page. Demo:
`curl https://<app>.onrender.com/` → **403 "Direct origin access is blocked"**, while
`https://<domain>/` returns 200. Why this matters: anyone who discovers the origin IP can
otherwise skip the WAF, rate limiting and bot protection entirely. In production I would
recommend, in order of preference: an origin firewall allowlisting Cloudflare IPs,
**Authenticated Origin Pulls** (mTLS client certificates), or making the origin reachable
*only* through Cloudflare Tunnel — which is effectively what Part 2 achieves.

### 2.6 Cloudflare Tunnel + SSO + Access policy (Part 2)

I created a **remotely-managed tunnel** in the Zero Trust dashboard and passed its token to
Render as the `TUNNEL_TOKEN` environment variable. On boot the app starts `cloudflared` as a
managed child process ([lib/tunnel.js](../lib/tunnel.js)) — the connector makes an
**outbound-only** connection, so the origin needs no inbound ports at all. A public hostname
`tunnel.<domain>` maps to `http://localhost:<PORT>` inside the container.

For identity I enabled the **one-time PIN** login method (email + code — zero external
dependencies; Google/GitHub OAuth are equally simple if the customer already uses them).
An Access application on `tunnel.<domain>/secure` (and a second one on `<domain>/secure` for
the Worker) uses one Include policy: **Emails = my address OR Email domain = cloudflare.com**.
Visiting `/secure` in an incognito window triggers the SSO login; after authenticating, the
origin receives `cf-access-authenticated-user-email` and renders the user's identity.
Uninvited visitors never reach the origin.

### 2.7 Worker + R2 + D1 (Part 3)

The Worker ([worker/src/index.js](../worker/src/index.js)), created and deployed with the
**Wrangler CLI**:

- **`/secure`** — reads the Cloudflare Access JWT from the request, **verifies the ES256
  signature** against the team's published keys (issuer, audience and expiry checked), and
  renders `<EMAIL> authenticated at <TIMESTAMP> from <COUNTRY>` as HTML, with the country
  linking to `/flags/<COUNTRY>`. The country comes from `request.cf.country`, set by the edge.
- **`/flags/:CC`** — fetches `flags/<cc>.svg` from the **private R2 bucket** through the
  Worker's R2 binding and returns it with `Content-Type: image/svg+xml`. No public bucket URL
  exists (no `r2.dev` exposure), so the asset is unreachable except through the Worker.
- **`/flags-d1/:CC`** — queries the **D1** database (bound via `[[d1_databases]]`) for the
  same SVG stored as TEXT, returning it with the image content type.

Flag assets are the open-source [flag-icons](https://github.com/lipis/flag-icons) SVGs.
Two engineering wrinkles worth mentioning: (1) D1 caps single SQL statements at 100KB, and
Serbia's coat-of-arms SVG alone is 181KB — my seed script
([make-d1-seed.js](../scripts/make-d1-seed.js)) inserts oversized rows empty and assembles
them with `UPDATE … content || '…'` appends, and loads chunks with retries
([load-d1.sh](../scripts/load-d1.sh)); the round-tripped file is byte-identical. (2) The R2
upload script parallelises `wrangler r2 object put` calls for the 257 flags.

## 3. Where I see these products being useful

- **Cloudflare as reverse proxy + WAF:** any internet-facing web property gets DDoS
  absorption, TLS, bot management and a continuously-updated WAF in front of it — ideally
  layered in front of legacy applications that can't be modified quickly.
- **Managed Rulesets / WAF:** retail (card-skimming/Magecart injection), healthcare and
  finance (compliance-driven), and any WordPress/CRM estate — protection without a dev cycle.
- **Rate Limiting:** authentication endpoints, checkout, password reset, and API protection
  against scraping or credential stuffing — cheap capacity insurance.
- **Cloudflare Tunnel:** publishing internal tools (dashboards, admin panels, Jenkins,
  home-lab services) with zero inbound ports and no VPN — instant, auditable remote access.
- **Zero Trust Access:** replacing corporate VPNs; contractor/partner access to specific
  apps; merge-and-acquisition scenarios where identities live in different IdPs.
- **Workers:** edge personalisation, A/B routing, API gateway glue, authNZ enforcement —
  sub-50ms cold starts, no servers to manage.
- **R2:** media/asset hosting with **zero egress fees** — backups, ML datasets, log archives,
  static sites; the private-bucket + Worker pattern is a clean way to serve paid or
  entitlement-gated content.
- **D1:** serverless relational data for read-heavy apps, config/feature-flag stores,
  session or metadata tables colocated with Workers (SQLite semantics, no connection pools).

## 4. How I filled the gaps in my knowledge

- **Tunnels on PaaS:** running `cloudflared` on a platform that only exposes one web process
  was new to me — the Zero Trust docs plus community posts confirmed the child-process
  pattern; I automated the binary download in `postinstall` and added supervised restarts.
- **Access JWT validation:** I hadn't verified an ES256 JWT in a Worker before. The
  Cloudflare docs on `Cf-Access-Jwt-Assertion`, the team `/cdn-cgi/access/certs` JWKS
  endpoint and WebCrypto's ECDSA API made the ~40-line verifier straightforward.
- **D1 limits:** hit `SQLITE_TOOBIG` loading the seed and learned D1's 100KB
  statement/batch caps the hard way; solved with chunking + UPDATE-concatenation.
- **Proxy-chain IP forensics:** determining the *true* peer behind Render's load balancer
  (spoofable left vs unforgeable right side of `X-Forwarded-For`) required reading how
  proxies append entries — the cf-only middleware is the distillation.
- **Free Managed Ruleset scope:** confirmed what the Free plan's ruleset covers vs the paid
  OWASP/Core rulesets, and complemented it with a custom rule for a deterministic demo.

## 5. How would a target customer experience this?

**Very positively — the "time to first value" is exceptional.** Proxy + TLS went from zero to
secure in under an hour with no code changes; the tunnel removed a VPN-class problem in
~15 minutes; Access gave us Google-grade SSO with a policy UI instead of weeks of IdP
integration. The single dashboard (DNS, WAF, rate limiting, Zero Trust, Workers) keeps the
mental model coherent, and free tiers are generous enough to prototype everything real.

**Frictions to be honest about:** free-service cold starts (Render spins down after 15 idle
minutes — a ~50s first request) can confuse a first-time demo; DNS/nameserver propagation
tests patience; rate-limit/WAF rule tuning needs a mental model of "counting characteristics";
and IP-based origin lockdown on a PaaS is inherently application-level — enterprises will
want the network-level/`mTLS` options, which Cloudflare also has (Authenticated Origin Pulls).
The Worker/R2/D1 experience is genuinely developer-friendly — Wrangler's local emulation
meant I could develop offline against real bindings before the first deploy.

## 6. Access instructions for reviewers

| What | URL | Notes |
|---|---|---|
| Application (proxied, WAF + rate limiting) | `https://<your-domain>/` | try `/search`, `/login` |
| SQLi demo (blocked at edge) | `https://<your-domain>/search?q=' OR 1=1 --` | 403, `cf-mitigated-header: block` |
| Rate limit demo | `https://<your-domain>/login` | "Fire 20 requests" button |
| Origin via Tunnel | `https://tunnel.<your-domain>/` | Zero Trust protected |
| Protected path (Worker) | `https://<your-domain>/secure` | Access policy: candidate + `@cloudflare.com`; OTP login |
| Flags from R2 / D1 | `https://<your-domain>/flags/CN` · `/flags-d1/CN` | `Content-Type: image/svg+xml` |

> Reviewers with an `@cloudflare.com` address are covered by the Access policy on `/secure`
> (email domain rule). *Screenshots to insert: WAF block event in Security Events, rate
> limiting analytics, tunnel health, Access login page, /secure identity page.*
