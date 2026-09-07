/**
 * Origin web server — Cloudflare ASE Take-Home Assessment (Part 1 & 2)
 *
 * Deployed on Render.com (free tier). All traffic should reach this server
 * through Cloudflare:
 *
 *   Part 1  https://<your-domain>/      proxied DNS record (orange cloud)
 *   Part 2  https://tunnel.<your-domain>/  Cloudflare Tunnel (cloudflared child process)
 *
 * Demo surfaces:
 *   GET  /            landing page + request trace (shows whether we were reached via Cloudflare)
 *   GET  /search      ⚠ intentionally SQL-injectable search (WAF demo)
 *   GET|POST /login   fake login form + "hammer" button (rate limiting demo)
 *   POST /api/login   endpoint the rate limiting rule protects
 *   GET  /secure      shows the Cloudflare Access identity headers (Zero Trust demo)
 *   GET  /healthz     liveness probe (never blocked by the cf-only middleware)
 */

"use strict";

const express = require("express");
const { cloudflareOnly, classify } = require("./lib/cf-only");
const { vulnerableSearch, isSimulated } = require("./lib/db");
const { startTunnel } = require("./lib/tunnel");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", true); // Render terminates TLS in front of us
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cloudflareOnly());

/* ------------------------------------------------------------------ */
/* Shared HTML helpers                                                 */
/* ------------------------------------------------------------------ */

const esc = (s) =>
  String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function layout({ title, body, req }) {
  const info = resLocalsInfo(req);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · Cloudflare ASE Demo Origin</title>
<style>
  :root{--ink:#14213d;--muted:#5b6b7c;--line:#e4e9f0;--accent:#f6821f;--bg:#f7f8fa}
  *{box-sizing:border-box}
  body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:var(--bg);line-height:1.6}
  header{background:#fff;border-bottom:1px solid var(--line);padding:14px 28px;display:flex;gap:22px;align-items:center;flex-wrap:wrap}
  header .brand{font-weight:700}
  header .brand span{color:var(--accent)}
  nav a{color:var(--ink);text-decoration:none;font-size:14px;padding:6px 10px;border-radius:8px}
  nav a:hover{background:#eef1f5}
  main{max-width:880px;margin:0 auto;padding:34px 22px 60px}
  h1{font-size:26px;margin:0 0 10px}
  h2{font-size:18px;margin:28px 0 8px}
  p.lead{color:var(--muted);margin-top:0}
  .card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:22px;margin:18px 0}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
  code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  code{background:#eef1f5;padding:2px 6px;border-radius:6px;font-size:13px}
  pre{background:#0e1726;color:#c9e3ff;padding:14px;border-radius:10px;overflow:auto;font-size:13px;line-height:1.5}
  table{border-collapse:collapse;width:100%;font-size:14px}
  th,td{border-bottom:1px solid var(--line);text-align:left;padding:8px 10px;vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  input[type=text]{width:100%;padding:10px 12px;border:1px solid #cfd8e3;border-radius:8px;font-size:15px}
  button,.btn{background:var(--accent);border:none;color:#fff;font-weight:600;padding:10px 18px;border-radius:8px;cursor:pointer;font-size:14px;text-decoration:none;display:inline-block}
  button.secondary{background:#eef1f5;color:var(--ink)}
  .pill{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:3px 10px}
  .pill.ok{background:#e3f7ec;color:#0d7a43}
  .pill.warn{background:#fdeee3;color:#b4530a}
  .pill.bad{background:#fde5e5;color:#b42318}
  .muted{color:var(--muted);font-size:13px}
  .trace{font-size:12.5px;color:var(--muted);border-top:1px dashed var(--line);margin-top:26px;padding-top:12px}
  ul.results{padding-left:18px}
  #hammer-log{margin-top:10px;font-size:13px;max-height:220px;overflow:auto}
  .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
</style>
</head>
<body>
<header>
  <div class="brand">☁️ <span>CF</span> ASE Demo Origin</div>
  <nav>
    <a href="/">Home</a>
    <a href="/search">WAF / SQLi demo</a>
    <a href="/login">Rate-limit demo</a>
    <a href="/secure">/secure</a>
    <a href="/healthz">health</a>
  </nav>
</header>
<main>
${body}
<div class="trace"><strong>Request trace:</strong>
peer_ip=${esc(info.peerIp)} · source=${esc(info.peerSource)} · cf-ray=${esc(info.cfRay || "absent")} ·
cf-connecting-ip=${esc(info.cfConnectingIp || "absent")} · cf-ipcountry=${esc(info.cfCountry || "absent")} ·
decision=<strong>${esc(info.reason)}</strong>
</div>
</main>
</body></html>`;
}

function resLocalsInfo(req) {
  const c = classify(req);
  return {
    peerIp: c.peerIp,
    peerSource: c.peerSource,
    reason: c.reason,
    cfRay: req.headers["cf-ray"],
    cfConnectingIp: req.headers["cf-connecting-ip"],
    cfCountry: req.headers["cf-ipcountry"],
    traversed: c.traversedCloudflare,
  };
}

/* ------------------------------------------------------------------ */
/* Home                                                                */
/* ------------------------------------------------------------------ */

app.get("/", (req, res) => {
  const via = req.headers["cf-ray"]
    ? `<span class="pill ok">Reached via Cloudflare (cf-ray present)</span>`
    : `<span class="pill warn">Not proxied through Cloudflare yet (no cf-ray header)</span>`;

  const body = `
  <h1>Origin server is live 🎉</h1>
  <p class="lead">This application runs on Render.com and is published through Cloudflare.
  It exists to demonstrate the Application Services, Zero Trust and Developer Platform
  tasks of the Associate Solutions Engineer take-home assessment.</p>
  ${via}
  <div class="grid">
    <div class="card"><h2>🛡 WAF — SQL injection</h2>
      <p class="muted">A deliberately vulnerable product search. Watch Cloudflare's managed
      ruleset block classic payloads before they ever reach the origin.</p>
      <a class="btn" href="/search">Open /search</a></div>
    <div class="card"><h2>⏱ Rate limiting</h2>
      <p class="muted">A fake login endpoint. Fire a burst of requests and watch the
      Cloudflare rate limiting rule start returning 429s.</p>
      <a class="btn" href="/login">Open /login</a></div>
    <div class="card"><h2>🔐 /secure — Zero Trust</h2>
      <p class="muted">Reached through the Cloudflare Tunnel and protected by Cloudflare
      Access with SSO. Only approved identities get in.</p>
      <a class="btn" href="/secure">Open /secure</a></div>
    <div class="card"><h2>🚫 No direct access</h2>
      <p class="muted">With <code>REQUIRE_CLOUDFLARE=true</code>, hitting this server
      directly (bypassing Cloudflare) returns a 403.</p>
      <a class="btn" href="/healthz">liveness probe</a></div>
  </div>`;
  res.send(layout({ title: "Home", body, req }));
});

/* ------------------------------------------------------------------ */
/* Part 1.5 — WAF / SQL injection demo                                 */
/* ------------------------------------------------------------------ */

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  const result = q ? vulnerableSearch(q) : null;

  const payloads = [
    ["coffee (benign)", "coffee"],
    ["' OR 1=1 -- (dump all rows)", "' OR 1=1 --"],
    ["' UNION SELECT id, username, password, email FROM users -- (leak credentials)", "' UNION SELECT id, username, password, email FROM users --"],
  ];

  const body = `
  <h1>Product search <span class="pill warn">⚠ intentionally vulnerable</span></h1>
  <p class="lead">The query below is concatenated straight into SQL — exactly the legacy
  pattern attackers look for. Two ways to see the difference Cloudflare makes:</p>
  <ol>
    <li>Through the Cloudflare-proxied domain: attacks are blocked at the edge (HTTP 403,
    response header <code>cf-mitigated-header: block</code>) — the request never reaches this server.</li>
    <li>Directly against the origin (or with the WAF off): the injection executes and leaks data.</li>
  </ol>
  <div class="card">
    <form method="get" action="/search" style="display:flex;gap:10px;">
      <input type="text" name="q" value="${esc(q)}" placeholder="Search products…" autofocus>
      <button type="submit">Search</button>
    </form>
    <p class="muted" style="margin-bottom:0">Try:
      ${payloads.map(([label, val]) => `<a href="/search?q=${encodeURIComponent(val)}">${esc(label)}</a>`).join(" · ")}
    </p>
  </div>
  ${
    result
      ? `<h2>What the origin executed</h2>
         <p class="muted">engine: ${esc(result.engine)}${isSimulated() ? " (native SQLite unavailable, simulated)" : ""}</p>
         <pre>${esc(result.sql)}</pre>
         ${
           result.error
             ? `<p><span class="pill bad">SQL error</span> <code>${esc(result.error)}</code></p>`
             : `<table><tr><th>id</th><th>name</th><th>price</th><th>description</th></tr>
                ${result.rows.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>${esc(r.price ?? "")}</td><td>${esc(r.description)}</td></tr>`).join("")}
                </table>
                <p class="muted">${result.rows.length} row(s) returned ${
                  result.rows.length > 3 ? '— <strong>that is way more than any product search should return. The injection worked.</strong>' : ""
                }</p>`
         }`
      : ""
  }`;
  res.send(layout({ title: "WAF demo", body, req }));
});

/* ------------------------------------------------------------------ */
/* Part 1.6 — Rate limiting demo                                       */
/* ------------------------------------------------------------------ */

const loginAttempts = new Map(); // ip -> count (per process, for display only)

app.get("/login", (req, res) => {
  const body = `
  <h1>Fake login <span class="pill warn">brute-force target</span></h1>
  <p class="lead"><code>POST /api/login</code> always answers <em>"invalid credentials"</em>.
  It exists to be hammered. Configure a Cloudflare rate limiting rule such as:</p>
  <div class="card"><pre>When: uri.path eq "/api/login"
With the same characteristics: source.ip
When rate exceeds: 10 requests per 10 seconds
Then: Block for 1 minute</pre></div>
  <div class="card">
    <h2 style="margin-top:0">Manual login form</h2>
    <form method="post" action="/api/login" style="display:flex;gap:10px;flex-wrap:wrap">
      <input type="text" name="username" placeholder="username" style="flex:1;min-width:140px">
      <input type="text" name="password" placeholder="password" style="flex:1;min-width:140px">
      <button type="submit">Sign in</button>
    </form>
    <h2>Brute-force simulator</h2>
    <p class="muted">Fires 20 rapid requests to <code>POST /api/login</code> and colours each
    response: <span class="dot" style="background:#12b76a"></span>401 reached origin ·
    <span class="dot" style="background:#f04438"></span>429/403 blocked by Cloudflare rate limiting</p>
    <button id="hammer">🔥 Fire 20 requests</button>
    <div id="hammer-log"></div>
  </div>
  <script>
    document.getElementById('hammer').addEventListener('click', async (e) => {
      e.preventDefault();
      const log = document.getElementById('hammer-log');
      log.innerHTML = '';
      for (let i = 1; i <= 20; i++) {
        try {
          const r = await fetch('/api/login', {method: 'POST'});
          const blocked = r.status === 429 || r.status === 403;
          log.insertAdjacentHTML('beforeend',
            '<div><span class="dot" style="background:' + (blocked ? '#f04438' : '#12b76a') + '"></span>' +
            '#' + i + ' → HTTP ' + r.status + (blocked ? ' — blocked by Cloudflare 🛡' : ' — reached origin') + '</div>');
          log.scrollTop = log.scrollHeight;
        } catch (err) {
          log.insertAdjacentHTML('beforeend', '<div><span class="dot" style="background:#f79009"></span>#' + i + ' → error ' + err.message + '</div>');
        }
      }
    });
  </script>`;
  res.send(layout({ title: "Rate-limit demo", body, req }));
});

app.post("/api/login", (req, res) => {
  const ip = req.headers["cf-connecting-ip"] || req.ip || "unknown";
  const n = (loginAttempts.get(ip) || 0) + 1;
  loginAttempts.set(ip, n);
  res.status(401).json({
    ok: false,
    message: "Invalid credentials",
    origin_seen_attempts_from_your_ip: n,
    hint: "Keep firing — once the Cloudflare rate limiting rule trips, you will get a 429 and never see this JSON again.",
  });
});

/* ------------------------------------------------------------------ */
/* Part 2 — /secure behind Cloudflare Access                           */
/* ------------------------------------------------------------------ */

app.get("/secure", (req, res) => {
  const email = req.headers["cf-access-authenticated-user-email"];
  const jwt = req.headers["cf-access-jwt-assertion"];
  const country = req.headers["cf-ipcountry"];

  const body = `
  <h1>/secure</h1>
  <p class="lead">This path is published through the Cloudflare Tunnel and locked down by a
  Cloudflare Access policy (SSO). The edge strips/validates the session and only forwards
  requests from approved identities — the rest get a login page from Cloudflare, never this server.</p>
  <div class="card">
    ${
      email
        ? `<h2 style="margin-top:0">✅ Authenticated</h2>
           <p style="font-size:18px"><strong>${esc(email)}</strong> authenticated at ${esc(new Date().toISOString())} from ${esc(country || "unknown")}</p>`
        : `<h2 style="margin-top:0">🔓 No Access identity on this request</h2>
           <p>You are seeing this page because the request did <em>not</em> pass through a Cloudflare
           Access policy (e.g. you opened it directly instead of via
           <code>tunnel.your-domain/secure</code>). In the assessed setup, Cloudflare Access sits in
           front of this path and only authenticated users ever reach it.</p>`
    }
    <p class="muted">Access sets these headers on requests it approves:
    <code>cf-access-authenticated-user-email</code> = ${esc(email || "—")},
    <code>cf-access-jwt-assertion</code> = ${jwt ? "present (" + jwt.length + " chars)" : "—"},
    <code>cf-ipcountry</code> = ${esc(country || "—")}</p>
    <p class="muted">The Workers version of this page (Part 3) validates the Access JWT itself and renders
    the required identity line with a country flag link.</p>
  </div>`;
  res.send(layout({ title: "/secure", body, req }));
});

/* ------------------------------------------------------------------ */
/* Health + errors                                                     */
/* ------------------------------------------------------------------ */

app.get("/healthz", (req, res) => {
  res.json({ ok: true, uptime_s: Math.round(process.uptime()), ts: new Date().toISOString() });
});

app.use((req, res) => {
  res.status(404).send(
    layout({
      title: "404",
      body: `<h1>404</h1><p class="lead">Nothing here. Try the <a href="/">home page</a>.</p>`,
      req,
    })
  );
});

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[server] listening on 0.0.0.0:${PORT}`);
  console.log(`[server] REQUIRE_CLOUDFLARE=${process.env.REQUIRE_CLOUDFLARE || "false"}`);
  startTunnel();
});
