/**
 * Cloudflare Worker — ASE take-home assessment, Part 3 (Developer Platform).
 *
 * Endpoints
 *   GET /               index page
 *   GET /secure         returns "${EMAIL} authenticated at ${TIMESTAMP} from
 *                       ${COUNTRY}" as HTML, where ${COUNTRY} links to
 *                       /flags/${COUNTRY}. The identity comes from the
 *                       Cloudflare Access JWT on the request; the JWT is
 *                       verified against the team's public keys.
 *   GET /flags/:CC      flag image fetched from a *private* R2 bucket through
 *                       a Worker binding (no public bucket URL exists).
 *   GET /flags-d1/:CC   the same flag served from a D1 database via a
 *                       Worker binding.
 */

/* ------------------------------------------------------------------ */
/* Access JWT verification (ES256)                                     */
/* ------------------------------------------------------------------ */

const textEncoder = new TextEncoder();

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

// Public keys of the Zero Trust team, cached for an hour.
let keysetCache = { at: 0, keys: null };

async function getTeamKeys(teamDomain) {
  const now = Date.now();
  if (keysetCache.keys && now - keysetCache.at < 3600_000) return keysetCache.keys;
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`, {
    cf: { cacheEverything: true, cacheTtl: 3600 },
  });
  if (!res.ok) throw new Error(`certs fetch failed: ${res.status}`);
  const data = await res.json();
  keysetCache = { at: now, keys: data.keys || [] };
  return keysetCache.keys;
}

/**
 * Verifies the Cf-Access-Jwt-Assertion cookie/header.
 * Returns { ok, reason?, email?, payload? }.
 */
async function verifyAccessJwt(jwt, env) {
  const parts = jwt.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed token" };
  const [h64, p64, s64] = parts;

  let header, payload;
  try {
    header = b64urlToJson(h64);
    payload = b64urlToJson(p64);
  } catch {
    return { ok: false, reason: "malformed token" };
  }
  if (header.alg !== "ES256") return { ok: false, reason: `unsupported alg ${header.alg}` };

  const team = env.ACCESS_TEAM_DOMAIN;
  const aud = env.ACCESS_AUD;

  if (team && payload.iss !== `https://${team}`) {
    return { ok: false, reason: `issuer mismatch (${payload.iss})` };
  }
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (aud && !auds.includes(aud)) {
    return { ok: false, reason: "audience mismatch" };
  }
  if (typeof payload.exp !== "number" || payload.exp * 1000 <= Date.now()) {
    return { ok: false, reason: "token expired" };
  }

  const keys = await getTeamKeys(team);
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) return { ok: false, reason: "unknown signing key (kid)" };

  const cryptoKey = await crypto.subtle.importKey(
    "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
  );
  // JOSE ES256 signatures are raw r||s — exactly what WebCrypto expects.
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    cryptoKey,
    b64urlToBytes(s64),
    textEncoder.encode(`${h64}.${p64}`)
  );
  if (!valid) return { ok: false, reason: "signature verification failed" };

  return { ok: true, email: payload.email, payload };
}

/* ------------------------------------------------------------------ */
/* Small HTML helpers                                                  */
/* ------------------------------------------------------------------ */

const esc = (s) =>
  String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const page = (title, bodyHtml, { status = 200 } = {}) =>
  new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>
 body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f7f8fa;color:#14213d;margin:0;line-height:1.6}
 main{max-width:760px;margin:0 auto;padding:44px 22px}
 h1{font-size:26px} code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
 code{background:#eef1f5;padding:2px 6px;border-radius:6px;font-size:13px}
 .card{background:#fff;border:1px solid #e4e9f0;border-radius:12px;padding:22px;margin:18px 0}
 .identity{font-size:19px} .identity a{color:#0b63d6;font-weight:700}
 .muted{color:#5b6b7c;font-size:13.5px}
 .pill{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:3px 10px}
 .pill.ok{background:#e3f7ec;color:#0d7a43}.pill.warn{background:#fdeee3;color:#b4530a}
 img.flag{width:120px;border:1px solid #e4e9f0;border-radius:6px;background:#fff}
 ul{padding-left:18px}
</style></head><body><main>${bodyHtml}</main></body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } }
  );

const SAMPLE_CODES = ["cn", "us", "gb", "de", "jp", "sg", "br", "in", "au", "fr"];

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

async function handleSecure(request, env) {
  const jwt =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    (request.headers.get("Cookie") || "")
      .split(";")
      .map((c) => c.trim())
      .find((c) => c.startsWith("CF_Authorization="))
      ?.split("=")
      .slice(1)
      .join("=") ||
    null;

  const country = (request.cf && request.cf.country) || null;
  const timestamp = new Date().toISOString();

  if (!jwt) {
    return page(
      "Unauthenticated",
      `<h1>/secure</h1>
       <div class="card"><span class="pill warn">🔓 unauthenticated</span>
       <p>This request did not include a Cloudflare Access session
       (<code>CF_Authorization</code> cookie). In the assessed setup a Cloudflare Access
       application sits in front of <code>/secure</code>, so unauthenticated visitors get
       an SSO login page from Cloudflare and never reach this Worker.</p></div>`
    );
  }

  let identity;
  const configured = env.ACCESS_TEAM_DOMAIN && !env.ACCESS_AUD?.startsWith("REPLACE");
  if (configured) {
    identity = await verifyAccessJwt(jwt, env);
  } else {
    // Dev mode: decode without verifying so the page still renders locally.
    identity = { ok: true, dev: true, email: b64urlToJson(jwt.split(".")[1]).email };
  }

  if (!identity.ok) {
    return page(
      "Invalid token",
      `<h1>/secure</h1>
       <div class="card"><span class="pill warn">⚠ token rejected</span>
       <p>The Access JWT failed verification: <code>${esc(identity.reason)}</code>.</p></div>`
    );
  }

  const email = identity.email || "unknown";
  const cc = country || "??";
  return page(
    "Authenticated",
    `<h1>/secure</h1>
     <div class="card">
       <span class="pill ok">✅ verified by Worker${identity.dev ? " (dev mode — set ACCESS_TEAM_DOMAIN/ACCESS_AUD to enable)" : ""}</span>
       <p class="identity">${esc(email)} authenticated at ${esc(timestamp)} from
       <a href="/flags/${esc(cc)}">${esc(cc)}</a></p>
       <p class="muted">The country code links to <code>/flags/${esc(cc)}</code>, which serves the flag
       from the private R2 bucket. The same flag from D1: <a href="/flags-d1/${esc(cc)}">/flags-d1/${esc(cc)}</a></p>
     </div>
     <div class="card muted">
       <strong>Debug</strong><br>
       source of country: <code>request.cf.country</code> (set by the Cloudflare edge)<br>
       identity source: Cloudflare Access JWT (ES256, verified against team public keys)<br>
       issuer: <code>${esc(identity.payload?.iss || "—")}</code> · aud: <code>${esc(JSON.stringify(identity.payload?.aud || "—"))}</code>
     </div>`
  );
}

async function handleFlagR2(countryCode, env) {
  const code = countryCode.toLowerCase();
  const object = await env.FLAGS.get(`flags/${code}.svg`);
  if (!object) {
    return page(
      "Flag not found",
      `<h1>Flag not found</h1><div class="card">
       <p>No <code>flags/${esc(code)}.svg</code> object in the R2 bucket. Did you run
       <code>scripts/upload-r2.js</code>?</p>
       <p class="muted">Sample codes: ${SAMPLE_CODES.map((c) => `<a href="/flags/${c}">${c}</a>`).join(" · ")}</p>
       </div>`,
      { status: 404 }
    );
  }
  return new Response(object.body, {
    headers: {
      "content-type": object.httpMetadata?.contentType || "image/svg+xml",
      "cache-control": "public, max-age=86400",
      "x-flag-source": "cloudflare-r2",
    },
  });
}

async function handleFlagD1(countryCode, env) {
  const code = countryCode.toUpperCase();
  let row;
  try {
    row = await env.FLAGS_DB.prepare(
      "SELECT content, content_type FROM flags WHERE country_code = ?"
    )
      .bind(code)
      .first();
  } catch (err) {
    return page(
      "D1 error",
      `<h1>D1 error</h1><div class="card"><p>The query failed: <code>${esc(err.message)}</code>.</p>
       <p class="muted">Most likely the <code>flags</code> table does not exist yet — run
       <code>npx wrangler d1 execute FLAGS_DB --file=scripts/schema.sql --remote</code>.</p></div>`,
      { status: 500 }
    );
  }
  if (!row) {
    return page(
      "Flag not found",
      `<h1>Flag not found (D1)</h1><div class="card">
       <p>No row for country code <code>${esc(code)}</code> in the D1 table. Did you run
       <code>scripts/make-d1-seed.js</code> and load <code>scripts/d1-seed.sql</code>?</p>
       <p class="muted">Sample codes: ${SAMPLE_CODES.map((c) => `<a href="/flags-d1/${c}">${c}</a>`).join(" · ")}</p>
       </div>`,
      { status: 404 }
    );
  }
  return new Response(row.content, {
    headers: {
      "content-type": row.content_type || "image/svg+xml",
      "cache-control": "public, max-age=86400",
      "x-flag-source": "cloudflare-d1",
    },
  });
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env, ctx) {
    const { pathname } = new URL(request.url);

    if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405 });
    }

    if (pathname === "/" ) {
      return page(
        "ASE Worker",
        `<h1>ASE assessment Worker</h1>
         <div class="card"><ul>
           <li><a href="/secure"><code>/secure</code></a> — identity of the Access-authenticated user (HTML)</li>
           <li><a href="/flags/cn"><code>/flags/:CC</code></a> — flag from the private R2 bucket (SVG)</li>
           <li><a href="/flags-d1/cn"><code>/flags-d1/:CC</code></a> — flag from D1 (SVG)</li>
         </ul></div>`
      );
    }

    if (pathname === "/secure") return handleSecure(request, env);

    const r2match = pathname.match(/^\/flags\/([A-Za-z]{2})\/?$/);
    if (r2match) return handleFlagR2(r2match[1], env);

    const d1match = pathname.match(/^\/flags-d1\/([A-Za-z]{2})\/?$/);
    if (d1match) return handleFlagD1(d1match[1], env);

    return new Response("Not found", { status: 404 });
  },
};
