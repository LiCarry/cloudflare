/**
 * "Cloudflare-only" middleware (Part 1, step 7 of the assessment).
 *
 * Goal: nobody should be able to bypass Cloudflare and talk to the origin
 * directly (e.g. by discovering the *.onrender.com URL).
 *
 * How it works on Render:
 *   - Render terminates TLS in front of the app and appends the *actual*
 *     connecting IP as the last entry of `X-Forwarded-For`. An attacker can
 *     forge header values, but they cannot forge that last entry.
 *   - Traffic that legitimately arrives via Cloudflare (orange-cloud DNS or
 *     a Cloudflare Tunnel to localhost) therefore has a peer IP inside
 *     Cloudflare's published ranges, or comes from loopback (cloudflared
 *     running next to this server).
 *   - Anything else gets a 403 with an explanation page.
 *
 * In production you would prefer network-level controls (origin firewall
 * allowlisting only Cloudflare IPs, Authenticated Origin Pulls mTLS, or
 * making the origin reachable *only* through Cloudflare Tunnel). On Render's
 * free tier we cannot install a host firewall, so we enforce it in the
 * application — which is also easy to demonstrate.
 *
 * Toggle with env var: REQUIRE_CLOUDFLARE=true|false (default: false so the
 * very first deployment on Render is reachable for a smoke test; flip it on
 * once the domain is proxied through Cloudflare).
 */

"use strict";

// Cloudflare published IP ranges (https://www.cloudflare.com/ips/).
// The list changes rarely; we refresh it in the background at boot and fall
// back to this embedded snapshot.
const EMBEDDED_RANGES = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
  "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
];

let activeRanges = EMBEDDED_RANGES.slice();

// Best-effort background refresh; never blocks startup.
fetch("https://www.cloudflare.com/ips-v4")
  .then((r) => r.text())
  .then(async (v4) => {
    const v6 = await fetch("https://www.cloudflare.com/ips-v6").then((r) => r.text());
    const merged = `${v4}\n${v6}`.split("\n").map((s) => s.trim()).filter(Boolean);
    if (merged.length >= 15) activeRanges = merged;
  })
  .catch(() => {});

/* ---------- CIDR math (IPv4 + IPv6, no external deps) ---------- */

function parseIp(ip) {
  if (!ip) return null;
  // Normalise IPv4-mapped IPv6 (::ffff:1.2.3.4) and strip zone index.
  let s = ip.split("%")[0].toLowerCase();
  if (s.startsWith("::ffff:") && s.includes(".")) s = s.slice(7);
  if (s.includes(":")) {
    // Expand "::" into the right number of zero groups.
    const [head, tail] = s.split("::");
    const headGroups = head ? head.split(":").filter(Boolean) : [];
    const tailGroups = tail != null ? tail.split(":").filter(Boolean) : [];
    const missing = 8 - headGroups.length - tailGroups.length;
    const groups = [...headGroups, ...Array(Math.max(0, missing)).fill("0"), ...tailGroups];
    if (groups.length !== 8) return null;
    let value = 0n;
    for (const g of groups) {
      const n = parseInt(g, 16);
      if (Number.isNaN(n)) return null;
      value = (value << 16n) | BigInt(n);
    }
    return { family: 6, value, bits: 128 };
  }
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = value * 256 + n;
  }
  return { family: 4, value: BigInt(value), bits: 32 };
}

function parseCidr(cidr) {
  const [addr, prefix] = cidr.split("/");
  const ip = parseIp(addr);
  if (!ip) return null;
  const len = Number(prefix);
  const mask = len === 0 ? 0n : ((1n << BigInt(len)) - 1n) << BigInt(ip.bits - len);
  return { family: ip.family, mask, network: ip.value & mask };
}

const parsedRanges = () => activeRanges.map(parseCidr).filter(Boolean);

function ipInCloudflare(ipStr) {
  const ip = parseIp(ipStr);
  if (!ip) return false;
  return parsedRanges().some(
    (r) => r.family === ip.family && (ip.value & r.mask) === r.network
  );
}

const PRIVATE_V4 = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
  "169.254.0.0/16", "100.64.0.0/10",
];

function isLoopback(ipStr) {
  const ip = parseIp(ipStr);
  if (!ip) return false;
  if (ip.family === 4) return (ip.value >> 24n) === 127n;
  return ip.value === 0n || ip.value === 1n; // :: or ::1
}

function isPrivate(ipStr) {
  if (isLoopback(ipStr)) return true;
  const ip = parseIp(ipStr);
  if (!ip) return false;
  if (ip.family === 6) return ip.value >> 120n >= 0xfcn; // fc00::/7 (unique local) + fe80 link-local share fc..ff
  return PRIVATE_V4.some((cidr) => {
    const r = parseCidr(cidr);
    return (ip.value & r.mask) === r.network;
  });
}

/**
 * Best guess at the *true* network peer that reached this server:
 * walk X-Forwarded-For from the right, skipping private/internal hops
 * (load balancers), and take the first public address. When no proxy chain
 * exists, fall back to the socket address.
 */
function truePeerIp(req) {
  const xff = String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (let i = xff.length - 1; i >= 0; i--) {
    if (!isPrivate(xff[i])) return { ip: xff[i], via: "x-forwarded-for" };
  }
  const remote = req.socket && req.socket.remoteAddress;
  return { ip: remote || "unknown", via: "socket" };
}

function classify(req) {
  const peer = truePeerIp(req);
  const fromLoopback = isLoopback(peer.ip); // cloudflared running beside us
  const fromCloudflare = ipInCloudflare(peer.ip);
  return {
    peerIp: peer.ip,
    peerSource: peer.via,
    // `cf-ray` only exists on requests that traversed the Cloudflare edge.
    traversedCloudflare: Boolean(req.headers["cf-ray"]),
    allowed: fromLoopback || fromCloudflare,
    reason: fromLoopback ? "loopback (Cloudflare Tunnel)" : fromCloudflare ? "Cloudflare IP range" : "not a Cloudflare IP",
  };
}

const EXEMPT_PATHS = ["/healthz"];

function cloudflareOnly() {
  const enabled = String(process.env.REQUIRE_CLOUDFLARE || "false").toLowerCase() === "true";
  return function middleware(req, res, next) {
    const info = classify(req);
    res.locals.requestInfo = info; // reused by pages to render a request trace
    if (!enabled || EXEMPT_PATHS.includes(req.path)) return next();
    if (!info.allowed) {
      console.warn(`[cf-only] BLOCKED ${req.method} ${req.originalUrl} from peer ${info.peerIp} (${info.reason})`);
      res.status(403).send(blockedPage(info));
      return;
    }
    next();
  };
}

/* ---------- 403 page (this is the demo artefact for step 7) ---------- */

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function blockedPage(info) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>403 — Direct origin access blocked</title>
<style>
 body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7f9;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#1c2733}
 .card{max-width:640px;background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(16,35,61,.12);padding:40px;margin:24px}
 h1{font-size:22px;margin:0 0 12px} code{background:#eef1f5;padding:2px 6px;border-radius:6px;font-size:13px}
 .trace{background:#0e1726;color:#9fe8c9;border-radius:8px;padding:14px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;margin:18px 0;overflow:auto}
 .muted{color:#5b6b7c;font-size:14px;line-height:1.65}
 a{color:#0b63d6}
</style></head><body><div class="card">
 <h1>🚫 403 — Direct origin access is blocked</h1>
 <div class="trace">peer_ip   = ${esc(info.peerIp)}<br>source    = ${esc(info.peerSource)}<br>decision = ${esc(info.reason)}<br>cf-ray    = ${esc(info.traversedCloudflare ? "present" : "absent")}</div>
 <p class="muted">This origin server only accepts traffic that arrives through the Cloudflare network —
 either proxied via an orange-cloud DNS record or through a Cloudflare Tunnel.</p>
 <p class="muted">Why: when visitors can reach the origin IP directly, they bypass the Web Application
 Firewall, rate limiting and bot protection, which makes those controls useless. Please use the
 application's official domain behind Cloudflare.</p>
</div></body></html>`;
}

module.exports = { cloudflareOnly, classify, ipInCloudflare, truePeerIp };
