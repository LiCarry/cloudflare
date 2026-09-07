/**
 * Optional Cloudflare Tunnel runner (Part 2 of the assessment).
 *
 * Render's free tier runs a single service per web app, so we run
 * `cloudflared` as a managed child process next to the Express server:
 *
 *   visitor → Cloudflare edge → Tunnel (outbound, encrypted QUIC/HTTP2)
 *           → cloudflared (this container) → http://localhost:PORT
 *
 * Configure with a single env var on Render:
 *   TUNNEL_TOKEN  — the token of a *remotely managed* tunnel created in the
 *                   Zero Trust dashboard (Networks → Tunnels → Create tunnel).
 *
 * The public hostname → service mapping (e.g. tunnel.yourdomain.com →
 * http://localhost:10000) is configured in the Zero Trust dashboard, not here.
 *
 * If TUNNEL_TOKEN is unset the app runs normally without the tunnel.
 */

"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const BIN = path.join(__dirname, "..", "bin", "cloudflared");
const RESTART_BACKOFF_MS = 5000;

function startTunnel(log = console.log) {
  const token = process.env.TUNNEL_TOKEN;
  if (!token) {
    log("[tunnel] TUNNEL_TOKEN not set — Cloudflare Tunnel disabled (set it on Render to enable)");
    return () => {};
  }
  if (!fs.existsSync(BIN)) {
    log("[tunnel] bin/cloudflared not found — run `npm install` again or download it manually");
    return () => {};
  }

  let child = null;
  let shuttingDown = false;
  let timer = null;

  const logLine = (stream, buf) =>
    buf
      .toString()
      .split("\n")
      .filter(Boolean)
      .slice(0, 4)
      .forEach((line) => log(`[cloudflared:${stream}] ${line}`));

  const launch = () => {
    child = spawn(BIN, ["tunnel", "--no-autoupdate", "run", "--token", token], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    log(`[tunnel] cloudflared started (pid ${child.pid})`);

    child.stdout.on("data", (b) => logLine("out", b));
    child.stderr.on("data", (b) => logLine("err", b));
    child.on("exit", (code) => {
      if (shuttingDown) return;
      log(`[tunnel] cloudflared exited (code ${code}) — restarting in ${RESTART_BACKOFF_MS / 1000}s`);
      timer = setTimeout(launch, RESTART_BACKOFF_MS);
    });
  };

  launch();

  const stop = () => {
    shuttingDown = true;
    if (timer) clearTimeout(timer);
    if (child) child.kill("SIGTERM");
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  return stop;
}

module.exports = { startTunnel };
