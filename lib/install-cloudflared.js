/**
 * Downloads the cloudflared binary into ./bin at install time so the origin
 * server can optionally run a Cloudflare Tunnel (Part 2 of the assessment).
 *
 * This script is safe to run anywhere: it never fails the install, it just
 * logs a warning when the download is not possible (e.g. offline CI) and the
 * tunnel can be skipped.
 */
const { createWriteStream } = require("fs");
const { mkdir, chmod, rm } = require("fs/promises");
const path = require("path");
const { spawn } = require("child_process");

const BIN_DIR = path.join(__dirname, "..", "bin");

function assetName() {
  const platform = process.platform; // darwin | linux | win32
  const arch = process.arch; // arm64 | x64

  if (platform === "linux" && arch === "x64") return "cloudflared-linux-amd64";
  if (platform === "linux" && arch === "arm64") return "cloudflared-linux-arm64";
  if (platform === "darwin" && arch === "x64") return "cloudflared-darwin-amd64.tgz";
  if (platform === "darwin" && arch === "arm64") return "cloudflared-darwin-arm64.tgz";
  return null;
}

async function run(cmd, args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, stdio: "ignore" });
    child.on("exit", (code) => resolve(code === 0));
    child.on("error", () => resolve(false));
  });
}

async function main() {
  const asset = assetName();
  if (!asset) {
    console.log("[cloudflared] unsupported platform, skipping download");
    return;
  }

  await mkdir(BIN_DIR, { recursive: true });
  const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/${asset}`;
  const dest = path.join(BIN_DIR, asset);

  console.log(`[cloudflared] downloading ${url}`);
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok || !res.body) {
    console.log(`[cloudflared] download failed (HTTP ${res.status}) — tunnel disabled, server still works`);
    return;
  }

  await new Promise((resolve, reject) => {
    const stream = require("stream");
    stream.pipeline(res.body, createWriteStream(dest), (err) => (err ? reject(err) : resolve()));
  });

  if (asset.endsWith(".tgz")) {
    // macOS releases ship as a tarball containing a single `cloudflared` file.
    const ok = await run("tar", ["-xzf", asset], BIN_DIR);
    await rm(dest, { force: true });
    if (!ok) {
      console.log("[cloudflared] failed to extract tarball — tunnel disabled, server still works");
      return;
    }
  } else {
    await run("mv", [asset, "cloudflared"], BIN_DIR).then(async (ok) => {
      if (!ok) {
        // mv unavailable — copy manually
        const { copyFile, rm: rmf } = require("fs/promises");
        await copyFile(dest, path.join(BIN_DIR, "cloudflared"));
        await rmf(dest, { force: true });
      }
    });
  }

  await chmod(path.join(BIN_DIR, "cloudflared"), 0o755);
  console.log("[cloudflared] binary ready at bin/cloudflared");
}

main().catch((err) => {
  console.log(`[cloudflared] install skipped: ${err.message}`);
});
