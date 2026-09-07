#!/usr/bin/env node
/**
 * Uploads the flag SVGs from ./flag-assets into the private R2 bucket,
 * key layout: flags/<cc>.svg  (lowercase ISO 3166-1 alpha-2).
 *
 * Usage (from the repo root, after `npm install` inside worker/ and
 * `wrangler login`):
 *   node scripts/upload-r2.js            # uses bucket from worker/wrangler.toml
 *   BUCKET=ase-flags node scripts/upload-r2.js
 *
 * The bucket stays private: no public bucket subdomain is ever exposed —
 * objects are read only through the Worker's R2 binding.
 */
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const ASSETS = path.join(ROOT, "flag-assets");
const WORKER = path.join(ROOT, "worker");
const CONCURRENCY = 8;

function bucketFromWranglerToml() {
  if (process.env.BUCKET) return process.env.BUCKET;
  const toml = fs.readFileSync(path.join(WORKER, "wrangler.toml"), "utf8");
  const m = toml.match(/^bucket_name\s*=\s*"(.+?)"/m);
  if (!m) throw new Error("bucket_name not found in worker/wrangler.toml (or set BUCKET env)");
  return m[1];
}

function runWrangler(args) {
  return new Promise((resolve) => {
    // npx resolves the locally installed wrangler from worker/node_modules
    const child = spawn("npx", ["wrangler", ...args], { cwd: WORKER, stdio: "ignore" });
    child.on("exit", (code) => resolve(code === 0));
    child.on("error", () => resolve(false));
  });
}

async function main() {
  const bucket = bucketFromWranglerToml();
  const files = fs
    .readdirSync(ASSETS)
    .filter((f) => /^[a-z]{2}\.svg$/.test(f))
    .sort();

  if (!files.length) {
    console.error("No flag SVGs in flag-assets/. Run scripts/download-flags.sh first.");
    process.exit(1);
  }

  console.log(`==> uploading ${files.length} flags to R2 bucket "${bucket}" (key: flags/<cc>.svg)`);

  let done = 0;
  let failed = 0;
  const queue = files.slice();

  async function worker() {
    while (queue.length) {
      const file = queue.shift();
      const ok = await runWrangler([
        "r2", "object", "put",
        `${bucket}/flags/${file}`,
        "--file", path.join(ASSETS, file),
        "--content-type", "image/svg+xml",
      ]);
      if (!ok) {
        failed++;
        console.error(`   ✗ ${file}`);
      }
      done++;
      if (done % 25 === 0 || done === files.length) console.log(`   ${done}/${files.length}`);
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  if (failed) {
    console.error(`==> finished with ${failed} failures — re-run this script to retry`);
    process.exit(1);
  }
  console.log("==> all flags uploaded. Verify with: npx wrangler r2 object get " + bucket + "/flags/cn --file=/tmp/cn.svg");
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
