/**
 * Tiny in-memory SQLite database used by the /search demo page.
 *
 * ⚠️ The /search endpoint is INTENTIONALLY VULNERABLE to SQL injection —
 * that is the whole point of the WAF demonstration (Part 1, step 5). The
 * query is built with string concatenation, exactly the way a legacy
 * application would do it. Do NOT reuse this pattern anywhere real.
 *
 * Falls back to a small simulator if the native `better-sqlite3` module
 * could not be compiled, so the demo keeps working everywhere.
 */

"use strict";

let db = null;
let simulated = false;

try {
  const Database = require("better-sqlite3");
  db = new Database(":memory:");
  db.exec(`
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT);
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT);
  `);
  const insertProduct = db.prepare("INSERT INTO products (name, price, description) VALUES (?, ?, ?)");
  [
    ["Cloudflare Hoodie", 39.0, "Classic black hoodie with the Cloudflare logo"],
    ["Orange Cloud Sticker Pack", 4.5, "12 vinyl stickers: orange clouds, rays, bots"],
    ["WAF Rules Notebook", 12.0, "A5 dotted notebook, 'my rules are managed' printed on the cover"],
    ["DNS Propagation Mug", 14.0, "Ceramic mug that never goes stale"],
    ["Zero Trust Water Bottle", 18.0, "Verify explicitly, hydrate implicitly"],
    ["Rate Limit Energy Drink", 3.0, "429 requests per can"],
  ].forEach((row) => insertProduct.run(...row));

  const insertUser = db.prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
  [
    ["admin", "adm1n_s3cr3t", "admin@example.com"],
    ["ase-candidate", "hunter2hunter2", "candidate@example.com"],
    ["demo", "password123", "demo@example.com"],
  ].forEach((row) => insertUser.run(...row));
} catch (err) {
  simulated = true;
  console.warn(`[db] better-sqlite3 unavailable (${err.message}) — using simulated SQL engine`);
}

/**
 * Builds and "executes" the vulnerable query. Returns the exact SQL string
 * that was sent to the engine so the demo page can show it.
 */
function vulnerableSearch(q) {
  const sql =
    `SELECT id, name, price, description FROM products ` +
    `WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;

  if (db) {
    try {
      return { engine: "sqlite3 (real)", sql, rows: db.prepare(sql).all() };
    } catch (err) {
      return { engine: "sqlite3 (real)", sql, error: err.message, rows: [] };
    }
  }

  // --- simulated engine ---
  const products = [
    { id: 1, name: "Cloudflare Hoodie", price: 39, description: "Classic black hoodie with the Cloudflare logo" },
    { id: 2, name: "Orange Cloud Sticker Pack", price: 4.5, description: "12 vinyl stickers: orange clouds, rays, bots" },
    { id: 3, name: "WAF Rules Notebook", price: 12, description: "A5 dotted notebook" },
    { id: 4, name: "DNS Propagation Mug", price: 14, description: "Ceramic mug that never goes stale" },
    { id: 5, name: "Zero Trust Water Bottle", price: 18, description: "Verify explicitly, hydrate implicitly" },
    { id: 6, name: "Rate Limit Energy Drink", price: 3, description: "429 requests per can" },
  ];
  const lower = String(q).toLowerCase();
  if (lower.includes("1=1") || lower.includes("'1'='1")) {
    return { engine: "simulated", sql, rows: products };
  }
  if (lower.includes("union") && lower.includes("users")) {
    return {
      engine: "simulated",
      sql,
      rows: [
        { id: 1, name: "admin", price: null, description: "password: adm1n_s3cr3t (email: admin@example.com)" },
        { id: 2, name: "ase-candidate", price: null, description: "password: hunter2hunter2 (email: candidate@example.com)" },
        { id: 3, name: "demo", price: null, description: "password: password123 (email: demo@example.com)" },
      ],
    };
  }
  const rows = products.filter(
    (p) => p.name.toLowerCase().includes(lower) || p.description.toLowerCase().includes(lower)
  );
  return { engine: "simulated", sql, rows };
}

module.exports = { vulnerableSearch, isSimulated: () => simulated };
