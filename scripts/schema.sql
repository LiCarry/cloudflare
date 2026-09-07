-- D1 schema for flag storage (Part 3, step 3).
-- Load with:
--   npx wrangler d1 execute FLAGS_DB --file=scripts/schema.sql --remote
CREATE TABLE IF NOT EXISTS flags (
  country_code TEXT PRIMARY KEY,          -- ISO 3166-1 alpha-2, uppercase (e.g. 'CN')
  content_type TEXT NOT NULL DEFAULT 'image/svg+xml',
  content      TEXT NOT NULL,             -- SVG source (flags are text, so TEXT works)
  size_bytes   INTEGER,
  updated_at   TEXT DEFAULT (datetime('now'))
);
