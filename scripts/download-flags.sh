#!/usr/bin/env bash
# Downloads all country flag SVGs (4x3) from the `flag-icons` package into
# ./flag-assets/. These are the assets uploaded to R2 and D1 in Part 3.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG_DIR="$ROOT/flag-assets/.pkg"
OUT_DIR="$ROOT/flag-assets"

mkdir -p "$PKG_DIR" "$OUT_DIR"

echo "==> installing flag-icons package (isolated in flag-assets/.pkg)"
npm install --prefix "$PKG_DIR" --no-fund --no-audit flag-icons >/dev/null

echo "==> copying SVGs to $OUT_DIR"
cp "$PKG_DIR/node_modules/flag-icons/flags/4x3/"*.svg "$OUT_DIR/"
rm -rf "$PKG_DIR"

COUNT=$(find "$OUT_DIR" -maxdepth 1 -name '*.svg' | wc -l | tr -d ' ')
TWO_LETTER=$(find "$OUT_DIR" -maxdepth 1 -name '*.svg' | sed 's|.*/||' | grep -Ec '^[a-z]{2}\.svg$' || true)
echo "==> done: $COUNT SVGs total ($TWO_LETTER are two-letter country codes usable with request.cf.country)"
