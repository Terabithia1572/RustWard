#!/usr/bin/env node
// Offline check of the built frontend (apps/rustward-desktop/dist): no asset
// may be loaded from the network at runtime. Fails on:
//  - any <script src>, <link href>, <img src>, @import or url() that is not a
//    relative/local path;
//  - any http(s) URL in shipped files other than XML namespace identifiers
//    and React's error-documentation link text (strings, never fetched);
//  - fetch()/XMLHttpRequest/WebSocket/EventSource usage in application code.
// Usage: node scripts/check-offline-assets.mjs [distDir]
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const dist = process.argv[2] ?? "apps/rustward-desktop/dist";
const ALLOWED_URL = [
  /^http:\/\/www\.w3\.org\//, // XML/SVG/MathML namespace identifiers
  /^https:\/\/react\.dev\/errors\//, // text inside React's minified error messages
];
const files = [];
(function walk(d) {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
})(dist);

const problems = [];
for (const f of files) {
  if (!/\.(html|js|css|json|svg|map)$/.test(f)) continue;
  const text = readFileSync(f, "utf8");
  const rel = relative(dist, f);
  for (const m of text.matchAll(/https?:\/\/[^\s"'`)<>\\]+/g)) {
    if (!ALLOWED_URL.some((re) => re.test(m[0]))) problems.push(`${rel}: external URL ${m[0]}`);
  }
  if (f.endsWith(".html")) {
    for (const m of text.matchAll(/\b(?:src|href)\s*=\s*"([^"]+)"/g)) {
      if (/^(?:[a-z]+:)?\/\//i.test(m[1])) problems.push(`${rel}: non-local reference ${m[1]}`);
    }
  }
  if (f.endsWith(".css")) {
    for (const m of text.matchAll(/@import\s+(?:url\()?["']?([^"')\s;]+)/g)) {
      if (/^(?:[a-z]+:)?\/\//i.test(m[1])) problems.push(`${rel}: CSS @import ${m[1]}`);
    }
  }
  if (f.endsWith(".js")) {
    for (const api of ["new WebSocket(", "new EventSource(", "XMLHttpRequest", "navigator.sendBeacon"]) {
      if (text.includes(api)) problems.push(`${rel}: network API ${api}`);
    }
    // fetch( appears only as a word boundary call; React itself does not use it.
    if (/[^.\w]fetch\(/.test(text)) problems.push(`${rel}: fetch() call`);
  }
}
if (files.length === 0) problems.push(`${dist}: no files (run vite build first)`);
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`offline assets OK: ${files.length} files in ${dist}, no runtime network references`);
