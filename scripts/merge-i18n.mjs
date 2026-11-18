#!/usr/bin/env node
// Merge per-page agent-returned namespace JSON fragments into the 3 locales.
// Fragment dir /tmp/i18n-frag/*.json, each shaped like { "<ns>": { "zh-CN": {...}, "zh-TW": {...}, "en-US": {...} }, ... }
// Each namespace is owned by exactly one agent → top-level assignment suffices, no conflicts. Keep existing nav/common/status/login etc. in the locales.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

const LOCALE_DIR = new URL("../web/src/i18n/locales/", import.meta.url);
const FRAG_DIR = "/tmp/i18n-frag";
const LANGS = ["zh-CN", "zh-TW", "en-US"];

// Safety net: decode HTML entities sub-agents may have over-escaped (&lt;→< &gt;→> &amp;→& etc).
// UI display text must always be literal characters; the <b> tags in settings also need literal form for <Trans>.
function decodeEntities(v) {
  if (typeof v === "string") {
    return v
      .replaceAll("&lt;", "<")
      .replaceAll("&gt;", ">")
      .replaceAll("&quot;", '"')
      .replaceAll("&#39;", "'")
      .replaceAll("&amp;", "&");
  }
  if (Array.isArray(v)) return v.map(decodeEntities);
  if (v && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v)) out[k] = decodeEntities(v[k]);
    return out;
  }
  return v;
}

const locales = {};
for (const l of LANGS) {
  locales[l] = JSON.parse(readFileSync(new URL(`${l}.json`, LOCALE_DIR), "utf8"));
}

let nsCount = 0;
const seen = new Set();
for (const f of readdirSync(FRAG_DIR).filter((f) => f.endsWith(".json")).sort()) {
  const frag = JSON.parse(readFileSync(`${FRAG_DIR}/${f}`, "utf8"));
  for (const ns of Object.keys(frag)) {
    if (seen.has(ns)) {
      console.warn(`⚠️  duplicate namespace: ${ns} (from ${f}) — latter wins`);
    }
    seen.add(ns);
    for (const l of LANGS) {
      const sub = frag[ns]?.[l];
      if (!sub) {
        console.warn(`⚠️  ${ns} in ${f} is missing ${l}`);
        continue;
      }
      locales[l][ns] = decodeEntities(sub);
    }
    nsCount++;
  }
}

for (const l of LANGS) {
  writeFileSync(new URL(`${l}.json`, LOCALE_DIR), JSON.stringify(locales[l], null, 2) + "\n");
}
console.log(`✓ merged ${nsCount} namespaces into ${LANGS.length} locales: ${[...seen].join(", ")}`);
