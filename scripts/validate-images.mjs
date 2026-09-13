#!/usr/bin/env node
// Validates that every `boxImage` in src/content/writeups/**/*.md points at a
// real file under public/, uses forward slashes, and does not include a
// `/public` prefix. Exits 1 on any error so it can gate the build.

import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const contentDir = join(root, "src", "content", "writeups");
const publicDir = join(root, "public");

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith(".md")) out.push(full);
  }
  return out;
}

function extractBoxImage(text) {
  const match = text.match(/^boxImage:\s*"([^"]*)"\s*$/m);
  return match ? match[1] : null;
}

// Case-sensitive existence check: fs.existsSync alone is case-insensitive on
// Windows, so walk the path segment by segment and compare exact names.
function existsCaseSensitive(absPath) {
  const rel = absPath.slice(publicDir.length).split(/[\\/]/).filter(Boolean);
  let current = publicDir;
  for (const segment of rel) {
    if (!existsSync(current)) return false;
    const names = readdirSync(current);
    if (!names.includes(segment)) return false;
    current = join(current, segment);
  }
  return true;
}

const errors = [];
const files = walk(contentDir);

for (const file of files) {
  const text = readFileSync(file, "utf8");
  const boxImage = extractBoxImage(text);
  if (!boxImage) continue;
  if (/^https?:\/\//.test(boxImage)) continue; // remote image, nothing to check

  if (boxImage.includes("\\")) {
    errors.push(`${file}: boxImage uses backslashes: "${boxImage}"`);
    continue;
  }
  if (boxImage.startsWith("/public/")) {
    errors.push(
      `${file}: boxImage must not include "/public" prefix: "${boxImage}" (use "${boxImage.replace(/^\/public/, "")}")`
    );
    continue;
  }
  if (!boxImage.startsWith("/")) {
    errors.push(`${file}: boxImage local path must start with "/": "${boxImage}"`);
    continue;
  }

  const absPath = join(publicDir, boxImage);
  if (!statSyncSafe(absPath)) {
    errors.push(`${file}: boxImage file does not exist: "${boxImage}"`);
    continue;
  }
  if (!existsCaseSensitive(absPath)) {
    errors.push(`${file}: boxImage path case mismatch on disk: "${boxImage}"`);
  }
}

function statSyncSafe(p) {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

if (errors.length) {
  console.error(`\nImage validation failed: ${errors.length} problem(s) found in boxImage paths.\n`);
  for (const e of errors) console.error(`  - ${e}`);
  console.error("");
  process.exit(1);
}

console.log(`Image validation passed: ${files.length} writeup(s) checked.`);
