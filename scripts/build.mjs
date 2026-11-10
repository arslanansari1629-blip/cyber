#!/usr/bin/env node
/* Concatenate the ordered source modules into a single dependency-free bundle.
 * No transpilation, no npm packages, no network access.
 */
import { readdirSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = join(root, 'src');
const outDir = join(root, 'dist');
const files = readdirSync(srcDir)
  .filter((f) => f.endsWith('.js'))
  .sort((a, b) => a.localeCompare(b));

if (!files.length) throw new Error('No source modules found in src/');

const banner = `/* AEGIS // SENTINEL — generated bundle. Do not edit directly.
 * Source: src/${'{modules}'}  |  Built with scripts/build.mjs
 * All analysis is local. No network calls. Authorization enforced in code.
 */\n`;

const parts = files.map((f) => {
  const content = readFileSync(join(srcDir, f), 'utf8');
  return `\n/* ===== ${f} ===== */\n${content.trim()}\n`;
});

mkdirSync(outDir, { recursive: true });
const out = banner.replace('{modules}', files.join(', ')) + parts.join('\n');
writeFileSync(join(outDir, 'bundle.js'), out);
const kb = (statSync(join(outDir, 'bundle.js')).size / 1024).toFixed(1);
console.log(`Built dist/bundle.js from ${files.length} modules (${kb} KB).`);
