#!/usr/bin/env node
/**
 * `entries/*.json` を走査して `index.json` を再生成するスクリプト。
 *
 * 出力フォーマットは easy-cursor-swap の `src-tauri/src/marketplace.rs::MarketplaceIndex`
 * に合わせる:
 *
 *   {
 *     "schema_version": 1,
 *     "commit": "<git sha>",   // CI が GITHUB_SHA を渡せばそれを使う
 *     "generated_at": "<ISO 8601>",  // 参考情報。Rust 側は未使用 (extra field は無視)
 *     "entries": [ ... ]
 *   }
 *
 * Rust 側 (`src-tauri/src/marketplace.rs`) の `MarketplaceEntry::name` は
 * `crate::theme::LocalizedString` (`#[serde(untagged)]`) を採用しており、
 * plain string と `{ ja, en, default, ... }` ロケールマップの両方を受け付ける。
 * したがって本スクリプトは entry の `name` / `description` を **一切フラット化せず
 * そのまま pass-through する**。flatten すると JA 値が削れて Marketplace カードが
 * JA モードでも EN 名を表示するバグになる (修正コミット: easy-cursor-swap
 * 79dcea4 fix(marketplace) を参照)。
 */
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');
const ENTRIES_DIR = join(ROOT, 'entries');
const SCHEMAS_DIR = join(ROOT, 'schemas');
const OUT_PATH = join(ROOT, 'index.json');

const SCHEMA_VERSION = 1;

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateEntry = ajv.compile(
  loadJson(join(SCHEMAS_DIR, 'index-entry.json'))
);

function loadJson(path) {
  return JSON.parse(readFileSync(path, 'utf-8'));
}

function readEntries() {
  if (!existsSync(ENTRIES_DIR)) return [];
  const files = readdirSync(ENTRIES_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort();
  const entries = [];
  for (const f of files) {
    const path = join(ENTRIES_DIR, f);
    const entry = loadJson(path);
    if (!validateEntry(entry)) {
      const errs = (validateEntry.errors ?? [])
        .map((e) => `${e.instancePath || '/'} ${e.message}`)
        .join('; ');
      throw new Error(`${f}: schema 違反 — ${errs}`);
    }
    entries.push(normalizeEntry(entry));
  }
  return entries;
}

function normalizeEntry(entry) {
  // Rust 側の `MarketplaceEntry` が読める形に揃える。
  // name / description は LocalizedString (string | { ja, en, ... }) のまま pass-through。
  // 余分なフィールドはそのまま残しても serde 側は無視する。
  const out = {
    id: entry.id,
    name: entry.name,
    author: entry.author,
    author_github: entry.author_github,
    author_pubkey_id: entry.author_pubkey_id,
    sha256: entry.sha256,
    signature: entry.signature,
    download_url: entry.download_url,
    version: entry.version,
    included_roles: entry.included_roles,
    tags: entry.tags ?? [],
    download_count: entry.download_count ?? 0,
  };
  if (entry.description != null) out.description = entry.description;
  if (entry.homepage) out.homepage = entry.homepage;
  if (entry.size_bytes != null) out.size_bytes = entry.size_bytes;
  if (entry.highlight) out.highlight = entry.highlight;
  if (entry.verified != null) out.verified = entry.verified;
  if (entry.published_at) out.published_at = entry.published_at;
  // preview_base_url: previews/<uuid>/Arrow.png が存在すれば自動導出する
  const uuidMatch = entry.download_url?.match(
    /\/themes\/([a-f0-9-]+)\.cursorpack/
  );
  if (uuidMatch) {
    const uuid = uuidMatch[1];
    const arrowPath = join(ROOT, 'previews', uuid, 'Arrow.png');
    if (existsSync(arrowPath)) {
      out.preview_base_url = entry.download_url.replace(
        `/themes/${uuid}.cursorpack`,
        `/previews/${uuid}`
      );
    }
  }
  return out;
}

/**
 * `.git/HEAD` を読んで現在の commit SHA を返す。
 * CI では GITHUB_SHA 環境変数を優先 (シャロークローンでも常に取得できる)。
 * いずれも使えなければ null。
 *
 * 注: 子プロセス起動 (execSync など) は使わない。シェル経由のコマンド実行は
 * 静的コマンドであっても security hook に引っかかるため。
 */
function detectCommit() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    const headPath = join(ROOT, '.git', 'HEAD');
    if (!existsSync(headPath)) return null;
    const head = readFileSync(headPath, 'utf-8').trim();
    if (head.startsWith('ref: ')) {
      const refPath = join(ROOT, '.git', head.slice(5).trim());
      if (existsSync(refPath)) {
        return readFileSync(refPath, 'utf-8').trim();
      }
      // packed-refs フォールバック
      const packed = join(ROOT, '.git', 'packed-refs');
      if (existsSync(packed)) {
        const ref = head.slice(5).trim();
        const line = readFileSync(packed, 'utf-8')
          .split('\n')
          .find((l) => l.endsWith(` ${ref}`));
        if (line) return line.split(' ')[0];
      }
      return null;
    }
    return head;
  } catch {
    return null;
  }
}

function main() {
  const entries = readEntries();
  const index = {
    schema_version: SCHEMA_VERSION,
    commit: detectCommit(),
    generated_at: new Date().toISOString(),
    entries,
  };
  const json = `${JSON.stringify(index, null, 2)}\n`;
  writeFileSync(OUT_PATH, json, 'utf-8');
  console.log(`wrote ${OUT_PATH} (${entries.length} entries)`);
}

main();
