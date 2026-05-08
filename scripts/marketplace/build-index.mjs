#!/usr/bin/env node
/**
 * `entries/*.json` を走査して `index.json` を再生成するスクリプト。
 *
 * 出力フォーマットは cursor-forge の `src-tauri/src/marketplace.rs::MarketplaceIndex`
 * に合わせる:
 *
 *   {
 *     "schema_version": 1,
 *     "commit": "<git sha>",   // CI が GITHUB_SHA を渡せばそれを使う
 *     "generated_at": "<ISO 8601>",  // 参考情報。Rust 側は未使用 (extra field は無視)
 *     "entries": [ ... ]
 *   }
 *
 * Rust 側の `MarketplaceEntry::name` は現状 `String` のみ受け付けるため、
 * schema が許す `{ ja, en }` オブジェクトの場合は `en > ja > id` の優先で
 * フォールバックして string 化する (Rust 側の i18n 対応までの暫定処理)。
 */
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..', '..')
const ENTRIES_DIR = join(ROOT, 'entries')
const SCHEMAS_DIR = join(ROOT, 'schemas')
const OUT_PATH = join(ROOT, 'index.json')

const SCHEMA_VERSION = 1

const ajv = new Ajv({ allErrors: true, strict: false })
addFormats(ajv)
const validateEntry = ajv.compile(loadJson(join(SCHEMAS_DIR, 'index-entry.json')))

function loadJson(path) {
  return JSON.parse(readFileSync(path, 'utf-8'))
}

/** Rust 側 `name: String` に合わせて i18n オブジェクトを単一文字列にフラット化する。 */
function flattenName(name, fallback) {
  if (typeof name === 'string') return name
  if (name && typeof name === 'object') {
    return name.en ?? name.ja ?? fallback
  }
  return fallback
}

/** description も同様にフラット化 (オプショナル)。 */
function flattenDescription(desc) {
  if (typeof desc === 'string') return desc
  if (desc && typeof desc === 'object') {
    return desc.en ?? desc.ja ?? null
  }
  return null
}

function readEntries() {
  if (!existsSync(ENTRIES_DIR)) return []
  const files = readdirSync(ENTRIES_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
  const entries = []
  for (const f of files) {
    const path = join(ENTRIES_DIR, f)
    const entry = loadJson(path)
    if (!validateEntry(entry)) {
      const errs = (validateEntry.errors ?? [])
        .map((e) => `${e.instancePath || '/'} ${e.message}`)
        .join('; ')
      throw new Error(`${f}: schema 違反 — ${errs}`)
    }
    entries.push(normalizeEntry(entry))
  }
  return entries
}

function normalizeEntry(entry) {
  // Rust 側の `MarketplaceEntry` が読める形に揃える。
  // 不要フィールドはそのまま残しても serde は無視するため、I18N 部分だけ正規化する。
  const out = {
    id: entry.id,
    name: flattenName(entry.name, entry.id),
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
  }
  const description = flattenDescription(entry.description)
  if (description != null) out.description = description
  if (entry.homepage) out.homepage = entry.homepage
  if (entry.size_bytes != null) out.size_bytes = entry.size_bytes
  if (entry.highlight) out.highlight = entry.highlight
  if (entry.verified != null) out.verified = entry.verified
  if (entry.published_at) out.published_at = entry.published_at
  return out
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
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA
  try {
    const headPath = join(ROOT, '.git', 'HEAD')
    if (!existsSync(headPath)) return null
    const head = readFileSync(headPath, 'utf-8').trim()
    if (head.startsWith('ref: ')) {
      const refPath = join(ROOT, '.git', head.slice(5).trim())
      if (existsSync(refPath)) {
        return readFileSync(refPath, 'utf-8').trim()
      }
      // packed-refs フォールバック
      const packed = join(ROOT, '.git', 'packed-refs')
      if (existsSync(packed)) {
        const ref = head.slice(5).trim()
        const line = readFileSync(packed, 'utf-8')
          .split('\n')
          .find((l) => l.endsWith(` ${ref}`))
        if (line) return line.split(' ')[0]
      }
      return null
    }
    return head
  } catch {
    return null
  }
}

function main() {
  const entries = readEntries()
  const index = {
    schema_version: SCHEMA_VERSION,
    commit: detectCommit(),
    generated_at: new Date().toISOString(),
    entries,
  }
  const json = `${JSON.stringify(index, null, 2)}\n`
  writeFileSync(OUT_PATH, json, 'utf-8')
  console.log(`wrote ${OUT_PATH} (${entries.length} entries)`)
}

main()
