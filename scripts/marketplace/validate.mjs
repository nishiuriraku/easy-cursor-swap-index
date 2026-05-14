#!/usr/bin/env node
/**
 * Marketplace 投稿検証スクリプト (Ajv 版)
 *
 * 本リポジトリ (easy-cursor-swap-index) への PR で動かす想定。
 * 環境変数 `CHANGED_FILES` (改行区切り) に変更ファイル一覧が入っていれば
 * その中の `entries/*.json` を検証対象とする。なければ `entries/*.json` を全走査。
 *
 * 検証ステップ:
 *  1. JSON Schema 検証 (schemas/index-entry.json + Ajv format: uri / date-time)
 *  2. パス整合性 (entry.id == basename, themes/<id>.cursorpack 存在, 著者ファイル名一致)
 *  3. ファイルサイズ閾値 (`themes/<id>.cursorpack` <= 50MB)
 *  4. SHA-256 整合性 (entry.sha256 == sha256(themes/<id>.cursorpack))
 *  5. 著者レコード Schema 検証 + Ed25519 公開鍵長 32 バイト
 *  6. Ed25519 署名検証 (current key or historical_keys のいずれか)
 *  7. マルウェアチェック (VirusTotal API / ローカル DB)
 *  8. 孤立検出: themes/*.cursorpack に対応する entries/*.json が無い場合は error
 */
import { readFileSync, statSync, existsSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { dirname, join, basename } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import AdmZip from 'adm-zip'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..', '..')
const ENTRIES_DIR = join(ROOT, 'entries')
const THEMES_DIR = join(ROOT, 'themes')
const AUTHORS_DIR = join(ROOT, 'authors')
const SCHEMAS_DIR = join(ROOT, 'schemas')
const MALWARE_DB = join(__dirname, 'malware-hashes.txt')

const MAX_PACK_BYTES = 50 * 1024 * 1024

// VirusTotal free tier: 4 req/min → 15s 間隔で安全側に倒す
const VT_RATE_LIMIT_MS = 15_000

const ajv = new Ajv({ allErrors: true, strict: false })
addFormats(ajv)

const validateEntrySchema = ajv.compile(loadJson(join(SCHEMAS_DIR, 'index-entry.json')))
const validateAuthorSchema = ajv.compile(loadJson(join(SCHEMAS_DIR, 'author.json')))

function logErr(msg) {
  console.error(`::error::${msg}`)
}

function logWarn(msg) {
  console.warn(`::warning::${msg}`)
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, 'utf-8'))
}

function listEntriesFromEnv() {
  const env = process.env.CHANGED_FILES ?? ''
  const list = env
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.startsWith('entries/') && s.endsWith('.json'))
  if (list.length > 0) return list.map((p) => join(ROOT, p))
  // フォールバック: 全エントリ
  if (!existsSync(ENTRIES_DIR)) return []
  return readdirSync(ENTRIES_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => join(ENTRIES_DIR, f))
}

function listThemes() {
  if (!existsSync(THEMES_DIR)) return []
  return readdirSync(THEMES_DIR).filter((f) => f.endsWith('.cursorpack'))
}

function formatAjvErrors(errors) {
  return (errors ?? []).map((e) => `${e.instancePath || '/'} ${e.message}`).join('; ')
}

/** entries/<uuid>.json のファイル名と entry.id が一致するか */
function checkEntryFilename(file, entry) {
  const expected = `${entry.id}.json`
  const actual = basename(file)
  if (expected !== actual) {
    return `ファイル名 ${actual} は entry.id (${entry.id}.json) と一致しません`
  }
  return null
}

function loadAuthor(github) {
  const path = join(AUTHORS_DIR, `${github}.json`)
  if (!existsSync(path)) {
    return { ok: false, error: `authors/${github}.json が存在しません` }
  }
  let record
  try {
    record = loadJson(path)
  } catch (e) {
    return { ok: false, error: `authors/${github}.json パース失敗: ${e.message}` }
  }
  // Schema 検証
  if (!validateAuthorSchema(record)) {
    return { ok: false, error: `authors/${github}.json schema 違反: ${formatAjvErrors(validateAuthorSchema.errors)}` }
  }
  // ファイル名と record.github の一致 (CI は Linux で大文字小文字を区別する)
  if (record.github !== github) {
    return { ok: false, error: `authors/${github}.json の github フィールド (${record.github}) はファイル名と一致する必要があります` }
  }
  return { ok: true, record }
}

function computeKeyId(pubkeyB64) {
  const raw = Buffer.from(pubkeyB64, 'base64')
  return createHash('sha256').update(raw).digest('hex').slice(0, 16)
}

/** Ed25519 公開鍵 (32 バイト) → SPKI DER → KeyObject */
function pubkeyFromB64(pubkeyB64) {
  const raw = Buffer.from(pubkeyB64, 'base64')
  if (raw.length !== 32) {
    throw new Error(`Ed25519 公開鍵長が不正: ${raw.length} bytes`)
  }
  // SPKI prefix for Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00
  const prefix = Buffer.from('302a300506032b6570032100', 'hex')
  const der = Buffer.concat([prefix, raw])
  return createPublicKey({ key: der, format: 'der', type: 'spki' })
}

function verifySignature(entry, authorRecord) {
  // key_id 一致確認 (現行 or historical)
  const currentKid = computeKeyId(authorRecord.public_key)
  let pubkeyB64 = null
  if (currentKid === entry.author_pubkey_id) {
    pubkeyB64 = authorRecord.public_key
  } else if (authorRecord.historical_keys
      && authorRecord.historical_keys[entry.author_pubkey_id]) {
    pubkeyB64 = authorRecord.historical_keys[entry.author_pubkey_id]
  } else {
    return { ok: false, error: `key_id ${entry.author_pubkey_id} が著者鍵と一致しません` }
  }

  let pubkey
  try {
    pubkey = pubkeyFromB64(pubkeyB64)
  } catch (e) {
    return { ok: false, error: e.message }
  }
  const sigBytes = Buffer.from(entry.signature, 'base64')
  if (sigBytes.length !== 64) {
    return { ok: false, error: `署名長が不正: ${sigBytes.length} bytes` }
  }
  // Marketplace 仕様: SHA-256 hex 文字列に対する Ed25519 署名
  const messageBytes = Buffer.from(entry.sha256.toLowerCase(), 'utf-8')
  const ok = verify(null, messageBytes, pubkey, sigBytes)
  return { ok, error: ok ? null : 'Ed25519 署名検証失敗' }
}

function checkPackFile(entry) {
  const path = join(THEMES_DIR, `${entry.id}.cursorpack`)
  if (!existsSync(path)) {
    return { ok: false, error: `themes/${entry.id}.cursorpack が存在しません` }
  }
  const stat = statSync(path)
  if (stat.size > MAX_PACK_BYTES) {
    return { ok: false, error: `${path} のサイズ ${stat.size} が 50MB を超えています` }
  }
  // entry.size_bytes が指定されていれば実体と一致するか確認
  if (typeof entry.size_bytes === 'number' && entry.size_bytes !== stat.size) {
    return { ok: false, error: `entry.size_bytes (${entry.size_bytes}) が実ファイル (${stat.size}) と一致しません` }
  }
  const sha = createHash('sha256').update(readFileSync(path)).digest('hex')
  if (sha.toLowerCase() !== entry.sha256.toLowerCase()) {
    return { ok: false, error: `SHA-256 不一致 expected=${entry.sha256} actual=${sha}` }
  }
  return { ok: true, sha, size: stat.size }
}

/** themes/*.cursorpack に対応する entries/<id>.json が存在しないものを検出 */
function detectOrphanThemes() {
  const orphans = []
  for (const file of listThemes()) {
    const id = file.replace(/\.cursorpack$/, '')
    if (!existsSync(join(ENTRIES_DIR, `${id}.json`))) {
      orphans.push(file)
    }
  }
  return orphans
}

/** VirusTotal API v3 でハッシュを照合する。
 *  - malicious > 0 → { ok: false, error, detections }
 *  - 404 (未登録) → { ok: true, known: false }
 *  - その他の API エラー → fail-open: { ok: true, warning }
 */
async function checkMalwareVirusTotal(sha, apiKey) {
  const url = `https://www.virustotal.com/api/v3/files/${sha.toLowerCase()}`
  let res
  try {
    res = await fetch(url, {
      headers: { 'x-apikey': apiKey },
      signal: AbortSignal.timeout(20_000),
    })
  } catch (e) {
    // ネットワーク障害 — fail-open (CI をブロックしない)
    logWarn(`VirusTotal: ネットワークエラー (${e.message})。ローカル DB のみで継続。`)
    return { ok: true, warning: 'network_error' }
  }

  if (res.status === 404) {
    // VT 未登録 = 既知マルウェアではない
    return { ok: true, known: false }
  }

  if (res.status === 429) {
    logWarn('VirusTotal: レート制限 (429)。ローカル DB のみで継続。')
    return { ok: true, warning: 'rate_limited' }
  }

  if (!res.ok) {
    logWarn(`VirusTotal: API エラー ${res.status}。ローカル DB のみで継続。`)
    return { ok: true, warning: `http_${res.status}` }
  }

  let body
  try {
    body = await res.json()
  } catch {
    logWarn('VirusTotal: レスポンスパース失敗。ローカル DB のみで継続。')
    return { ok: true, warning: 'parse_error' }
  }

  const stats = body?.data?.attributes?.last_analysis_stats ?? {}
  const malicious = (stats.malicious ?? 0) + (stats.suspicious ?? 0)
  if (malicious > 0) {
    const engines = body?.data?.attributes?.last_analysis_results ?? {}
    const flagged = Object.entries(engines)
      .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
      .map(([engine]) => engine)
      .slice(0, 5)
      .join(', ')
    return {
      ok: false,
      error: `VirusTotal: ${malicious} エンジンが検出 (${flagged}...)`,
    }
  }
  return { ok: true, known: true }
}

function checkMalwareLocal(sha) {
  if (!existsSync(MALWARE_DB)) return { ok: true }
  const known = readFileSync(MALWARE_DB, 'utf-8')
    .split('\n')
    .map((l) => l.trim().toLowerCase())
    .filter((l) => l && !l.startsWith('#'))
  if (known.includes(sha.toLowerCase())) {
    return { ok: false, error: `マルウェアハッシュ DB と一致: ${sha}` }
  }
  return { ok: true }
}

/**
 * .cursorpack から previews/<role>.png を取り出して outRoot/previews/<uuid>/ に配置する。
 * @param {string} packPath - ローカルの .cursorpack ファイルパス
 * @param {string} uuid - テーマ UUID (= entry.id)
 * @param {string} outRoot - リポジトリルート (previews/ の親)
 * @returns {number} 抽出したファイル数
 */
function extractPreviews(packPath, uuid, outRoot) {
  const zip = new AdmZip(packPath)
  const previewDir = join(outRoot, 'previews', uuid)
  mkdirSync(previewDir, { recursive: true })
  let extracted = 0
  for (const entry of zip.getEntries()) {
    const name = entry.entryName // e.g. "previews/Arrow.png"
    if (!name.startsWith('previews/') || name === 'previews/') continue
    const role = name.slice('previews/'.length) // "Arrow.png"
    if (!/^[A-Za-z0-9_]+\.png$/.test(role)) continue
    zip.extractEntryTo(entry, previewDir, false, true)
    extracted++
  }
  return extracted
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function checkMalware(sha, vtApiKey, isFirst) {
  // VirusTotal API key が設定されていれば優先使用
  if (vtApiKey) {
    // 2件目以降はレート制限回避のため待機
    if (!isFirst) await sleep(VT_RATE_LIMIT_MS)
    const vtResult = await checkMalwareVirusTotal(sha, vtApiKey)
    if (!vtResult.ok) return vtResult
    // VT がエラーでも (fail-open) ローカル DB も確認する
  }
  return checkMalwareLocal(sha)
}

async function main() {
  const vtApiKey = process.env.VIRUSTOTAL_API_KEY ?? ''
  if (vtApiKey) {
    console.log('VirusTotal API: 有効 (実 DB 照合モード)')
  } else {
    console.log('VirusTotal API: 未設定 — ローカル malware-hashes.txt のみで照合')
  }

  // 孤立した themes/*.cursorpack を検出 (PR で削除し忘れた残骸)
  const orphans = detectOrphanThemes()
  for (const o of orphans) {
    logErr(`themes/${o} に対応する entries/*.json が存在しません (孤立ファイル)`)
  }

  const targets = listEntriesFromEnv()
  if (targets.length === 0 && orphans.length === 0) {
    console.log('no entries to validate')
    return 0
  }

  let errors = orphans.length
  let vtCallIndex = 0
  for (const file of targets) {
    console.log(`\n--- ${basename(file)} ---`)
    let entry
    try {
      entry = loadJson(file)
    } catch (e) {
      logErr(`${file}: JSON パース失敗: ${e.message}`)
      errors++
      continue
    }

    // 1. Schema 検証 (Ajv)
    if (!validateEntrySchema(entry)) {
      logErr(`${file}: schema 違反: ${formatAjvErrors(validateEntrySchema.errors)}`)
      errors++
      continue
    }

    // 2. ファイル名整合性
    const filenameErr = checkEntryFilename(file, entry)
    if (filenameErr) {
      logErr(`${file}: ${filenameErr}`)
      errors++
      continue
    }

    // 3. 著者レコード読み込み + Schema 検証
    const author = loadAuthor(entry.author_github)
    if (!author.ok) {
      logErr(`${file}: ${author.error}`)
      errors++
      continue
    }

    // 4. 署名検証
    const sigResult = verifySignature(entry, author.record)
    if (!sigResult.ok) {
      logErr(`${file}: ${sigResult.error}`)
      errors++
      continue
    }

    // 5. .cursorpack 存在 + サイズ + SHA-256
    const pack = checkPackFile(entry)
    if (!pack.ok) {
      logErr(`${file}: ${pack.error}`)
      errors++
      continue
    }

    // 6. マルウェアチェック
    const malware = await checkMalware(pack.sha, vtApiKey, vtCallIndex === 0)
    vtCallIndex++
    if (!malware.ok) {
      logErr(`${file}: ${malware.error}`)
      errors++
      continue
    }

    // 7. プレビュー PNG 抽出 (.cursorpack 内の previews/*.png → previews/<uuid>/)
    const packPath = join(THEMES_DIR, `${entry.id}.cursorpack`)
    const previewCount = extractPreviews(packPath, entry.id, ROOT)
    if (previewCount === 0) {
      logErr(`${entry.id}: .cursorpack 内にプレビューが見つかりません — Arrow.png は必須です`)
      errors++
      continue
    }
    console.log(`  previews: ${previewCount} ファイル抽出済み`)

    const vtLabel = vtApiKey ? ' [VT✓]' : ''
    const nameLabel = typeof entry.name === 'string' ? entry.name : (entry.name?.en ?? entry.name?.ja ?? '?')
    console.log(`  OK: ${nameLabel} (${entry.version}) ${pack.size}B sha=${pack.sha.slice(0, 12)}...${vtLabel}`)
  }

  if (errors > 0) {
    console.error(`\n${errors} validation error(s) detected`)
    return 1
  }
  return 0
}

main().then(process.exit)
