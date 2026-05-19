# EasyCursorSwap — Official Theme Index

[EasyCursorSwap](https://github.com/nishiuriraku/easy-cursor-swap) の公式テーマ
インデックスとオーサー鍵レジストリです。アプリ内の **公式インデックス** タブから
ここに登録された `.cursorpack` を検索・ダウンロードできます。

## ディレクトリ構成

```
.
├── authors/                 公開鍵レジストリ (1 著者 = 1 ファイル)
│   └── <github>.json        { github, display_name, public_key, historical_keys? }
├── entries/                 テーマメタデータ (1 テーマ = 1 ファイル)
│   └── <uuid>.json          { id, name, author, author_github, sha256, signature, ... }
│                            ※ `author` = theme.json の作者クレジット (表示用)
│                            ※ `author_github` = 提出者 GitHub username (鍵紐付け用)
├── themes/                  実体 .cursorpack (uuid.cursorpack)
├── previews/                カーソルロール別プレビュー PNG (validate.mjs が自動生成)
│   └── <uuid>/
│       ├── Arrow.png        各ロールの 64×64 PNG プレビュー (Arrow は必須)
│       ├── Help.png
│       ├── AppStarting.png
│       ├── Wait.png
│       ├── Crosshair.png
│       └── IBeam.png
├── schemas/                 JSON Schema (entry / author)
├── scripts/marketplace/     検証スクリプト (validate.mjs + malware-hashes.txt)
└── .github/workflows/       PR 自動検証 (Schema + SHA-256 + Ed25519 + VirusTotal)
```

`previews/` 以下のファイルは `scripts/marketplace/validate.mjs` が `.cursorpack` から
自動展開します。各エントリの `index.json` には `preview_base_url` フィールドが付与され、
アプリはそこを起点に `<preview_base_url>/Arrow.png` などを取得してサムネイルを表示します。

## テーマを提出する

1. アプリ内 **設定 → Security & Keys** で鍵ペアを生成 (初回のみ)
2. ライブラリで対象テーマを選び **「公式インデックスに提出」**
3. アプリが GitHub の Web エディタを開きます。指示に従って:
   - `authors/<your-github>.json` (初回のみ) を作成
   - `entries/<uuid>.json` を作成
   - `themes/<uuid>.cursorpack` をアップロード
4. PR を作成すると自動検証 (CI) が走ります
5. レビュアー目視 → マージで公開

詳細手順は [新規著者公開鍵の登録ガイド](https://github.com/nishiuriraku/easy-cursor-swap/blob/main/docs/author_registration.md) を参照してください。

## 自動検証 (PR CI)

以下を `marketplace-validate` ワークフローが PR ごとに実行します:

- ✅ JSON スキーマ検証 (`schemas/index-entry.json` / `schemas/author.json`)
- ✅ ファイルサイズ閾値 (`themes/*.cursorpack` ≤ 50 MB)
- ✅ SHA-256 整合性 (entry.sha256 == sha256(pack))
- ✅ Ed25519 署名検証 (entry.signature を著者公開鍵で検証)
- ✅ key_id 一致確認 (現行鍵 / `historical_keys` どちらか一致すれば OK)
- ✅ VirusTotal ハッシュ照合 (`secrets.VIRUSTOTAL_API_KEY` 設定時)
- ✅ ローカル `malware-hashes.txt` 照合 (フォールバック)

## ライセンス

メタデータと検証スクリプトは [MIT License](./LICENSE) です。
**個別の `.cursorpack` の利用条件は各テーマ作者に従ってください**
(著者ごとに `authors/<github>.json` の `display_name` と PR 内の記載を参照)。
