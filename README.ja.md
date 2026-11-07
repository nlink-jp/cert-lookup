# cert-lookup

公開の CT（Certificate Transparency）ログは、あるドメインにどんな証明書を記録しているか —
いつ・どの認証局が発行し、ほかにどの名前が載り、今も有効か・失効したか — に答えます。

cert-lookup は 2 つの CT 索引を重ねて 1 つの答えにします。

- **SSLMate CT Search API** — 今有効な証明書と失効状態（キー必須・無料の Small プラン）
- **Validin** — 過去の発行（`--history` のとき・無料の Community）。Validin の履歴は**標本**です。
  大きなドメインでは月ごと抜けることがあり、そのことは答えに示されません。

外へ出るのは照会したドメイン名だけで、この 2 社に届きます。調べる相手には何も届きません
（DNS の問い合わせもしません）。組織自身の業務だけに使ってください。

> 状態: 開発中。CLI は動きます。MCP サーバーは後の段階で入ります。

[English README](README.md)

## インストール

ソースからビルドします（Go 1.25 以上）。

```bash
make build   # → dist/cert-lookup
```

## 設定

[config.example.toml](config.example.toml) を `~/.config/cert-lookup/config.toml` に写して
`chmod 600` し、キーを引用符つきで書きます。

```toml
[sslmate]
api_key = "..."   # 必須

[validin]
api_key = "..."   # 任意。--history だけが使う
```

環境変数は設定ファイルより優先します: `CERT_LOOKUP_SSLMATE_API_KEY`、
`CERT_LOOKUP_VALIDIN_API_KEY`、`CERT_LOOKUP_SSLMATE_BASE_URL`、`CERT_LOOKUP_VALIDIN_BASE_URL`、
`CERT_LOOKUP_CACHE_DIR`、`CERT_LOOKUP_TIMEOUT_SECONDS`。

## 使い方

```bash
cert-lookup example.com                    # 今有効な証明書（SSLMate）
cert-lookup example.com --history          # 過去の発行も（Validin、標本）
cert-lookup example.com --subdomains       # サブドメインまで含める
cert-lookup example.com --json             # 構造化出力
cat domains.txt | cert-lookup              # 20 件まで、1 行 1 件
cert-lookup --clear-cache                  # キャッシュを全部消す
```

フラグはどこに置いても構いません。名前は ASCII だけで、国際化ドメイン名は punycode
（`xn--...`）で渡します。URL・IP アドレス・ワイルドカードは、何も送る前に断ります。

### 答えの中身

ドメインごとに要約（発行の件数、最初と最新、認証局、そして証明書に載っていた**ドメインの外の
名前** — 関連ドメインの手がかり）と、発行ごとの有効期間・発行元・失効状態（`revoked` /
`not_revoked` / `unknown`）・その認証局を許可する CAA の値・証明書の SHA-256・どのソースが
見たか、を返します。`caa_domains` とドメインの CAA レコードの突き合わせは doh-lookup で行います。

### 答えの読み方

- **空の答えは、発行が無かった証拠ではありません。** SSLMate は有効期限内の証明書しか持たず、
  公開サフィックス（`co.jp`）や索引に無い名前にも空で答えます。
- **Validin の履歴は標本です。** 載っていない発行が実在することがあります。
- 単一ホストの照会では、Validin の履歴にそのホストを覆うワイルドカード証明書は含まれません
  （SSLMate 側には含まれます）。
- `truncated: "newest_missing"` — SSLMate は古い発行から返すので、大きなドメインでページの
  上限に達すると新しい側が欠けます。そのため最新の発行日は出しません。

### 上限（無料枠）

| ソース | 上限 |
|---|---|
| SSLMate | 単一ホスト 1 時間 100 回・サブドメイン込み 1 時間 10 回・1 秒 5 回。100 件のページごとに 1 回、終わりを確かめる空ページも 1 回 |
| Validin | 1 日 10 回・月 50 回・1 回 250 件 |

`--history` のときは、照会の前に Validin の残り回数を確かめ（この確認は回数を使いません）、
キャッシュに無いドメインの数に足りなければ、何も送らずに断ります。答えはキャッシュします:
SSLMate 4 時間（空なら 15 分）、Validin 7 日。

### 終了コード

`0` 全ドメインで全ソースが答えた · `1` どれかのドメインかソースが失敗した（答えは表示する）·
`2` 使用法の誤り、または何も送らずに断った呼び出し。

## プライバシーと規約

- 照会したドメインは SSLMate（リクエスト URL をログに残す）と、`--history` のとき Validin に
  届きます。結果は手元に残ります — ただし AI アシスタント経由で使うと、そのモデルの提供元にも
  渡ります。
- キーは `Authorization` ヘッダーだけで送り、リダイレクトは拒否し、エラーメッセージに URL や
  上流のメッセージを載せません。
- Validin の規約は、利用を組織自身の社内セキュリティ業務に限り（§3(e)）、契約終了時に取得した
  データの削除を求めます（§4(c)）— `cert-lookup --clear-cache` で消せます。

## 文書

- [RFP](docs/ja/cert-lookup-rfp.ja.md) · [段階 0 の実測](docs/ja/cert-lookup-phase0.ja.md)
- 開発者向けは [AGENTS.md](AGENTS.md)

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
