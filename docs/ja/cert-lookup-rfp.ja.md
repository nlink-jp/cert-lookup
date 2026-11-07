# RFP: cert-lookup

> Generated: 2026-11-07
> Status: Draft（利用者と全 7 項目合意済み・設計の独立検証を反映済み・段階 0 の実測を反映済み — [段階 0 の記録](cert-lookup-phase0.ja.md)）

## 1. Problem Statement

調査中のドメインについて、公開の CT（Certificate Transparency）ログに記録された
証明書を答える。答えるのは 3 つ — **いつ・どの認証局が発行したか**、**証明書の SAN に
一緒に載っていた別の名前**、**今も有効か・失効したか**。今有効な証明書と失効状態は
**SSLMate CT Search API** から、過去の発行履歴は **Validin** から取り、1 つの答えにまとめる。
Validin の履歴は標本で、完全さは主張しない（発行の少ないドメインでは約 2 年半分が欠けなく返り、
大きなドメインでは月ごとに抜ける — 段階 0）。調べる相手のサーバーにも DNS にも一切接続せず、第三者の索引だけを読む。

使うのはこの組織のセキュリティ調査担当と、MCP 経由の調査エージェント。想定する使い方は
2 つで、**どちらも組織自身の業務に限る**（Validin 規約 §3(e)）。

1. **不審なドメインの調査** — 発行されたばかりか（新しく作られた攻撃基盤の兆候）、
   どの認証局か、SAN から関連するドメインをたどれるか。
2. **自社ドメインの点検** — 身に覚えのない発行が無いかを、聞かれたときに 1 回答える。
   定期的な見張りと通知は範囲外（SSLMate の Cert Spotter など専用サービスの仕事）。

現在のツール群で証明書に触れるのは、rdns-lookup（CT 由来の**名前**を索引の一部として返す）と
shodan-lookup（ある IP で**観測された**証明書）だけで、「このドメインに対して発行された証明書の
一覧と発行元・期間・失効」には答えられない。

## 2. Functional Specification

### Commands / API Surface

**CLI**

```
cert-lookup [flags] <domain> [domain...]   # 引数で 1〜20 件。引数なしなら stdin から 1 行 1 件
  --subdomains      # サブドメイン（任意の深さ）の証明書も含める
  --history         # Validin から過去の発行履歴も取る（Validin の回数を使う）
  --json            # 構造化出力（既定は人間向けテキスト）
  --refresh         # キャッシュを使わず取り直す
  --timeout <dur>   # 上流タイムアウト
  --config <path>   # 設定ファイル
  --clear-cache     # キャッシュを全消去（Validin 規約 §4(c) の削除義務に応えるため）
  --version         # 必須応答（brew test が叩く）
cert-lookup mcp     # ローカル MCP サーバー（stdio）
```

- 既定は SSLMate だけを引く。**Validin は `--history` を付けたときだけ**（1 日 10 回しか無いため）
- 単一ホストの照会では、そのホストを覆うワイルドカード証明書（`www.example.com` に対する
  `*.example.com`）も含める（SSLMate の `match_wildcards=true`）
- 入力は全件を手元で検査してから照会を始める（1 件でも検査に落ちれば何も送らない）。重複は除く。
  照会の後で起きた失敗（回数超過・タイムアウト等）は、そのドメインだけの失敗になる（下記「失敗の扱い」）
- **照会は 1 件ずつ順に送る**。SSLMate は 1 秒 5 回を超えないよう間隔を空け、応答ヘッダーの
  `X-Ratelimit-Remaining` が 0 になったら、残りのドメインは送らずにそれぞれ `rate_limited` とする
  （サブドメイン込みの照会は 1 時間 10 回しか無く、20 件を一度には通せない）

**ドメインの検査（照会の前に、外へ何も送らずに行う）**

- 受け付けるのは ASCII だけ（`xn--` 形式の punycode を含む）。**非 ASCII（日本語ドメイン等）は
  「punycode で渡してください」と断る** — IDNA の変換表は標準ライブラリに無く、正しく自作するのは
  重いため
- 小文字に揃え、末尾のドット 1 つは外す。ラベルは英数字とハイフン、1〜63 文字で、**先頭と末尾は
  ハイフン不可**。全体 253 文字まで、2 ラベル以上
- 断るもの: IP アドレス、`*` を含む名前、URL（スキーム・パス・ポート付き）、空白・制御文字
- 登録可能なドメインかどうか（`co.jp` のような公開サフィックス）は手元では判定しない。**SSLMate は
  公開サフィックスを断らず、空の配列で答える**（段階 0: `com`・`co.jp`）。空の答えは「SSLMate に
  有効期限内の証明書が無い（公開サフィックスや索引に無い名前も空になる）」と書き、発行が無いとは言わない

**MCP ツール**

| tool | 役割 |
|---|---|
| `lookup_certs` | 1〜20 件のドメインに、まとめた発行の一覧と要約を返す。引数 `domains[]`・`subdomains`・`history`・`refresh` |
| `cache_status` | キーの有無、キャッシュの件数・保持期間・場所、両ソースの残り回数（Validin は使用量 API の日と月、SSLMate は照会の種類別 — 単一ホストとサブドメイン込み — に最後の応答ヘッダーの値と**その観測時刻**） |
| `get_usage` | 操作マニュアル（usage.md を埋め込み、メタテストでコードと照合） |

SSLMate のキーが無くても MCP サーバーは起動し、`cache_status` と `get_usage` は答える。
`lookup_certs` は構造化エラー `no_api_key` を返す。CLI はキーが無ければ使用法エラー（exit 2）。

### Input / Output

**照会の組み立て**

- SSLMate: `GET https://api.certspotter.com/v1/issuances?domain=<d>` に、単一ホストなら
  `include_subdomains=false&match_wildcards=true`、`--subdomains` なら `include_subdomains=true`、
  常に `expand=dns_names,issuer,issuer.caa_domains,revocation`。ページは最後の `id` を `after=` に
  渡して空になるまで進める。**応答の `Link` ヘッダーは使わない**（実測でパスから `/v1` が
  抜けていた）
- **SSLMate は古く見つけた順に返す**（文書: "in the order that they were discovered"、`after` 無しは
  "least-recently-discovered"。段階 0 でも確認）。新しい発行が後ろに来るので、ページの上限で打ち切ると
  **新しい発行から欠ける**。超えたら `truncated: "newest_missing"` を立て、要約の「最新の発行」は出さない
- **1 ページは 100 件で、空のページを含め 1 ページごとに 1 回と数える**（段階 0）。終わりは文書どおり
  空のページで確かめる（100 件未満のページを最後とみなす近道は文書に無いので使わない）。したがって発行が
  N 件のドメインは ceil(N/100)＋1 回かかる。ページの上限は**単一ホスト 5 ページ（500 件）、サブドメイン込み
  3 ページ（300 件）**とし、残り回数が 0 になればその前でも止める。大きなドメインの全件は取らない —
  1 ページで 540〜608 KB あり（google.com、段階 0）、MCP の応答にはどのみち収まらない
- Validin: `GET https://app.validin.com/api/axon/domain/certificates/<d>?wildcard=<subdomains>&limit=250&lookback=1095&time_format=unix`。
  **期間は常に `lookback=1095`（3 年）を明示する** — 期間を指定しないと直近の一部しか返らない（段階 0:
  google.com で 2026 年 8 月と 11 月だけ）。現在の証明書は SSLMate が答えるので、Validin には過去側を求める
- **Validin の履歴は標本である**（利用者の判断で受け入れ）。大きなドメインでは期間を明示しても月ごとに大きく
  抜け、それでも `limited` は `false` のまま（段階 0）。答えには Validin が返した観測の範囲（最初と最後の観測日）と
  件数を書き、「Validin は一部だけを返すことがある」と明示する。完全さは主張しない。発行の少ないドメインでは
  索引の深さの範囲で欠けなく返った（組織のドメイン）
- **Validin は単一ホストの照会で、覆うワイルドカード証明書を返さない**（段階 0）。単一ホストの履歴はその名前を
  載せた証明書だけで、ワイルドカード証明書は含まないと `notes` に書く（親ドメインの照会は回数を余計に使うので
  自動ではしない）
- `--history` のときは、照会の前に `GET /api/profile/usage`（回数を消費しない）で残りを見る。
  **日と月の残りの小さい方**が、送る必要のあるドメインの数（キャッシュに無いもの。`--refresh` なら
  全件）より少なければ、何も送らずに `quota_exhausted` で断る

**発行のまとめ方**

1 回の発行が複数の形で返る — SSLMate は同じ発行を別の `id` で重複して返し（実測）、Validin は
仮証明書（precert）と本証明書を、それぞれ記録された CT ログの数だけ返す（実測で 18 件 → 4 発行）。

1. SSLMate の中は `tbs_sha256` でまとめる（文書: この値が発行を一意に示す）
2. Validin の本証明書の `fingerprint_sha256` が SSLMate の `cert_sha256` と一致すれば同じ発行（実測で
   一致した）。ただし SSLMate の `cert_sha256` は本証明書を知らなければ仮証明書の値なので、一致しない
   ことがある
3. それ以外（Validin の仮証明書・SSLMate に無い過去の発行）は、**発行元の要素（C・O・CN）・`not_before`・
   `not_after`・名前の集合**（Validin は CN が `domains` に入らないことがあるので CN と合わせる）の一致で
   まとめる。通し番号（RFC 5280 で証明書を特定する組）は Validin の応答に無いので使えない（段階 0）。
   発行元の DN は SSLMate がカンマ区切り（`C=US, O=…, CN=WE2`）、Validin がスラッシュ区切り
   （`/C=US/O=…/CN=WR2`）と要素の表（`issuer: {C, O, CN}`）なので、SSLMate の DN を RFC 4514 の
   エスケープに従って要素に分け、要素どうしで比べる。同時に出た RSA と ECDSA の 2 枚は別の中間証明書から
   出ていた（段階 0: cloudflare.com）ので、発行元を含むこの組で取り違えない

**1 件の発行（JSON）**

| 項目 | 内容 |
|---|---|
| `names` | 証明書が有効な名前（SAN と CN の和） |
| `issuer` | `name`（SSLMate の整えた名前、無ければ DN の O/CN）と `dn` |
| `not_before` / `not_after` | 有効期間 |
| `expired` | **答えを返す時点**で期限切れか（キャッシュした時点ではない） |
| `revocation` | `status`（`revoked` / `not_revoked` / `unknown`）、`time`、`reason`（RFC 5280 の理由コード。文書は認証局の理由が正確とは限らないと注意している）、`checked_at`。SSLMate が状態を知らない（`null`）とき、SSLMate が返さない発行（期限切れ・Validin だけ）のときは `unknown` |
| `caa_domains` | この認証局を許可する CAA の値（SSLMate）。CAA レコードとの照合は doh-lookup で行う |
| `cert_sha256` | 見えた証明書・仮証明書の SHA-256 の一覧 |
| `tbs_sha256` | SSLMate が返したとき |
| `logged_at` | Validin が CT ログで観測した時刻（あれば） |
| `seen_by` | `sslmate` / `validin` / 両方 |

**ドメインごとの結果**

- 要約: 発行の件数、最初と最新の `not_before`（`truncated` で欠けた側は出さない）、認証局の一覧（20 件まで＋総数）
- `names_outside` — **照会したドメインとその配下の外にある SAN の名前**（関連ドメインの手がかり。
  公開サフィックスの判定は要らない）。100 件まで＋総数
- `sources` — `sslmate` と `validin` それぞれの状態（`ok` / `failed` / `not_requested`）と、失敗なら
  その `code`
- `history`（`--history` のとき）— Validin が返した観測の範囲（`observed_from` / `observed_to`）と件数、
  `sample: true`（Validin は一部だけを返すことがある）
- `truncated` — SSLMate がページの上限で打ち切ったとき `"newest_missing"`。`notes`（片方が失敗したとき、
  履歴を頼んでいないとき、Validin の履歴が標本であること、単一ホストの履歴がワイルドカード証明書を含まないこと、
  空の答えが発行の不在を意味しないこと）
- ドメインだけの失敗（`rate_limited`・`timeout`・`upstream_error`・`invalid_api_key`）は、`sources` の各ソースに
  `state: "failed"`・`code`・自前の `message` で示し、`rate_limited` には上流の `Retry-After` の秒数を
  `retry_after_seconds` として添える（段階 1: 失敗はソースごとに起きるので、ドメインに 1 つの `error` は置かず
  ソースの状態に持たせた）。呼び出し全体を止める失敗とは分ける（下記）

**失敗の扱い**: 片方のソースが失敗したら、そのドメインは `degraded: true` とし、ある分だけで答える。
**履歴が空でも「発行が無かった」とは書かない** — Validin の索引にある範囲で見えない、とだけ言う
（実測では組織のドメインで 2024-06 より前が 0 件だった。crt.sh には 2015 年からある）。

**呼び出し全体のエラー**（MCP は `{code, message}`、何も送らずに断る）: `invalid_domain`（手元の検査）、
`too_many_domains`、`no_api_key`、`history_unavailable`（Validin のキーが無いのに `--history`）、
`quota_exhausted`。

**キーが上流に拒まれたとき**（SSLMate 401 `bad_credentials`、Validin 403 `Unauthorized user` — 段階 0）は、
そのソースへの送信をその場でやめ、ソースの状態を `failed`・`code: "invalid_api_key"` とする。Validin の 403 は
回数を消費しない。

**上流のエラーメッセージはそのまま出さない**。SSLMate の `bad_credentials` の本文にはキーの先頭部分が載る
（段階 0）。上流の `code` と HTTP 状態から自前の文を作る。

**CLI の終了コード**: 0 は全ドメインで全ソースが答えた。**1 はどれかのドメインかソースが失敗した**
（`degraded`・ドメインごとの `error` を含む。部分的な答えを完全と読ませない）。2 は使用法の誤りと、
何も送らずに断った呼び出し全体のエラー。

**応答量**: MCP の応答は 128 KB（二重エスケープ後の実際の送信文字列で測る）を上限とする。超えたら、
**全ドメインを通して `not_before` の古い発行から**落とし、ドメインごとの `omitted` に件数を書く。要約は
全件から計算し、一覧は上記の件数上限で頭打ちにする。第三者の文字列はすべて長さに上限を持つ（§3）。

### Configuration

`~/.config/cert-lookup/config.toml`（nlink-jp/toml の厳格ローダ。未知のキーは拒否、構文エラーは
**行と桁だけ**を出し値を引用しない）。ファイルが 0600 より緩ければ警告する。

```toml
[sslmate]
api_key  = "..."   # 必須
# base_url = "https://api.certspotter.com"

[validin]
api_key  = "..."   # 任意。無ければ --history は history_unavailable
# base_url = "https://app.validin.com"

# [cache]
# dir = "~/.cache/cert-lookup"

# [network]
# timeout_seconds = 30
```

（段階 1 で、時間切れとキャッシュの置き場所は vpn-lookup と同じ `[network] timeout_seconds`・`[cache] dir` にした。
表の外に書く `timeout` はやめた — 書く位置を誤ると別の表のキーになる、という独立検証の指摘も同時に消える。）

環境変数は設定ファイルより優先する（vpn-lookup と同じ命名）: `CERT_LOOKUP_SSLMATE_API_KEY`、
`CERT_LOOKUP_SSLMATE_BASE_URL`、`CERT_LOOKUP_VALIDIN_API_KEY`、`CERT_LOOKUP_VALIDIN_BASE_URL`、
`CERT_LOOKUP_CACHE_DIR`、`CERT_LOOKUP_TIMEOUT_SECONDS`。

**キャッシュ**

- ソースごと、鍵は `(ソース, モード, ドメイン)` に `base_url` とキーの指紋を加えた範囲で区切る
  （キーや接続先を変えたら古い答えを使わない）。保持は **SSLMate 4 時間**（応答の
  `Cache-Control: max-age=14400` に合わせる。空の答えは上流の `max-age=900` に合わせて 15 分）、**Validin 7 日**（新しい発行は SSLMate 側で見えるので、
  Validin は過去を答えられれば足り、少ない回数を守る効果が大きい）。ディレクトリは 0700
- **失敗・`degraded`・エラー応答はキャッシュしない**。Validin の空の答えは、応答が `status: "finished"`
  で 0 件と明示したときだけキャッシュする（確かめられない空は保存しない）
- Validin の OpenAPI はこの経路に `x-cache: "no-store"` を付けている。これは経路の付記で規約ではないが、
  手元のキャッシュは規約 §4(c) の削除義務の範囲で持ち、`--clear-cache` で消せるようにする
- `--clear-cache` は壊れた設定でも動き、書きかけの一時ファイルも消す

### External Dependencies

- SSLMate CT Search API（`api.certspotter.com`、無料の Small プラン、キー必須）
- Validin（`app.validin.com`、無料の Community、キー任意）
- Go 標準ライブラリと nlink-jp/toml のみ。コミュニティ製の依存は入れない

## 3. Design Decisions

- **Go・依存は標準ライブラリと組織のライブラリだけ** — lookup 群と同じ。骨格は vpn-lookup から
  パッケージごとに移す（厳格な設定ローダ、キーの指紋で区切るキャッシュ、MCP の引数の厳格な検査、
  usage.md のメタテスト、128 KB 上限、リダイレクト拒否、エラーから URL を剥がす `guard`）
- **キーは Authorization ヘッダーだけで送る** — 両 API とも Bearer を受け付けるので、URL にキーを
  載せない。キーを持つクライアントはリダイレクトを拒否する（別ホストへキーが渡るのを防ぐ）
- **2 ソースを重ねる理由** — SSLMate は量（1 時間 100 回）と失効状態があるが有効期限内しか返さない。
  Validin は期限切れまで返すが 1 日 10 回。片方では「今」と「過去」の両方に答えられない
- **補い合う既存ツール** — whois-lookup（ドメインの登録日。発行日と並べると「作ってすぐ証明書を
  取った」が分かる）、doh-lookup（CAA レコードと今の DNS）、rdns-lookup（名前の網羅）、
  shodan-lookup（その証明書が実際にどの IP で使われているか）。完成後の mcp-tactics への収載は
  mcp-tactics 側の判断として別に扱う
- **同梱のスキルは作らない（ADR-027）** — 呼び方の約束は `get_usage` で足り、どの順で他のツールと
  組み合わせるかは mcp-tactics の領分。このツール固有の技法と呼べるものは無い
- **第三者の文字列** — 証明書の名前と発行元は認証局と申請者が書いたもので、事実の主張として扱う。
  制御文字・書式文字（Cc/Cf）を落とし、長さに上限を付ける（名前 253 字、発行元 200 字、失効理由など
  その他の文字列 200 字、1 証明書の名前は 100 件まで＋総数）

**範囲外**

- 定期的な見張り・通知、全証明書の流し読み（firehose、有料）
- CAA レコードの取得（DNS を引くので「相手に触れない」から外れる → doh-lookup）
- 似せたドメインの検索（どちらの API にも無い）
- 証明書本体（DER）の取得と解析（Validin では 1 回分を消費する）
- 証明書の SHA-256・公開鍵からの逆引き
- crt.sh（規約が公開されていない）
- 2024 年より前の履歴（無料のソースで規約を満たすものが無い）
- 国際化ドメイン名の Unicode からの変換

## 4. Development Plan

各段階の終わりで止まり、利用者の確認を得てから次へ進む。**Validin の回数は開発全体で 15 回まで**
（2026-11-07 時点で今月の残り 48 回）。

### Phase 0: 残りの実測（完了 2026-11-07）

[段階 0 の記録](cert-lookup-phase0.ja.md)。SSLMate のページと回数・公開サフィックス・誤ったキー・回数超過・
`match_wildcards`・DN、Validin の誤ったキー・存在しない名前・ワイルドカード・通し番号・DN・観測期間を測り、
本 RFP に反映した。Validin の消費は開発全体で 7 回（予算 15 回）。

### Phase 1: Core

雛形（`_wip/cert-lookup`）、設定、ドメインの検査、2 つのクライアント、発行のまとめ、ソースごとの
キャッシュ、CLI（text / JSON）。テストを一緒に書く。

### Phase 2: Features

MCP（`lookup_certs`・`cache_status`・`get_usage`）、照会前の Validin 残量確認、SSLMate の残りを
応答ヘッダー（`X-Ratelimit-Remaining`）から見せる、usage.md とメタテスト、応答量の上限。

### Phase 3: Release

実サービスでの e2e（環境変数を付けたときだけ動き、Validin は 1 回の実行で 1 回だけ）、README の日英、
AGENTS、CHANGELOG、リリース前の独立検証、リリースと org への統合。

独立検証は 2 回 — この RFP の確定時（2026-11-07 実施・反映済み）と、リリース前。

## 5. Required API Scopes / Permissions

- SSLMate CT Search API のキー（Small プラン・無料）。権限の範囲という概念は無い
- Validin Community のキー。同上
- **送り先**:
  - 照会したドメイン名 → SSLMate と Validin。SSLMate はリクエスト URL をサーバーログに残すと
    書いている（定期的に消去）
  - 結果 → CLI なら手元の端末だけ。**MCP で使うときは、答えが利用者の使う AI モデルの提供元にも渡る**
  - 調べる相手には何も届かない
- **組織自身の業務だけに使う**（Validin §3(e) "solely its own internal security purposes"）。顧客から
  受けた調査には使えない。Validin のアカウントは 1 人の名義に限られる（§3(c)）ので、キーもその人の
  ものとして扱い、人に渡さない
- **残余として受け入れること**: Validin §3(f)(1) は「サービスを第三者が利用できるようにすること」を
  禁じる。MCP 経由で答えがモデルの提供元に渡るのは、組織が自分の調査のために使う処理系への受け渡しで
  あり、サービスを第三者が利用できるようにすることには当たらないと読む（規約に AI・LLM での利用を
  禁じる条項は無い）。この読みが Validin と食い違えば、MCP での `--history` を止める

## 6. Series Placement

Series: cybersecurity-series
Reason: 第三者の索引を読む lookup 群の一つ。rdns-lookup・whois-lookup・doh-lookup と並ぶ。

## 7. External Platform Constraints

**SSLMate（ToS 2026-01-03、API 仕様、料金表を 2026-11-07 に一次確認）**

- 目的の制限はキー無しの利用だけ（API 仕様: "personal or evaluation purposes"）。ToS は違法・無許可の
  目的を禁じるだけ
- 無料（料金表）: 単一ホスト 1 時間 100 回、サブドメイン込み 1 時間 10 回、1 分 75 回、1 秒 5 回、
  1 照会 15 秒で打ち切り。混雑時は下がることがある。API 仕様は無料枠の機能を予告なく止め・変え・
  制限しうるとしている
- **有効期限内の証明書しか返さない**（API 仕様 "all unexpired"）。**古く見つけた順に返る**
- 1 ページ 100 件、空のページを含め 1 ページ 1 回。公開サフィックスは空の配列で答える（実測）
- 残りは応答ヘッダー `X-Ratelimit-Limit` / `X-Ratelimit-Remaining` に照会の種類別に出る。超えると 429
  `rate_limited` と `Retry-After`（秒）。枠は少しずつ回復する（実測）
- 誤ったキーは 401 `bad_credentials`、本文にキーの先頭部分が載る（実測）
- 同じ発行が別の `id` で重複する。`Link` ヘッダーのパスは誤っている（ともに実測）
- アカウントは人が自分で登録する（ToS）

**Validin（規約 2026-07 版を 2026-11-07 に一次確認）**

- §3(e) 自社の社内セキュリティ目的のみ、§3(d) 回数の上限を回避しない、§3(f)(1) 第三者に利用させない、
  §4(c) 終了時に取得物と控えを削除、§4(d) 無料は予告なく終了しうる。生成 AI・LLM での利用を禁じる条項は無い
- 無料: 1 日 10 回・月 50 回、1 回 250 件。接続先は `app.validin.com`（`api.validin.com` は DNS に無い）
- 応答の形（`limited` を含む）と並び順は文書に無く、実測だけが根拠
- 文書は CT を 2020 年から集めているとするが、**実測では組織のドメインで 2024-06 より前が 0 件**
  （観測期間を明示しても 0）。無料枠の制限か索引の深さかは未確定
- **期間を指定しないと直近の一部しか返らず、指定しても大きなドメインでは月ごとに抜ける。`limited: false` でも
  全件とは限らない**（実測: google.com）
- 単一ホストの照会でワイルドカード証明書を返さない。通し番号は応答に無い。誤ったキーは 403 で回数を消費しない。
  0 件の答えも 1 回と数える（実測）
- `/api/profile/usage` は回数を消費しない（実測）

---

## Discussion Log

- **発端（2026-11-07）**: OSINT の追加ソース調査の表にあった SSLMate CT Search API を、利用者が
  「CT の検索ができると良さそう」と取り上げた。規約を一次確認し、キー付きなら目的の制限が無いことを
  確かめた
- **履歴の問題**: SSLMate は有効期限内しか返さないと分かり、利用者が「履歴が欲しい」。候補を洗った —
  Validin（無料枠に CT 履歴、規約は社内セキュリティ可）、crt.sh（全期間だが規約なし・応答 43 秒・
  最新の発行が欠けていた）、Merklemap（無償枠なし）
- **Validin の実測**: 利用者が無料キーを用意。証明書履歴のエンドポイントは無料キーで答え、期限切れも
  返したが、組織のドメインで 2024-06 より前は 0 件（crt.sh には 2015 年から約 49 発行）。利用者は
  「Validin＋SSLMate」を選んだ（深い履歴は諦める）
- **SSLMate の実測**: 利用者がキーを用意。残りが応答ヘッダーに出る、同じ発行の重複、`Link` の誤り、
  Validin の本証明書の SHA-256 と `cert_sha256` の一致を確認
- **問題定義**: 使い道は (a) 不審なドメインの調査と (b) 自社ドメインの 1 回ごとの点検。見張りは範囲外。
  名前の網羅は rdns-lookup に任せる。名前は利用者が `ct-lookup` ではなく `cert-lookup` を選んだ
- **機能仕様**: Validin は `--history` のときだけ、SSLMate のキーは必須（キー無しは個人・評価目的に
  限られるため）、CAA との照合はしない（DNS を引くため。doh-lookup の役）、1 回 20 件まで・残り回数が
  足りなければ照会前に断る — いずれも利用者が承認
- **設計判断**: 国際化ドメイン名は ASCII だけ受け付けて断る、キャッシュは SSLMate 4 時間・Validin 7 日、
  単一ホストでもワイルドカード証明書を含める — 利用者が承認
- **開発計画**: Validin は開発全体で 15 回まで、e2e は環境変数で有効にし Validin は 1 回の実行で 1 回、
  独立検証は RFP 確定時とリリース前 — 利用者が承認
- **設計の独立検証（2026-11-07）**: 11 件の指摘を全部採用した — SSLMate は古い順に返るのでページ上限で
  新しい発行が欠ける（`newest_missing`、最新を出さない）、終了コード 1 を「どれかが失敗」に（vpn-lookup と
  教訓に合わせる）、SSLMate のサブドメイン照会 1 時間 10 回に対し順送り・間隔・残り 0 で打ち切り、要約の
  一覧にも上限と全ドメインを通した落とし方、失敗・確かめられない空をキャッシュしない・残量は日と月の小さい
  方・`--refresh` は全件を数える、まとめ方の前提（通し番号・DN の書き方・RSA と ECDSA）を段階 0 で測る、
  `no_key` 状態の削除・ドメインごとのエラーと呼び出し全体のエラーの区別・失効の表し方を 1 つに、環境変数と
  0600 の警告、TOML 例の誤り、MCP での送り先と Validin §3(f)(1) の読み、ADR-027（同梱スキル不要）・
  SSLMate 残量の観測時刻・`expired` は答える時点・ラベル先頭末尾のハイフン
- **段階 0（2026-11-07）**: SSLMate は公開サフィックスを断らず空で答える（RFP の前提を訂正）、1 ページ 100 件で
  ページごとに 1 回、誤ったキーの本文にキーの先頭部分、回数超過は 429 と `Retry-After`。Validin は期間を
  指定しないと直近の一部しか返さず、指定しても大きなドメインでは月ごとに抜ける — **利用者は「標本と明示して
  進む」を選んだ**。SSLMate の最後のページは、文書どおり空のページで確かめる（ADR-023: 文書に無い近道に
  乗らない。回数は 1 ドメインあたり 1 回増える）
