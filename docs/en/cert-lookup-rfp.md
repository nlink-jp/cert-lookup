# RFP: cert-lookup

> Generated: 2026-11-07
> Status: Draft (all 7 items agreed with the owner; independent design review applied; Phase 0 measurements applied — [Phase 0 record](cert-lookup-phase0.md))

## 1. Problem Statement

For a domain under investigation, answer what the public Certificate Transparency (CT) logs
recorded about its certificates. Three things are answered: **when and by which certificate
authority each certificate was issued**, **which other names were on the same certificate's
SAN**, and **whether it is still valid or was revoked**. Currently valid certificates and their
revocation status come from the **SSLMate CT Search API**; past issuances come from **Validin**; the
two are merged into one answer. Validin's history is a sample and is never claimed complete (for
domains with few issuances about two and a half years came back whole; for large domains whole months
are missing — Phase 0). Nothing is sent to
the investigated party's servers or DNS — only third-party indexes are read.

The users are this organization's security investigators and investigation agents over MCP.
Two uses are intended, **both limited to the organization's own work** (Validin terms §3(e)):

1. **Investigating a suspicious domain** — was a certificate issued just now (a sign of freshly
   built attack infrastructure), by which CA, and do the SANs lead to related domains.
2. **Checking the organization's own domains** — is there an issuance nobody recognizes, answered
   once, when asked. Continuous monitoring and alerting are out of scope (that is the job of a
   dedicated service such as SSLMate's Cert Spotter).

Among the current tools only rdns-lookup (CT-derived **names**, as part of its index) and
shodan-lookup (certificates **observed** on an IP) touch certificates; neither answers "the
certificates issued for this domain, with issuer, validity and revocation".

## 2. Functional Specification

### Commands / API Surface

**CLI**

```
cert-lookup [flags] <domain> [domain...]   # 1-20 as arguments; with none, one per line from stdin
  --subdomains      # also include certificates for subdomains (any depth)
  --history         # also fetch past issuances from Validin (spends Validin queries)
  --json            # structured output (default: human-readable text)
  --refresh         # bypass the cache
  --timeout <dur>   # upstream timeout
  --config <path>   # config file
  --clear-cache     # delete the whole cache (to meet Validin terms §4(c) deletion duty)
  --version         # mandatory (brew test calls it)
cert-lookup mcp     # local MCP server (stdio)
```

- By default only SSLMate is queried. **Validin only with `--history`** (it allows 10 queries a day)
- A single-host query also includes wildcard certificates covering that host (`*.example.com` for
  `www.example.com`) — SSLMate's `match_wildcards=true`
- Every input is checked locally before anything is sent (one entry failing the check and nothing is
  sent); duplicates are removed. A failure after sending (exceeded limit, timeout and the like) fails
  that domain only (see "Failures" below)
- **Queries are sent one at a time.** SSLMate requests are spaced to stay under 5 a second; once the
  `X-Ratelimit-Remaining` response header reaches 0, the remaining domains are not sent and each gets
  `rate_limited` (subdomain queries allow only 10 an hour, so 20 cannot all go through at once)

**Domain validation (before any query; nothing leaves the machine)**

- ASCII only (punycode `xn--` labels included). **Non-ASCII input (e.g. a Japanese domain) is
  refused with "pass it as punycode"** — IDNA mapping tables are not in the standard library, and
  a correct implementation of our own would be heavy
- Lowercased; one trailing dot removed. Labels are letters, digits and hyphens, 1-63 characters,
  **not starting or ending with a hyphen**; 253 characters in all; at least two labels
- Refused: IP addresses, names containing `*`, URLs (with scheme, path or port), whitespace and
  control characters
- Whether the name is a registrable domain (as opposed to a public suffix such as `co.jp`) is not
  judged locally. **SSLMate does not refuse public suffixes; it answers with an empty array** (Phase 0:
  `com`, `co.jp`). An empty answer says "SSLMate holds no unexpired certificate for this name (public
  suffixes and unindexed names are empty too)" and never "no issuance"

**MCP tools**

| tool | role |
|---|---|
| `lookup_certs` | Merged issuances and a summary for 1-20 domains. Arguments `domains[]`, `subdomains`, `history`, `refresh` |
| `cache_status` | Which keys are set; cache entries, retention and location; remaining queries at both sources (Validin's daily and monthly from its usage API; SSLMate per query kind — single-host and subdomain — from the last response header together with **when it was observed**) |
| `get_usage` | The manual (usage.md embedded and checked against the code by meta-tests) |

Without an SSLMate key the MCP server still starts and `cache_status` and `get_usage` answer;
`lookup_certs` returns the structured error `no_api_key`. The CLI treats a missing key as a usage
error (exit 2).

### Input / Output

**Building the queries**

- SSLMate: `GET https://api.certspotter.com/v1/issuances?domain=<d>` with
  `include_subdomains=false&match_wildcards=true` for a single host, `include_subdomains=true` with
  `--subdomains`, and always `expand=dns_names,issuer,issuer.caa_domains,revocation`. Pages are
  walked by passing the last `id` as `after=` until an empty page. **The response's `Link` header
  is not used** (measured: its path drops `/v1`)
- **SSLMate returns issuances oldest-discovered first** (docs: "in the order that they were
  discovered"; without `after`, the "least-recently-discovered"; confirmed in Phase 0). New issuances
  come last, so a page cap **loses the newest first**. Beyond the cap `truncated: "newest_missing"` is
  set and the summary's "latest issuance" is not reported
- **A page holds 100 issuances, and every page counts as one query, empty pages included** (Phase 0).
  The end is confirmed with an empty page as documented (treating a page under 100 as the last is not
  documented and is not used). A domain with N issuances therefore costs ceil(N/100)+1 queries. The
  page cap is **5 pages (500 issuances) for a single host and 3 pages (300) with subdomains**, and the
  walk stops earlier when the remaining allowance reaches 0. Large domains are not fetched whole — one
  page is 540-608 KB (google.com, Phase 0) and would not fit an MCP response anyway
- Validin: `GET https://app.validin.com/api/axon/domain/certificates/<d>?wildcard=<subdomains>&limit=250&lookback=1095&time_format=unix`.
  **The window is always sent explicitly as `lookback=1095` (three years)** — without a window only a
  recent subset comes back (Phase 0: only August and November 2026 for google.com). SSLMate answers for
  current certificates, so Validin is asked for the past
- **Validin's history is a sample** (accepted by the owner). For large domains whole months are missing
  even with an explicit window, and `limited` still says `false` (Phase 0). The answer states the range
  Validin returned (first and last observation dates) and the count, and says that Validin may return
  only part. Completeness is never claimed. For a domain with few issuances it came back whole within
  the index's depth (the organization's domain)
- **Validin does not return covering wildcard certificates for a single-host query** (Phase 0). A
  single host's history holds only certificates naming it, and `notes` says wildcard certificates are
  not included (querying the parent spends another query, so it is not done automatically)
- With `--history`, `GET /api/profile/usage` (which spends no query) is read first. If **the smaller
  of the daily and monthly remainders** is less than the number of domains that need a query (those
  missing from the cache; all of them with `--refresh`), nothing is sent and `quota_exhausted` is returned

**Merging issuances**

One issuance comes back in several shapes — SSLMate returns the same issuance under different
`id`s (measured), and Validin returns the precertificate and the certificate once per CT log that
recorded them (measured: 18 records → 4 issuances).

1. Within SSLMate, merge by `tbs_sha256` (docs: it uniquely identifies the issuance)
2. A Validin certificate whose `fingerprint_sha256` equals SSLMate's `cert_sha256` is the same issuance
   (measured: they matched). SSLMate's `cert_sha256` is the precertificate's when the certificate is
   not known, so a match can be missed
3. Everything else (Validin precertificates, past issuances SSLMate no longer returns) is merged on
   equal **issuer components (C, O, CN), `not_before`, `not_after` and name set** (Validin may leave
   the CN out of `domains`, so the CN is added). The serial number (the RFC 5280 identity) is not in
   Validin's response and cannot be used (Phase 0). SSLMate formats the issuer DN comma-separated
   (`C=US, O=…, CN=WE2`), Validin slash-separated (`/C=US/O=…/CN=WR2`) plus a component table
   (`issuer: {C, O, CN}`), so SSLMate's DN is split into components following RFC 4514 escaping and
   components are compared. An RSA and an ECDSA certificate issued together came from different
   intermediates (Phase 0: cloudflare.com), so a tuple that includes the issuer keeps them apart

**One issuance (JSON)**

| field | content |
|---|---|
| `names` | Names the certificate is valid for (SANs plus CN) |
| `issuer` | `name` (SSLMate's curated name, else the DN's O/CN) and `dn` |
| `not_before` / `not_after` | Validity period |
| `expired` | Expired **at the time the answer is given** (not when it was cached) |
| `revocation` | `status` (`revoked` / `not_revoked` / `unknown`), `time`, `reason` (RFC 5280 reason code; the docs warn that CAs do not always give an accurate reason), `checked_at`. `unknown` when SSLMate does not know (`null`) and for issuances SSLMate does not return (expired, or Validin only) |
| `caa_domains` | CAA values that authorize this CA (SSLMate). Comparing with CAA records is done with doh-lookup |
| `cert_sha256` | SHA-256 of every certificate / precertificate seen |
| `tbs_sha256` | When SSLMate returned it |
| `logged_at` | When Validin observed it in a CT log (if known) |
| `seen_by` | `sslmate` / `validin` / both |

**Per-domain result**

- Summary: number of issuances, earliest and latest `not_before` (the side lost to `truncated` is not
  reported), list of CAs (up to 20 plus the total)
- `names_outside` — **SAN names outside the queried domain and its subtree** (leads to related
  domains; no public-suffix judgment needed). Up to 100 plus the total
- `sources` — the state of `sslmate` and `validin` (`ok` / `failed` / `not_requested`) and, on
  failure, its `code`
- `history` (with `--history`) — the range Validin returned (`observed_from` / `observed_to`), the
  count, and `sample: true` (Validin may return only part)
- `truncated` — `"newest_missing"` when SSLMate's walk hit the page cap. `notes` (one source failed,
  history not requested, Validin's history is a sample, a single host's history excludes wildcard
  certificates, an empty answer does not mean no issuance)
- `error` — a failure of that domain only (`rate_limited`, `timeout`, `upstream_error`).
  `rate_limited` carries upstream's `Retry-After` as `retry_after_seconds`. Kept apart from failures
  that stop the whole call (below)

**Failures**: when one source fails, that domain is `degraded: true` and the answer rests on what
remains. **An empty history is never reported as "no issuance"** — only as not visible within what
Validin's index holds (measured: nothing before 2024-06 for the organization's domain, while crt.sh
has issuances back to 2015).

**Whole-call errors** (MCP `{code, message}`; refused before anything is sent): `invalid_domain`
(local check), `too_many_domains`, `no_api_key`, `history_unavailable` (`--history` without a Validin
key), `quota_exhausted`.

**When upstream rejects a key** (SSLMate 401 `bad_credentials`, Validin 403 `Unauthorized user` —
Phase 0), sending to that source stops at once and the source's state becomes `failed` with
`code: "invalid_api_key"`. Validin's 403 spends no query.

**Upstream error messages are never shown as is.** SSLMate's `bad_credentials` message carries the
leading part of the key (Phase 0). Our own text is built from upstream's `code` and HTTP status.

**CLI exit codes**: 0 when every source answered for every domain. **1 when any domain or source
failed** (including `degraded` and per-domain `error`; a partial answer must not read as complete).
2 for usage errors and for whole-call errors refused before sending.

**Response size**: an MCP response is capped at 128 KB (measured on the escaped text actually sent).
Beyond it, issuances are dropped **oldest `not_before` first across all domains**, and each domain's
`omitted` counts them. Summaries are computed from everything; lists are capped as above. Every
third-party string has a length cap (§3).

### Configuration

`~/.config/cert-lookup/config.toml` (strict loader on nlink-jp/toml: unknown keys are refused; a
syntax error reports **line and column only**, never the value). A file looser than 0600 draws a warning.

```toml
# timeout = "30s"   # keep above the first table (after [validin] it would be validin.timeout and refused)

[sslmate]
api_key  = "..."   # required
# base_url = "https://api.certspotter.com"

[validin]
api_key  = "..."   # optional; without it --history returns history_unavailable
# base_url = "https://app.validin.com"
```

Environment variables override the file (named as in vpn-lookup): `CERT_LOOKUP_SSLMATE_API_KEY`,
`CERT_LOOKUP_SSLMATE_BASE_URL`, `CERT_LOOKUP_VALIDIN_API_KEY`, `CERT_LOOKUP_VALIDIN_BASE_URL`,
`CERT_LOOKUP_CACHE_DIR`, `CERT_LOOKUP_TIMEOUT_SECONDS`.

**Cache**

- Per source, keyed by `(source, mode, domain)` within a scope of `base_url` and a key fingerprint
  (changing the key or endpoint never serves an old answer). Retention: **SSLMate 4 hours** (matching
  the response's `Cache-Control: max-age=14400`; empty answers 15 minutes, matching upstream's
  `max-age=900`), **Validin 7 days** (new issuances are visible
  through SSLMate, so Validin only has to answer the past, and the longer retention protects a small
  quota). Directory mode 0700
- **Failures, `degraded` results and error responses are never cached.** An empty Validin answer is
  cached only when the response says `status: "finished"` with zero records (an empty answer that
  cannot be confirmed is not stored)
- Validin's OpenAPI marks this route `x-cache: "no-store"`. That is route metadata, not a term; the
  local cache is held within the terms' §4(c) deletion duty and can be removed with `--clear-cache`
- `--clear-cache` works with a broken config and also removes half-written temporary files

### External Dependencies

- SSLMate CT Search API (`api.certspotter.com`, free Small plan, key required)
- Validin (`app.validin.com`, free Community, key optional)
- Go standard library and nlink-jp/toml only. No community dependencies

## 3. Design Decisions

- **Go, standard library and organization libraries only** — like the rest of the lookup family.
  The skeleton is ported package by package from vpn-lookup (strict config loader, cache scoped by
  a key fingerprint, strict MCP argument checks, usage.md meta-tests, the 128 KB ceiling, refused
  redirects, the `guard` that strips URLs from errors)
- **Keys travel only in the Authorization header** — both APIs accept a Bearer token, so no key is
  ever put in a URL. Key-carrying clients refuse redirects (so a key never follows to another host)
- **Why two sources** — SSLMate has volume (100 queries an hour) and revocation status but returns
  only unexpired certificates; Validin returns expired ones too but allows 10 queries a day. Neither
  alone answers both "now" and "before"
- **Tools it complements** — whois-lookup (registration date; next to the issuance date it shows
  "certificate obtained right after registration"), doh-lookup (CAA records and current DNS),
  rdns-lookup (exhaustive names), shodan-lookup (which IPs actually serve that certificate).
  Listing it in mcp-tactics afterwards is mcp-tactics' own decision and handled separately
- **No bundled skill (ADR-027)** — `get_usage` covers the call contract, and the order in which it is
  combined with other tools belongs to mcp-tactics. There is no tool-specific craft to ship
- **Third-party text** — certificate names and issuers are written by CAs and applicants and treated
  as claims. Control and format characters (Cc/Cf) are dropped and lengths are capped (name 253,
  issuer 200, other strings such as revocation reasons 200, at most 100 names per certificate plus
  the total)

**Out of scope**

- Continuous monitoring and alerting; the all-certificates firehose (paid)
- Fetching CAA records (that resolves DNS, against "never touch the party" → doh-lookup)
- Lookalike-domain search (neither API offers it)
- Fetching and parsing the certificate body (DER) (Validin charges a query for it)
- Reverse lookup from a certificate SHA-256 or public key
- crt.sh (its terms are not published)
- History before 2024 (no free source that meets the terms has it)
- Converting internationalized domain names from Unicode

## 4. Development Plan

Each phase ends with a stop for the owner's review. **Validin queries are capped at 15 for the whole
development** (48 left this month as of 2026-11-07).

### Phase 0: remaining measurements (done 2026-11-07)

[Phase 0 record](cert-lookup-phase0.md). SSLMate's pages and counting, public suffixes, wrong key,
exceeded limit, `match_wildcards` and DN; Validin's wrong key, nonexistent names, wildcards, serial
number, DN and observation window were measured and applied to this RFP. Validin spent: 7 queries for
the whole development (budget 15).

### Phase 1: Core

Scaffold (`_wip/cert-lookup`), config, domain validation, both clients, issuance merging, per-source
cache, CLI (text / JSON), with tests.

### Phase 2: Features

MCP (`lookup_certs`, `cache_status`, `get_usage`), the Validin quota check before querying, SSLMate's
remaining queries from its response header (`X-Ratelimit-Remaining`), usage.md and meta-tests, the
response-size ceiling.

### Phase 3: Release

Live e2e (enabled only by an environment variable; one Validin query per run), README in English
and Japanese, AGENTS, CHANGELOG, the pre-release independent review, release and organization
integration.

Two independent reviews — when this RFP is settled (done and applied 2026-11-07), and before release.

## 5. Required API Scopes / Permissions

- An SSLMate CT Search API key (Small plan, free). There is no notion of scopes
- A Validin Community key. Same
- **Where things go**:
  - Queried domain names → SSLMate and Validin. SSLMate states that it logs request URLs in its
    server logs (purged periodically)
  - Results → only the local terminal for the CLI. **Over MCP, answers also reach the provider of
    the AI model the operator uses**
  - Nothing reaches the investigated party
- **Used for the organization's own work only** (Validin §3(e) "solely its own internal security
  purposes"); not for investigations done for clients. A Validin login belongs to a single named
  individual (§3(c)), so the key is treated as that person's and never handed to others
- **Accepted residual**: Validin §3(f)(1) forbids making the Services available to any third party.
  Answers reaching the model provider over MCP are a hand-off to processing the organization uses for
  its own investigation, and are read as not making the Services available to a third party (the
  terms have no clause against use with AI or LLMs). Should Validin read it otherwise, `--history`
  over MCP is switched off

## 6. Series Placement

Series: cybersecurity-series
Reason: one of the lookup tools that read third-party indexes, next to rdns-lookup, whois-lookup and
doh-lookup.

## 7. External Platform Constraints

**SSLMate (ToS 2026-01-03, API reference and pricing read first-hand on 2026-11-07)**

- The only purpose restriction is on keyless use (API reference: "personal or evaluation purposes").
  The ToS only forbids illegal or unauthorized purposes
- Free (pricing page): 100 single-hostname queries an hour, 10 full-domain queries an hour, 75 a
  minute, 5 a second, 15-second query timeout; these may drop under load. The API reference says
  free-tier functionality may be discontinued, altered or restricted at any time without notice
- **Only unexpired certificates are returned** (API reference "all unexpired"), **oldest-discovered first**
- 100 issuances per page; every page counts as one query, empty pages included; public suffixes are
  answered with an empty array (measured)
- Remaining queries appear per query kind in the `X-Ratelimit-Limit` / `X-Ratelimit-Remaining`
  response headers. Beyond them, 429 `rate_limited` with `Retry-After` (seconds); the allowance refills
  gradually (measured)
- A wrong key gets 401 `bad_credentials`, and the message carries the leading part of the key (measured)
- The same issuance appears under different `id`s; the `Link` header's path is wrong (both measured)
- Accounts are registered by a human (ToS)

**Validin (terms, July 2026 version, read first-hand on 2026-11-07)**

- §3(e) own internal security purposes only; §3(d) do not circumvent limits; §3(f)(1) do not make the
  Services available to third parties; §4(c) on termination delete output and copies; §4(d) free
  services may end without notice. No clause forbids use with generative AI or LLMs
- Free: 10 queries a day, 50 a month, 250 results per query. Endpoint `app.validin.com`
  (`api.validin.com` does not exist in DNS)
- The response shape (including `limited`) and the order are undocumented; only measurement supports them
- The documentation says CT has been collected since 2020, but **measured, the organization's domain
  shows nothing before 2024-06** (zero even with an explicit observation window). Whether that is a
  free-tier limit or the depth of the index is unsettled
- **Without a window only a recent subset comes back, and even with one, large domains miss whole
  months. `limited: false` does not mean complete** (measured: google.com)
- A single-host query returns no wildcard certificates; there is no serial number in the response; a
  wrong key gets 403 and spends no query; a zero-record answer still counts as one query (measured)
- `/api/profile/usage` spends no query (measured)

---

## Discussion Log

- **Origin (2026-11-07)**: the owner picked the SSLMate CT Search API from the OSINT source survey
  ("CT search would be good"). Its terms were read first-hand: keyed use has no purpose restriction
- **The history problem**: SSLMate returns only unexpired certificates, and the owner wanted history.
  Candidates — Validin (CT history in the free tier; terms allow internal security), crt.sh (full
  history but no terms, a 43-second response, and the latest issuance missing), Merklemap (no free tier)
- **Validin measured**: the owner provided a free key. The certificate-history endpoint answered on
  the free key and returned expired certificates, but nothing before 2024-06 for the organization's
  domain (crt.sh has about 49 issuances from 2015). The owner chose "Validin + SSLMate", giving up deep
  history
- **SSLMate measured**: the owner provided a key. Remaining queries in response headers, duplicated
  issuances, the wrong `Link` header, and Validin certificate SHA-256 equal to `cert_sha256` confirmed
- **Problem statement**: (a) investigating suspicious domains and (b) one-off checks of own domains;
  monitoring out of scope; exhaustive names left to rdns-lookup. The owner chose the name
  `cert-lookup` over `ct-lookup`
- **Functional specification**: Validin only with `--history`; SSLMate key required (keyless use is
  personal/evaluation only); no CAA comparison (it resolves DNS — doh-lookup's job); 20 domains per
  call and a refusal before querying when the Validin quota is short — all approved by the owner
- **Design decisions**: ASCII only with a refusal for internationalized names; cache SSLMate 4 hours,
  Validin 7 days; wildcard certificates included for single hosts — approved by the owner
- **Development plan**: at most 15 Validin queries during development; e2e behind an environment
  variable with one Validin query per run; independent reviews at RFP settlement and before release —
  approved by the owner
- **Independent design review (2026-11-07)**: all 11 findings adopted — SSLMate returns oldest first,
  so a page cap loses the newest (`newest_missing`, latest not reported); exit code 1 means "anything
  failed" (as in vpn-lookup and the recorded lesson); sequential, spaced SSLMate queries that stop at a
  zero remainder against the 10-an-hour subdomain limit; caps on summary lists and a drop order across
  domains; failures and unconfirmed empties never cached, the quota check uses the smaller of daily and
  monthly and counts every domain under `--refresh`; the merge premises (serial number, DN format, RSA
  and ECDSA twins) measured in Phase 0; the `no_key` state removed, per-domain errors kept apart from
  whole-call errors, one shape for revocation; environment variables and the 0600 warning; the TOML
  example bug; destinations over MCP and the reading of Validin §3(f)(1); ADR-027 (no bundled skill),
  SSLMate remainder with its observation time, `expired` at answer time, hyphens at label edges
- **Phase 0 (2026-11-07)**: SSLMate does not refuse public suffixes but answers empty (an RFP premise
  corrected); 100 issuances per page and one query per page; a wrong key's message carries the key's
  leading part; an exceeded limit is 429 with `Retry-After`. Validin returns only a recent subset
  without a window, and large domains miss whole months even with one — **the owner chose "proceed,
  stating it is a sample"**. SSLMate's last page is confirmed with an empty page as documented
  (ADR-023: no undocumented shortcut; one more query per domain)
