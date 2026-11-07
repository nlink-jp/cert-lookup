# AGENTS.md — cert-lookup

## Summary

A CLI (and, from Phase 2, a local MCP server) that answers what the public Certificate
Transparency logs recorded for a domain: when and by which CA each certificate was issued,
which other names were on it, and whether it is still valid or revoked. It layers the
SSLMate CT Search API (currently valid certificates, revocation) and Validin (past
issuances — a sample, never complete) into one merged list with a per-domain summary.

Module path: `github.com/nlink-jp/cert-lookup`. Design authority:
[docs/ja/cert-lookup-rfp.ja.md](docs/ja/cert-lookup-rfp.ja.md) (English beside it);
measurements in [docs/ja/cert-lookup-phase0.ja.md](docs/ja/cert-lookup-phase0.ja.md).

**Status: in development (Phase 1 done: CLI; Phase 2: MCP; Phase 3: release).**

## Build / test

```bash
make build   # → dist/cert-lookup (NEVER `go build` directly)
make test    # go test -race -cover ./... then go vet -tags e2e ./...  (offline)
make lint    # golangci-lint — before every commit
make check   # lint + test + build-all
```

Go 1.25+. One dependency, the organization's TOML decoder `github.com/nlink-jp/toml`
(ADR-026). Everything else is the standard library.

## Layout

```
main.go              Entry point; delegates to internal/app
source_test.go       No raw control or bidi character in any source file
internal/config/     Strict TOML + CERT_LOOKUP_* loader (ported from vpn-lookup)
internal/guard/      Clean/Cap (Cc/Cf, length caps), RefuseRedirects, ScrubURL
internal/domain/     The ASCII-only domain gate (punycode for IDN), batch of ≤20, Inside()
internal/upstream/   Shared error type (our own messages only) and a bounded body read
internal/sslmate/    SSLMate CT Search v1 client: one page per call, allowance headers
internal/validin/    Validin certificate-history (lookback=1095) and usage client
internal/issuance/   Pure merge (tbs_sha256 → cert fingerprint → issuer C/O/CN + validity
                     + names) and the per-domain summary; DN parsing
internal/cache/      Per-source JSON-file cache (ported from vpn-lookup), dir 0700
internal/engine/     Page walk with caps and pacing, per-kind allowance stops, the Validin
                     quota check before sending, per-source cache, merge
internal/app/        CLI shell: flags (anywhere), validation, text/JSON, --clear-cache
docs/{en,ja}/        RFP and the Phase 0 record
```

## Copy sources

- config, guard, cache, the Makefile and `source_test.go`: vpn-lookup (the newest sibling)
- `scripts/`: copied from vpn-lookup, which holds them byte-identical to
  `nlink-jp/.github/templates/` (check-org check 10)

## Gotchas (measured — see the Phase 0 record)

- **SSLMate returns oldest first, 100 to a page, and every page counts** (an empty one too).
  The walk ends only on an empty page (the documented signal), within 5 pages for a single
  host and 3 with subdomains; a cut sets `truncated: "newest_missing"` and hides the latest.
- **SSLMate answers a public suffix (`com`, `co.jp`) with an empty list.** Empty is never
  worded as "nothing issued".
- **SSLMate's `bad_credentials` message quotes the leading part of the key.** No upstream
  message is passed through; `internal/upstream` builds our own.
- **SSLMate's `Link` header drops `/v1`.** Pages are built from `after=`.
- **SSLMate meters single-host and subdomain queries apart** (100 / 10 an hour); a 429
  carries `Retry-After` seconds and the allowance refills gradually. The engine stops a kind
  at a zero remainder or a 429 and sends no more of it in that call.
- **Validin without a window returns only a recent subset**; with one, large domains still
  miss whole months and `limited` stays false. Always `lookback=1095`; history is a sample.
- **Validin's single-host query returns no covering wildcard certificates**, has no serial
  number, and is `app.validin.com` (`api.validin.com` does not resolve).
- **Validin's 403 spends nothing; a zero-record answer spends one query.**
- **Issuer DNs differ in format** (SSLMate `C=US, O=…`, Validin `/C=US/O=…` plus components);
  the merge compares C, O and CN.

## Decisions (from the RFP — do not silently reverse)

- SSLMate key required (keyless is personal/evaluation only); Validin only with `--history`.
- No CAA lookup (it resolves DNS — doh-lookup's job); `caa_domains` is returned for comparison.
- ASCII input only; non-ASCII is refused with "pass punycode".
- Cache: SSLMate 4 h (15 min when empty), Validin 7 days; failures never cached.
- For the organization's own work only (Validin §3(e)).
