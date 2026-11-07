# CLAUDE.md — cert-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server that answers which certificates the public CT logs recorded for a
domain — when, by which CA, for which other names, and whether revoked — by layering the
SSLMate CT Search API (current certificates) and Validin (past issuances, a sample).

Design authority: [docs/ja/cert-lookup-rfp.ja.md](docs/ja/cert-lookup-rfp.ja.md).
Measured behaviour: [docs/ja/cert-lookup-phase0.ja.md](docs/ja/cert-lookup-phase0.ja.md).
Contributor summary and gotchas: [AGENTS.md](AGENTS.md).

## Build & test

```bash
make build   # never `go build` directly
make test    # offline
make lint    # run it before every commit, not only the tests
make e2e     # live; keys from CERT_LOOKUP_SSLMATE_API_KEY / CERT_LOOKUP_VALIDIN_API_KEY
```

## Key conventions

- **Validin allows 10 queries a day and 50 a month.** Count every live Validin query; the
  development budget is in the RFP. Unit tests never reach the network.
- **Measure before you code a response shape.** Validin's shape is undocumented; SSLMate has
  undocumented edges (public suffixes answer empty, the `Link` header is wrong). Pin what was
  measured in tests.
- **A negative answer is never manufactured.** An empty SSLMate answer is "nothing held",
  not "nothing issued"; Validin's history is a sample; a failure is never cached.
- **Keys never appear on any output surface.** Authorization header only, redirects refused,
  no URL and no upstream error text in any message (SSLMate echoes part of a bad key).
- **Input that is not understood is refused**: unknown config keys, empty values, non-ASCII
  names (punycode only), URLs, IPs, wildcards.
- **No raw control or bidi character in any source file** (`source_test.go`). Writing a
  backslash-u escape of a bidi override through a tool has turned it into the raw character; re-escape.

## Communication Language

All communication between contributors and Claude Code is conducted in **Japanese**.
