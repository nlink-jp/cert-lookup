# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The MCP server speaks both eras of the protocol** (ADR-0001): the
  2026-07-28 revision, whose clients probe with `server/discover`, as well as
  the earlier `initialize` handshake (2025-11-25, 2025-06-18, 2024-11-05). The
  protocol layer is now the organization's shared module nlink-jp/mcp
  (organization ADR-030); the tools, their arguments and their results are
  unchanged.

### Changed

- Protocol details now follow the module:
  - an unknown tool is -32602 (it was an isError `unknown_tool` result, now
    gone from usage.md);
  - `tools/list`, `tools/call` and unknown methods before `initialize` are
    refused with -32602 (an unknown method was -32601);
  - `arguments` that is not an object is refused with -32602 before reaching
    the tool;
  - a request with `"id":null`, or without `"jsonrpc":"2.0"`, gets -32600;
  - messages are read one per line (up to 16 MiB) instead of as a JSON stream;
  - a parse error or a batch no longer ends the server (a batch gets -32600);
  - a panic in a tool is answered -32603 and the server goes on (it crashed);
  - up to 256 calls wait behind a running one; more are refused with -32603
    "server busy";
  - `notifications/cancelled` now cancels the call.
    A cancelled `lookup_certs` still runs to its end — the engine takes no
    context — and its answer is dropped; the cache is written whole to a
    temporary file and renamed, so no entry is ever partial; a temp file left
    by a process ended part-way (a SIGTERM past the shutdown grace) is removed
    by `cache clear`.

  Requests piped in are still all answered before the server exits at end of
  input.
- `mcp.Serve` takes a context first, cancelled by SIGINT and SIGTERM in the
  `mcp` subcommand.

### Fixed

- SIGINT or SIGTERM ended the MCP server by killing the process; a signal now ends it through its context, so its cleanup runs.

## [0.1.1] - 2026-11-27

### Changed

- `make package` runs `govulncheck ./...` first (`make vuln`) and stops on a
  finding, so a release cannot be built past one.
- `make vuln` — and so `make package` — scans every platform in `PLATFORMS`,
  with the environment `build-all` builds each with. It scanned the host's
  build alone, so an advisory in a Linux- or Windows-only package could not
  stop a release.

### Fixed

- **`initialize` no longer echoes back whichever protocol version the client
  asks for.** The server answers with the requested revision only when it
  satisfies it (2025-11-25, 2025-06-18 or 2024-11-05), and with 2025-11-25
  otherwise, as the MCP lifecycle requires. A client asking for 2026-07-28 was
  told the server spoke it, while the server went on speaking the
  handshake-based protocol. 2025-03-26 is not offered: it requires accepting
  JSON-RPC batches, which this server does not.

## [0.1.0] - 2026-11-07

First release.

### Added

- Project scaffold: the RFP (en/ja) with the Phase 0 measurements, the strict
  config loader (`[sslmate]` / `[validin]` keys, `[cache] dir`,
  `[network] timeout_seconds`, `CERT_LOOKUP_*` overrides) ported from
  vpn-lookup.
- Lookups from the CLI (RFP Phase 1): the ASCII-only domain gate, the SSLMate
  CT Search client (one page per call, allowance headers, our own error
  messages), the Validin certificate-history and usage client
  (`lookback=1095`), the merge of both sources into issuances with a
  per-domain summary (CAs, names outside the domain), the engine (page walk to
  the documented empty page within a cap, pacing under 5 requests a second,
  per-kind allowance stops, the Validin quota check before sending, a
  per-source cache that never stores failures), text and `--json` output, and
  `--clear-cache`.
- The MCP server (RFP Phase 2): `lookup_certs` (validation identical to the
  CLI's, the engine's whole-call refusals with their codes, a 128 KB ceiling
  that drops issuances oldest first across domains and counts them per
  domain), `cache_status` (keys, cache, SSLMate's allowance as last observed,
  Validin's remaining queries) and `get_usage`, with usage.md pinned to the
  tools, arguments, codes and result values by meta-tests.
- A live e2e suite (`make e2e`): about six SSLMate queries and one Validin
  query a run.

### Fixed (before release, from the independent review)

- An SSLMate allowance block no longer outlives its reason: it lasts until
  Retry-After passes, or for the call when there is none (it had lasted the
  MCP server's lifetime). A walk the allowance cut short is degraded and not
  cached; a refused key stops that source for the call; Validin's sample is
  never offered as the latest issuance when SSLMate failed.
