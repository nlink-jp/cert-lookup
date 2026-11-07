// Package mcp is the zero-dependency stdio JSON-RPC 2.0 MCP server answering
// lookup_certs, cache_status and get_usage over the same engine the CLI uses.
//
// This package is where the response budget lives: lookup_certs's result is
// encoded compactly and, if it would cross 128 KB, loses issuances oldest
// first across every domain, counted in each domain's omitted (one page of a
// large domain measured 540-608 KB). Summaries are computed from everything and
// stay whole. The CLI's --json is never cut.
//
// get_usage is canonical: the embedded usage.md is what an agent reads before
// its first call, and meta-tests pin it to the tools, arguments and error
// codes. Tool errors are structured JSON ({code, message}), returned as results
// rather than protocol errors so that the model sees them. Arguments are decoded
// strictly (decodeArgs): an undeclared argument is refused by name, for every
// tool including those that take none. Domains are validated exactly as the CLI
// validates them (domain.ParseBatch) before anything is sent. A closing stdin is
// the shutdown signal.
package mcp
