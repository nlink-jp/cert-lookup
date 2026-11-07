// Command cert-lookup answers which certificates the public Certificate
// Transparency logs recorded for a domain — when, by which certificate
// authority, for which other names, and whether they were revoked — by layering
// SSLMate's CT Search API (current certificates) and Validin (past issuances,
// a sample) into one lookup, as a CLI and a local MCP server.
//
// Only the domain names looked up reach those two services; nothing reaches
// the domain itself.
package main

import (
	"os"

	"github.com/nlink-jp/cert-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
