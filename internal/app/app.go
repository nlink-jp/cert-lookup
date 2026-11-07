// Package app is the CLI shell: flag parsing, input validation, dispatch and
// rendering. Everything below it is I/O-free or dependency-injected, so this is
// the only layer that touches the real process environment.
package app

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/cache"
	"github.com/nlink-jp/cert-lookup/internal/config"
	"github.com/nlink-jp/cert-lookup/internal/domain"
	"github.com/nlink-jp/cert-lookup/internal/engine"
	"github.com/nlink-jp/cert-lookup/internal/guard"
	"github.com/nlink-jp/cert-lookup/internal/mcp"
	"github.com/nlink-jp/cert-lookup/internal/sslmate"
	"github.com/nlink-jp/cert-lookup/internal/validin"
)

// Exit codes (RFP §2).
const (
	exitOK    = 0 // every source answered for every domain
	exitError = 1 // a domain or a source failed (results still printed)
	exitUsage = 2 // bad flags, bad input, configuration, or a call refused before sending
)

// MaxPerCall is the most distinct domains one invocation answers (RFP §2).
const MaxPerCall = 20

// Run executes the CLI with the given arguments and returns the process exit
// code.
func Run(args []string, version string) int {
	return run(args, version, os.Stdin, os.Stdout, os.Stderr)
}

func run(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "mcp" {
		return runMCP(args[1:], version, stdin, stdout, stderr)
	}

	fs := flag.NewFlagSet("cert-lookup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	var (
		subdomains  = fs.Bool("subdomains", false, "include certificates for subdomains")
		history     = fs.Bool("history", false, "also fetch past issuances from Validin")
		jsonOut     = fs.Bool("json", false, "structured output")
		refresh     = fs.Bool("refresh", false, "bypass the cache")
		clearCache  = fs.Bool("clear-cache", false, "delete every cache entry")
		timeout     = fs.Duration("timeout", 0, "upstream timeout (e.g. 30s)")
		configPath  = fs.String("config", "", "config file path")
		showVersion = fs.Bool("version", false, "print version")
	)
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitUsage
	}

	if *showVersion {
		printVersion(stdout, version)
		return exitOK
	}

	cfg, err := config.Load(*configPath, *timeout)
	if *clearCache {
		// Deleting cached answers is a duty (Validin terms §4(c)), so a broken
		// config does not stop it: the directory falls back to
		// CERT_LOOKUP_CACHE_DIR or the default.
		if len(positional) > 0 {
			fmt.Fprintln(stderr, "error: --clear-cache takes no domains")
			return exitUsage
		}
		dir := config.DefaultCacheDir()
		if err != nil {
			if v := strings.TrimSpace(os.Getenv("CERT_LOOKUP_CACHE_DIR")); v != "" {
				dir = v
			}
			fmt.Fprintf(stderr, "warning: config not read (%v); clearing %s\n", err, dir)
		} else {
			dir = cfg.CacheDir
		}
		n, err := (&cache.Store{Dir: dir}).Clear()
		if err != nil {
			fmt.Fprintf(stderr, "error: clear cache: %v\n", err)
			return exitError
		}
		fmt.Fprintf(stdout, "removed %d cache entries from %s\n", n, dir)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	warn(stderr, cfg)

	if len(positional) == 0 && isTerminal(stdin) {
		usage(stderr)
		return exitUsage
	}
	domains, err := gatherDomains(positional, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	if len(domains) == 0 {
		usage(stderr)
		fmt.Fprintln(stderr, "\nerror: no domains given (pass them as arguments or on stdin)")
		return exitUsage
	}
	if err := cfg.Ready(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

	rep, err := NewEngine(cfg, version).Lookup(domains, engine.Options{Subdomains: *subdomains, History: *history, Refresh: *refresh})
	if err != nil {
		var ce *engine.CallError
		if errors.As(err, &ce) {
			fmt.Fprintf(stderr, "error: %s: %s\n", ce.Code, ce.Message)
		} else {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
		return exitUsage
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "error: encode results: %v\n", err)
			return exitError
		}
	} else {
		renderText(stdout, rep)
	}
	for i := range rep.Results {
		r := &rep.Results[i]
		for _, s := range []struct {
			name string
			st   engine.SourceState
		}{{"SSLMate", r.Sources.SSLMate}, {"Validin", r.Sources.Validin}} {
			if s.st.State == engine.StateFailed {
				fmt.Fprintf(stderr, "error: %s: %s (%s): %s\n", r.Domain, s.name, s.st.Code, s.st.Message)
			}
		}
	}
	if rep.Degraded > 0 {
		return exitError
	}
	return exitOK
}

// gatherDomains validates every input before any network I/O; one bad name
// fails the whole invocation, so a typo never half-runs a lookup.
func gatherDomains(args []string, stdin io.Reader) ([]string, error) {
	raw := args
	if len(raw) == 0 {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			raw = append(raw, line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
	}
	return domain.ParseBatch(raw, MaxPerCall)
}

// NewEngine builds the engine for a configuration: one HTTP client per source,
// each refusing redirects because each carries a key.
func NewEngine(cfg *config.Config, version string) *engine.Engine {
	ua := "cert-lookup/" + version
	e := &engine.Engine{
		Cache: &cache.Store{Dir: cfg.CacheDir},
		Now:   time.Now,
		Sleep: time.Sleep,
	}
	if cfg.HasSSLMate() {
		e.SSLMate = &sslmate.Client{HTTP: keyClient(cfg), BaseURL: cfg.SSLMateBaseURL, APIKey: cfg.SSLMateKey, UserAgent: ua}
		e.SSLMateScope = scope(cfg.SSLMateBaseURL, sslmate.DefaultBaseURL, cfg.SSLMateKey)
	}
	if cfg.HasValidin() {
		e.Validin = &validin.Client{HTTP: keyClient(cfg), BaseURL: cfg.ValidinBaseURL, APIKey: cfg.ValidinKey, UserAgent: ua}
		e.ValidinScope = scope(cfg.ValidinBaseURL, validin.DefaultBaseURL, cfg.ValidinKey)
	}
	return e
}

// scope is a source's cache scope: its endpoint and a short fingerprint of its
// key. Only the fingerprint is used, and cache.Key hashes it again with the
// domain into the file name, so the key is never on disk.
func scope(baseURL, def, key string) string {
	if baseURL == "" {
		baseURL = def
	}
	sum := sha256.Sum256([]byte(key))
	return baseURL + "|" + hex.EncodeToString(sum[:8])
}

func keyClient(cfg *config.Config) *http.Client {
	return &http.Client{Timeout: cfg.Timeout, CheckRedirect: guard.RefuseRedirects}
}

// parseInterleaved parses flags that appear anywhere among the positional
// arguments, and returns the positionals (from vpn-lookup). Go's flag package
// stops at the first non-flag argument, so `cert-lookup example.com --json`
// would otherwise read --json as a domain.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}

// runMCP starts the stdio MCP server. Diagnostics go to stderr only: stdout
// belongs to the JSON-RPC stream. It starts without any key, so that get_usage
// and cache_status answer before the operator has configured anything.
func runMCP(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cert-lookup mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		timeout    = fs.Duration("timeout", 0, "upstream timeout (e.g. 30s)")
		configPath = fs.String("config", "", "config file path")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: mcp takes no positional arguments (got %q)\n", fs.Arg(0))
		return exitUsage
	}
	cfg, err := config.Load(*configPath, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	warn(stderr, cfg)
	opts := mcp.Options{Config: cfg, Engine: NewEngine(cfg, version), Version: version}
	if cfg.HasValidin() {
		vc := &validin.Client{HTTP: keyClient(cfg), BaseURL: cfg.ValidinBaseURL, APIKey: cfg.ValidinKey, UserAgent: "cert-lookup/" + version}
		opts.ValidinQuota = vc.Usage
	}
	if err := mcp.Serve(opts, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "error: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}

func warn(w io.Writer, cfg *config.Config) {
	for _, m := range cfg.Warnings {
		fmt.Fprintf(w, "warning: %s\n", m)
	}
}

// isTerminal reports whether r is an interactive terminal, so that a bare
// `cert-lookup` prints usage instead of waiting on stdin.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// printVersion is the single source of the version banner (a Homebrew
// formula's brew test calls --version).
func printVersion(w io.Writer, version string) {
	fmt.Fprintln(w, "cert-lookup "+version)
}

func usage(w io.Writer) {
	fmt.Fprint(w, strings.TrimLeft(`
cert-lookup — which certificates were issued for a domain, by whom, for which names, and are they revoked?

Reads the public Certificate Transparency logs through two indexes: SSLMate
(currently valid certificates and revocation; key required) and, with
--history, Validin (past issuances; a sample, never complete). Only the domain
names reach those two services; nothing reaches the domain itself. For your
organization's own work only.

Usage:
  cert-lookup [flags] <domain> [domain...]   # up to 20; flags may come anywhere
  cert-lookup [flags]                        # domains from stdin, one per line
  cert-lookup --clear-cache                  # delete every cache entry
  cert-lookup mcp [--config <path>] [--timeout <dur>]  # local MCP server (stdio)

Flags:
  --subdomains      include certificates for subdomains (SSLMate allows 10 such queries an hour)
  --history         also fetch past issuances from Validin (10 queries a day)
  --json            structured output (default: human-readable text)
  --refresh         bypass the cache
  --clear-cache     delete every cache entry
  --timeout <dur>   upstream timeout (e.g. 30s)
  --config <path>   config file (default ~/.config/cert-lookup/config.toml)
  --version         print version

Names must be ASCII; pass an internationalized name as punycode (xn--...).
An empty answer is not evidence that nothing was issued.

Exit codes: 0 every source answered / 1 a domain or source failed /
2 usage error or a call refused before anything was sent.
`, "\n"))
}
