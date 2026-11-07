// Package config resolves cert-lookup's settings from flags, environment
// variables and a TOML file, in that order of precedence.
//
// The file is read with nlink-jp/toml (organization ADR-026) and strictly: an
// unknown key is an error that names it, a present-but-empty value is an
// error, a number out of range is an error, and a file named with --config
// that does not exist is an error. Input that is not understood is refused,
// never ignored. (The loader is ported from vpn-lookup, the most recent
// sibling to revise it.)
//
// Loading succeeds without any key, so that the MCP handshake, get_usage and
// cache_status work before the operator has configured anything; Ready
// reports what is missing (the SSLMate key is required, the Validin key only
// for --history), and every lookup checks it first.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nlink-jp/toml"
)

// AppName is the directory name under every config and cache root.
const AppName = "cert-lookup"

// Defaults and bounds.
const (
	// DefaultTimeout covers one request. SSLMate's free tier cuts a query at
	// 15 seconds on its side; the margin is for the network.
	DefaultTimeout      = 30 * time.Second
	MaxTimeoutSeconds   = 600
	redactedPlaceholder = "[redacted]"
)

// Config holds resolved runtime settings.
type Config struct {
	SSLMateKey     string
	ValidinKey     string
	SSLMateBaseURL string // "" = the client's built-in endpoint
	ValidinBaseURL string // "" = the client's built-in endpoint
	CacheDir       string
	Timeout        time.Duration

	// Path is the config file actually read, "" when none was.
	Path string
	// Searched lists where a file was looked for when none was named.
	Searched []string
	// Warnings are conditions the operator should see once, on stderr.
	Warnings []string
}

// fileConfig mirrors the TOML document. Pointers tell "absent" from "set".
type fileConfig struct {
	SSLMate struct {
		APIKey  *string `toml:"api_key"`
		BaseURL *string `toml:"base_url"`
	} `toml:"sslmate"`
	Validin struct {
		APIKey  *string `toml:"api_key"`
		BaseURL *string `toml:"base_url"`
	} `toml:"validin"`
	Cache struct {
		Dir *string `toml:"dir"`
	} `toml:"cache"`
	Network struct {
		TimeoutSeconds *int `toml:"timeout_seconds"`
	} `toml:"network"`
}

const knownKeys = "[sslmate] api_key, base_url; [validin] api_key, base_url; [cache] dir; [network] timeout_seconds"

// Load resolves configuration. configPath is the --config flag ("" when not
// given); timeoutOverride is the --timeout flag (0 when not given).
func Load(configPath string, timeoutOverride time.Duration) (*Config, error) {
	cfg := &Config{Timeout: DefaultTimeout, CacheDir: DefaultCacheDir()}

	path := configPath
	if path == "" {
		cfg.Searched = SearchPaths()
		path = firstExisting(cfg.Searched)
	} else {
		path = expandHome(path)
	}
	if path != "" {
		if err := cfg.readFile(path, configPath != ""); err != nil {
			return nil, err
		}
	}
	if err := cfg.applyEnv(); err != nil {
		return nil, err
	}
	if timeoutOverride != 0 {
		if timeoutOverride < time.Second || timeoutOverride > MaxTimeoutSeconds*time.Second {
			return nil, fmt.Errorf("--timeout must be 1-%d seconds", MaxTimeoutSeconds)
		}
		cfg.Timeout = timeoutOverride
	}
	if err := cfg.finish(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) readFile(path string, explicit bool) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && explicit {
			return fmt.Errorf("config file %s does not exist (named with --config)", path)
		}
		return fmt.Errorf("config file %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("config file %s has permissions %04o; expected 0600 (it holds API keys).", path, perm))
	}

	var fc fileConfig
	if _, err := toml.DecodeFile(path, &fc); err != nil {
		var unknown *toml.UnknownKeysError
		if errors.As(err, &unknown) {
			names := make([]string, len(unknown.Keys))
			for i, k := range unknown.Keys {
				names[i] = k.String()
			}
			return fmt.Errorf("config file %s: unknown key(s): %s (known: %s)", path, strings.Join(names, ", "), knownKeys)
		}
		return fmt.Errorf("config file %s: %s", path, describeTOMLError(err))
	}
	cfg.Path = path

	for _, s := range []struct {
		name string
		val  *string
		dst  *string
	}{
		{"[sslmate] api_key", fc.SSLMate.APIKey, &cfg.SSLMateKey},
		{"[sslmate] base_url", fc.SSLMate.BaseURL, &cfg.SSLMateBaseURL},
		{"[validin] api_key", fc.Validin.APIKey, &cfg.ValidinKey},
		{"[validin] base_url", fc.Validin.BaseURL, &cfg.ValidinBaseURL},
		{"[cache] dir", fc.Cache.Dir, &cfg.CacheDir},
	} {
		if s.val == nil {
			continue
		}
		if strings.TrimSpace(*s.val) == "" {
			return fmt.Errorf("config file %s: %s is present but empty (remove the line to leave it unset)", path, s.name)
		}
		*s.dst = strings.TrimSpace(*s.val)
	}
	if v := fc.Network.TimeoutSeconds; v != nil {
		if *v < 1 || *v > MaxTimeoutSeconds {
			return fmt.Errorf("config file %s: [network] timeout_seconds must be 1-%d", path, MaxTimeoutSeconds)
		}
		cfg.Timeout = time.Duration(*v) * time.Second
	}
	return nil
}

// describeTOMLError says where the file is wrong without quoting what is
// there: the decoder's own messages quote the offending token (up to 40
// characters), and the token may be an API key written without quotes.
func describeTOMLError(err error) string {
	var pe *toml.ParseError
	if errors.As(err, &pe) {
		return fmt.Sprintf("not valid TOML at line %d, column %d (the text is not shown: it may hold a key — check the quoting there)", pe.Line, pe.Column)
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		return fmt.Sprintf("line %d: a value of the wrong type (strings are quoted, numbers are not)", de.Line)
	}
	return "not valid TOML (details withheld: they may quote a key)"
}

func (cfg *Config) applyEnv() error {
	for _, s := range []struct {
		name string
		dst  *string
	}{
		{"CERT_LOOKUP_SSLMATE_API_KEY", &cfg.SSLMateKey},
		{"CERT_LOOKUP_SSLMATE_BASE_URL", &cfg.SSLMateBaseURL},
		{"CERT_LOOKUP_VALIDIN_API_KEY", &cfg.ValidinKey},
		{"CERT_LOOKUP_VALIDIN_BASE_URL", &cfg.ValidinBaseURL},
		{"CERT_LOOKUP_CACHE_DIR", &cfg.CacheDir},
	} {
		if v, ok := env(s.name); ok {
			*s.dst = v
		}
	}
	if v, ok := env("CERT_LOOKUP_TIMEOUT_SECONDS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxTimeoutSeconds {
			return fmt.Errorf("CERT_LOOKUP_TIMEOUT_SECONDS must be 1-%d, got %q", MaxTimeoutSeconds, v)
		}
		cfg.Timeout = time.Duration(n) * time.Second
	}
	return nil
}

// env returns a variable's value when it is set and not blank. A variable set
// to an empty string is treated as unset, as shells commonly leave them.
func env(name string) (string, bool) {
	v := strings.TrimSpace(os.Getenv(name))
	return v, v != ""
}

// finish validates the merged settings.
func (cfg *Config) finish() error {
	for _, u := range []struct {
		name string
		dst  *string
	}{
		{"sslmate base_url", &cfg.SSLMateBaseURL},
		{"validin base_url", &cfg.ValidinBaseURL},
	} {
		if *u.dst == "" {
			continue
		}
		v, err := validateBaseURL(u.name, *u.dst)
		if err != nil {
			return err
		}
		*u.dst = v
	}
	cfg.CacheDir = expandHome(cfg.CacheDir)
	return nil
}

// validateBaseURL accepts an https URL, or an http URL to a loopback host (a
// test server), with a host and nothing that would smuggle a credential or
// change the request: no user info, query or fragment. A trailing slash is
// dropped.
//
// Errors never quote the input: Go's url.Error repeats the whole URL, and a
// value that carries user info would put the credential on stderr.
func validateBaseURL(name, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("%s: %v", name, err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s must not carry user info, a query or a fragment", name)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s has no host", name)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return "", fmt.Errorf("%s must be https (plain http only to a loopback host): the API key travels with every request", name)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// HasSSLMate and HasValidin report whether a source has a key. SSLMate is
// required (keyless use is for personal or evaluation purposes only — its API
// reference); Validin only serves --history.
func (cfg *Config) HasSSLMate() bool { return cfg.SSLMateKey != "" }
func (cfg *Config) HasValidin() bool { return cfg.ValidinKey != "" }

// Ready reports what keeps the tool from looking anything up: no SSLMate key.
func (cfg *Config) Ready() error {
	if cfg.HasSSLMate() {
		return nil
	}
	where := "no config file was found"
	if cfg.Path != "" {
		where = "read " + cfg.Path
	}
	return &NotConfiguredError{Where: where, Searched: cfg.Searched}
}

// NotConfiguredError says that the SSLMate key is missing, and where the tool
// looked.
type NotConfiguredError struct {
	Where    string
	Searched []string
}

func (e *NotConfiguredError) Error() string {
	msg := "not configured: set [sslmate] api_key (or CERT_LOOKUP_SSLMATE_API_KEY) (" + e.Where
	if len(e.Searched) > 0 {
		msg += "; searched " + strings.Join(e.Searched, ", ")
	}
	return msg + ")"
}

// Redacted returns the settings with the keys replaced by a fixed marker, for
// anything that prints or serialises them.
func (cfg *Config) Redacted() Config {
	c := *cfg
	if c.SSLMateKey != "" {
		c.SSLMateKey = redactedPlaceholder
	}
	if c.ValidinKey != "" {
		c.ValidinKey = redactedPlaceholder
	}
	return c
}

// SearchPaths lists where a config file is looked for, in order. macOS has two
// conventions and CLI users expect ~/.config there too, so both are searched —
// and ~/.config is searched even when XDG_CONFIG_HOME is set, because a file
// that exists and is silently not read is worse than none.
func SearchPaths() []string {
	var paths []string
	if x := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); x != "" {
		paths = append(paths, filepath.Join(x, AppName, "config.toml"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dot := filepath.Join(home, ".config", AppName, "config.toml")
		if len(paths) == 0 || paths[0] != dot {
			paths = append(paths, dot)
		}
		if runtime.GOOS == "darwin" {
			paths = append(paths, filepath.Join(home, "Library", "Application Support", AppName, "config.toml"))
		}
	}
	return paths
}

// DefaultCacheDir returns the default cache directory, honoring
// XDG_CACHE_HOME. Cached answers are re-fetchable transient state, so they
// belong under the cache home, not data.
func DefaultCacheDir() string {
	if x := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); x != "" {
		return filepath.Join(x, AppName)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", AppName)
	}
	return AppName + "-cache"
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
