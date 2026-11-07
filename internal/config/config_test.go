package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points every search root and variable at a temp dir, so no test
// reads the developer's real config or keys.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	for _, k := range []string{
		"CERT_LOOKUP_SSLMATE_API_KEY", "CERT_LOOKUP_SSLMATE_BASE_URL",
		"CERT_LOOKUP_VALIDIN_API_KEY", "CERT_LOOKUP_VALIDIN_BASE_URL",
		"CERT_LOOKUP_CACHE_DIR", "CERT_LOOKUP_TIMEOUT_SECONDS",
	} {
		t.Setenv(k, "")
	}
	return dir
}

func write(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsLoadWithoutAnyKey(t *testing.T) {
	dir := isolate(t)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("loading with nothing configured must succeed (MCP handshake, get_usage): %v", err)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Fatalf("default timeout = %v", cfg.Timeout)
	}
	if cfg.CacheDir != filepath.Join(dir, "cache", AppName) {
		t.Fatalf("CacheDir = %q, want under XDG_CACHE_HOME", cfg.CacheDir)
	}
	if cfg.HasSSLMate() || cfg.HasValidin() {
		t.Fatal("no source should have a key")
	}
	var nc *NotConfiguredError
	if err := cfg.Ready(); err == nil || !asNotConfigured(err, &nc) {
		t.Fatalf("Ready() = %v, want NotConfiguredError", err)
	}
}

func asNotConfigured(err error, target **NotConfiguredError) bool {
	e, ok := err.(*NotConfiguredError)
	if ok {
		*target = e
	}
	return ok
}

func TestFileIsRead(t *testing.T) {
	dir := isolate(t)
	p := write(t, dir, `
[sslmate]
api_key = "sk"
base_url = "http://127.0.0.1:9/"

[validin]
api_key = "vk"

[cache]
dir = "~/cl-cache"

[network]
timeout_seconds = 5
`)
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSLMateKey != "sk" || cfg.ValidinKey != "vk" || !cfg.HasSSLMate() || !cfg.HasValidin() {
		t.Fatalf("keys = %q / %q", cfg.SSLMateKey, cfg.ValidinKey)
	}
	if cfg.SSLMateBaseURL != "http://127.0.0.1:9" {
		t.Fatalf("SSLMateBaseURL = %q (trailing slash dropped)", cfg.SSLMateBaseURL)
	}
	if cfg.Timeout != 5*time.Second {
		t.Fatalf("timeout %v", cfg.Timeout)
	}
	if !strings.HasSuffix(cfg.CacheDir, "cl-cache") || strings.HasPrefix(cfg.CacheDir, "~") {
		t.Fatalf("CacheDir = %q, want ~ expanded", cfg.CacheDir)
	}
	if err := cfg.Ready(); err != nil {
		t.Fatalf("Ready() = %v", err)
	}
}

// SSLMate is required; Validin alone does not make the tool ready (RFP §2).
func TestSSLMateKeyIsRequired(t *testing.T) {
	isolate(t)
	t.Setenv("CERT_LOOKUP_VALIDIN_API_KEY", "vk")
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasValidin() || cfg.Ready() == nil {
		t.Fatalf("validin=%v ready=%v; a Validin key alone must not be enough", cfg.HasValidin(), cfg.Ready())
	}
	if !strings.Contains(cfg.Ready().Error(), "[sslmate] api_key") {
		t.Fatalf("Ready() must name what is missing: %v", cfg.Ready())
	}
	t.Setenv("CERT_LOOKUP_VALIDIN_API_KEY", "")
	t.Setenv("CERT_LOOKUP_SSLMATE_API_KEY", "sk")
	cfg, err = Load("", 0)
	if err != nil || cfg.Ready() != nil || cfg.HasValidin() {
		t.Fatalf("an SSLMate key alone is enough: cfg=%+v err=%v", cfg.Redacted(), err)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := isolate(t)
	p := write(t, dir, "[sslmate]\napi_key = \"file\"\n[network]\ntimeout_seconds = 2\n")
	t.Setenv("CERT_LOOKUP_SSLMATE_API_KEY", "env")
	t.Setenv("CERT_LOOKUP_TIMEOUT_SECONDS", "7")
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSLMateKey != "env" || cfg.Timeout != 7*time.Second {
		t.Fatalf("env must win: %q %v", cfg.SSLMateKey, cfg.Timeout)
	}
}

func TestTimeoutFlagWins(t *testing.T) {
	isolate(t)
	t.Setenv("CERT_LOOKUP_TIMEOUT_SECONDS", "60")
	cfg, err := Load("", 3*time.Second)
	if err != nil || cfg.Timeout != 3*time.Second {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
	if _, err := Load("", 601*time.Second); err == nil {
		t.Fatal("a --timeout over the ceiling must be refused")
	}
}

func TestRefusesWhatItDoesNotUnderstand(t *testing.T) {
	cases := map[string]string{
		"unknown key":     "[sslmate]\napi_kee = \"x\"\n",
		"unknown section": "[crtsh]\napi_key = \"x\"\n",
		"empty key":       "[validin]\napi_key = \"  \"\n",
		"removed ttl key": "[cache]\nttl_hours = 4\n",
		"top-level key":   "timeout = \"30s\"\n",
		"timeout zero":    "[network]\ntimeout_seconds = 0\n",
		"wrong type":      "[network]\ntimeout_seconds = \"5\"\n",
		"malformed":       "[sslmate\napi_key = \"x\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := isolate(t)
			if _, err := Load(write(t, dir, body), 0); err == nil {
				t.Fatalf("%q was accepted", body)
			}
		})
	}
}

func TestUnknownKeyIsNamed(t *testing.T) {
	dir := isolate(t)
	_, err := Load(write(t, dir, "[validin]\nlookback = 30\n"), 0)
	if err == nil || !strings.Contains(err.Error(), "validin.lookback") || !strings.Contains(err.Error(), "known:") {
		t.Fatalf("err = %v; want the unknown key named and the known keys listed", err)
	}
}

func TestEnvNumbersAreChecked(t *testing.T) {
	for _, v := range []string{"0", "1e9", "NaN", "601"} {
		isolate(t)
		t.Setenv("CERT_LOOKUP_TIMEOUT_SECONDS", v)
		if _, err := Load("", 0); err == nil {
			t.Errorf("CERT_LOOKUP_TIMEOUT_SECONDS=%s was accepted", v)
		}
	}
}

func TestExplicitConfigMustExist(t *testing.T) {
	dir := isolate(t)
	_, err := Load(filepath.Join(dir, "nope.toml"), 0)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v", err)
	}
}

func TestBaseURLRules(t *testing.T) {
	ok := map[string]string{
		"https://api.example.test/":   "https://api.example.test",
		"https://api.example.test/v1": "https://api.example.test/v1",
		"http://127.0.0.1:8080":       "http://127.0.0.1:8080",
		"http://localhost:1/":         "http://localhost:1",
	}
	for in, want := range ok {
		got, err := validateBaseURL("x", in)
		if err != nil || got != want {
			t.Errorf("validateBaseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"http://api.example.test", // plain http to another machine: the key would travel in clear
		"ftp://api.example.test",
		"https://",
		"https://user:secret@api.example.test",
		"https://api.example.test/?key=secret",
		"https://api.example.test/#frag",
	} {
		if _, err := validateBaseURL("x", in); err == nil {
			t.Errorf("validateBaseURL(%q) was accepted", in)
		}
	}
}

// A malformed URL with credentials must not echo them: Go's url.Error quotes
// the whole input.
func TestBaseURLErrorNeverQuotesTheInput(t *testing.T) {
	for _, in := range []string{"https://user:s3cret@host/%zz", "https://user:s3cret@host/?k=v"} {
		_, err := validateBaseURL("sslmate base_url", in)
		if err == nil {
			t.Fatalf("%q was accepted", in)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("error leaks the credential: %v", err)
		}
	}
}

func TestPermissionWarning(t *testing.T) {
	dir := isolate(t)
	p := write(t, dir, "[sslmate]\napi_key = \"k\"\n")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "0644") {
		t.Fatalf("Warnings = %v", cfg.Warnings)
	}
}

func TestDotConfigIsFoundEvenWithXDGSet(t *testing.T) {
	dir := isolate(t)
	dot := filepath.Join(dir, "home", ".config", AppName)
	if err := os.MkdirAll(dot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dot, "config.toml"), []byte("[sslmate]\napi_key = \"k\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasSSLMate() || cfg.Path != filepath.Join(dot, "config.toml") {
		t.Fatalf("Path = %q; ~/.config must be searched even when XDG_CONFIG_HOME is set", cfg.Path)
	}
}

func TestRedactedHidesKeys(t *testing.T) {
	cfg := &Config{SSLMateKey: "sk-secret", ValidinKey: "vk-secret"}
	r := cfg.Redacted()
	if strings.Contains(r.SSLMateKey+r.ValidinKey, "secret") {
		t.Fatalf("Redacted leaked a key: %+v", r)
	}
	if cfg.SSLMateKey != "sk-secret" {
		t.Fatal("Redacted must not modify the original")
	}
}

// The decoder quotes the token it cannot parse; an API key written without
// quotes must not reach stderr (and from there an MCP client's log).
func TestParseErrorNeverQuotesTheValue(t *testing.T) {
	for _, body := range []string{
		"[sslmate]\napi_key = 7f3a9c1b2d4e5f60718293a4b5c6d7e8\n",
		"[validin]\napi_key = 2026-11-07secretkeyvalue\n",
		"[sslmate]\napi_key = secretkeyvalue\n",
		"[network]\ntimeout_seconds = \"7f3a9c1b2d4e\"\n",
	} {
		dir := isolate(t)
		_, err := Load(write(t, dir, body), 0)
		if err == nil {
			t.Fatalf("%q was accepted", body)
		}
		for _, secret := range []string{"7f3a9c1b2d4e", "secretkeyvalue"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error quotes the value: %v", err)
			}
		}
		if !strings.Contains(err.Error(), "line") {
			t.Fatalf("the error must still say where: %v", err)
		}
	}
}
