package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nlink-jp/cert-lookup/internal/engine"
)

const tbs = "3fb2c998f9839fc264233db73cb496a4fbbe32b6b563e190644e23cb76651ec7"

// env isolates the process environment and points both sources at local fakes.
// It returns counters of requests each fake received.
func env(t *testing.T, sslmateStatus int) (*atomic.Int32, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("CERT_LOOKUP_CACHE_DIR", filepath.Join(dir, "c"))
	t.Setenv("CERT_LOOKUP_TIMEOUT_SECONDS", "")
	var sHits, vHits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sHits.Add(1)
		if sslmateStatus != http.StatusOK {
			w.WriteHeader(sslmateStatus)
			_, _ = w.Write([]byte(`{"code":"internal_error","message":"x"}`))
			return
		}
		if r.URL.Query().Get("after") != "" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"1","tbs_sha256":"` + tbs + `","dns_names":["example.com","www.example.com","related.example"],
			"issuer":{"friendly_name":"Example CA","name":"C=US, O=Example CA, CN=R1"},
			"not_before":"2026-10-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","revoked":false}]`))
	}))
	t.Cleanup(s.Close)
	v := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vHits.Add(1)
		if r.URL.Path == "/api/profile/usage" {
			_, _ = w.Write([]byte(`{"remaining":{"daily":10,"monthly":50}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"finished","records_returned":0,"limited":false,"records":{"ctstream":[]}}`))
	}))
	t.Cleanup(v.Close)
	t.Setenv("CERT_LOOKUP_SSLMATE_API_KEY", "sk")
	t.Setenv("CERT_LOOKUP_SSLMATE_BASE_URL", s.URL)
	t.Setenv("CERT_LOOKUP_VALIDIN_API_KEY", "vk")
	t.Setenv("CERT_LOOKUP_VALIDIN_BASE_URL", v.URL)
	return &sHits, &vHits
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, "v0.0.0-test", strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionNeedsNoConfig(t *testing.T) {
	env(t, http.StatusOK)
	t.Setenv("CERT_LOOKUP_TIMEOUT_SECONDS", "NaN") // a broken setting
	code, out, _ := runCLI("--version")
	if code != exitOK || out != "cert-lookup v0.0.0-test\n" {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestLookupJSONAndExitZero(t *testing.T) {
	sHits, vHits := env(t, http.StatusOK)
	code, out, errs := runCLI("example.com", "--json")
	if code != exitOK {
		t.Fatalf("code %d stderr %s", code, errs)
	}
	var rep engine.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	r := rep.Results[0]
	if r.Domain != "example.com" || r.Summary.Issuances != 1 || strings.Join(r.Summary.NamesOutside, ",") != "related.example" {
		t.Fatalf("result = %+v", r.Summary)
	}
	if sHits.Load() != 2 || vHits.Load() != 0 {
		t.Fatalf("hits sslmate %d validin %d; want the page and the empty page, and no Validin without --history", sHits.Load(), vHits.Load())
	}
}

func TestHistoryAsksValidin(t *testing.T) {
	_, vHits := env(t, http.StatusOK)
	code, out, errs := runCLI("--history", "example.com")
	if code != exitOK {
		t.Fatalf("code %d stderr %s", code, errs)
	}
	if vHits.Load() != 2 || !strings.Contains(out, "Validin history: 0 records (a sample)") || !strings.Contains(out, "queries left") {
		t.Fatalf("validin hits %d, out:\n%s", vHits.Load(), out)
	}
}

func TestHistoryWithoutValidinKeyIsRefused(t *testing.T) {
	sHits, _ := env(t, http.StatusOK)
	t.Setenv("CERT_LOOKUP_VALIDIN_API_KEY", "")
	code, _, errs := runCLI("--history", "example.com")
	if code != exitUsage || !strings.Contains(errs, "history_unavailable") || sHits.Load() != 0 {
		t.Fatalf("code %d stderr %s hits %d", code, errs, sHits.Load())
	}
}

func TestSourceFailureExitsOne(t *testing.T) {
	env(t, http.StatusInternalServerError)
	code, out, errs := runCLI("example.com")
	if code != exitError || !strings.Contains(errs, "SSLMate (upstream_error)") || !strings.Contains(out, "SSLMate failed") {
		t.Fatalf("code %d\nout %s\nerr %s", code, out, errs)
	}
	if strings.Contains(errs, `"message":"x"`) {
		t.Fatal("upstream's message must not be passed through")
	}
}

func TestBadInputSendsNothing(t *testing.T) {
	sHits, _ := env(t, http.StatusOK)
	for _, args := range [][]string{
		{"example.com", "not a domain"},
		{"https://example.com/"},
		{"例え.jp"},
		{"192.0.2.1"},
	} {
		code, _, errs := runCLI(args...)
		if code != exitUsage || errs == "" {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if sHits.Load() != 0 {
		t.Fatalf("%d requests were sent for bad input", sHits.Load())
	}
}

func TestTooManyDomains(t *testing.T) {
	env(t, http.StatusOK)
	var args []string
	for i := 0; i < MaxPerCall+1; i++ {
		args = append(args, strings.Repeat("a", i+1)+".example.com")
	}
	if code, _, errs := runCLI(args...); code != exitUsage || !strings.Contains(errs, "at most 20") {
		t.Fatalf("code %d stderr %s", code, errs)
	}
}

func TestNoKeyIsAUsageError(t *testing.T) {
	sHits, _ := env(t, http.StatusOK)
	t.Setenv("CERT_LOOKUP_SSLMATE_API_KEY", "")
	code, _, errs := runCLI("example.com")
	if code != exitUsage || !strings.Contains(errs, "[sslmate] api_key") || sHits.Load() != 0 {
		t.Fatalf("code %d stderr %s", code, errs)
	}
}

func TestDomainsFromStdin(t *testing.T) {
	sHits, _ := env(t, http.StatusOK)
	var out, errb bytes.Buffer
	code := run([]string{"--json"}, "t", strings.NewReader("# a comment\nexample.com\n\nexample.com.\n"), &out, &errb)
	if code != exitOK || sHits.Load() != 2 {
		t.Fatalf("code %d hits %d stderr %s; duplicates fold to one lookup", code, sHits.Load(), errb.String())
	}
}

func TestClearCacheWorksWithABrokenConfig(t *testing.T) {
	env(t, http.StatusOK)
	dir := os.Getenv("CERT_LOOKUP_CACHE_DIR")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"sslmate_x.json", ".tmp-123"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CERT_LOOKUP_TIMEOUT_SECONDS", "NaN")
	code, out, errs := runCLI("--clear-cache")
	if code != exitOK || !strings.Contains(out, "removed 2") || !strings.Contains(errs, "config not read") {
		t.Fatalf("code %d out %q err %q", code, out, errs)
	}
	if code, _, _ := runCLI("--clear-cache", "example.com"); code != exitUsage {
		t.Fatal("--clear-cache takes no domains")
	}
}

func TestCacheServesTheRepeat(t *testing.T) {
	sHits, _ := env(t, http.StatusOK)
	runCLI("example.com")
	runCLI("example.com")
	if sHits.Load() != 2 {
		t.Fatalf("hits %d; the repeat must come from the cache", sHits.Load())
	}
	runCLI("example.com", "--refresh")
	if sHits.Load() != 4 {
		t.Fatalf("hits %d; --refresh must re-ask", sHits.Load())
	}
}

func TestMCPIsNotBuiltYet(t *testing.T) {
	env(t, http.StatusOK)
	if code, _, errs := runCLI("mcp"); code != exitUsage || !strings.Contains(errs, "not built yet") {
		t.Fatalf("code %d err %s", code, errs)
	}
}

func TestTextRendering(t *testing.T) {
	env(t, http.StatusOK)
	code, out, _ := runCLI("example.com")
	if code != exitOK {
		t.Fatal(code)
	}
	for _, want := range []string{
		"example.com  (single host; SSLMate)",
		"issuances: 1 (earliest 2026-10-01, latest 2026-10-01)",
		"CAs: Example CA",
		"names outside example.com: related.example",
		"2026-10-01 → 2027-01-01  Example CA  not_revoked  [sslmate]",
		"note: History was not requested",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
