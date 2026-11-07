//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/cert-lookup/internal/app"
	"github.com/nlink-jp/cert-lookup/internal/config"
	"github.com/nlink-jp/cert-lookup/internal/domain"
	"github.com/nlink-jp/cert-lookup/internal/engine"
	"github.com/nlink-jp/cert-lookup/internal/issuance"
	"github.com/nlink-jp/cert-lookup/internal/upstream"
)

// Live fixtures. example.com is the IANA-reserved example domain, chosen
// because it is published as an example, not because anyone investigates it;
// co.jp is a public suffix (Phase 0: SSLMate answers it with an empty list).
// If one of these tests starts failing, the upstream data or wire format
// changed — investigate before touching the assertion.
//
// Budget per run: about six SSLMate single-host queries (a page and the empty
// page that ends it, per lookup) and exactly one Validin query.
const (
	example      = "example.com"
	publicSuffix = "co.jp"
)

func sslmateKey(t *testing.T) string {
	t.Helper()
	k := os.Getenv("CERT_LOOKUP_SSLMATE_API_KEY")
	if k == "" {
		t.Skip("CERT_LOOKUP_SSLMATE_API_KEY must be set for the live suite")
	}
	return k
}

func liveConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{SSLMateKey: sslmateKey(t), CacheDir: t.TempDir(), Timeout: 30 * time.Second}
}

func TestLiveCurrentCertificates(t *testing.T) {
	cfg := liveConfig(t)
	rep, err := app.NewEngine(cfg, "e2e").Lookup([]string{example}, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Degraded || r.Sources.SSLMate.State != engine.StateOK || r.Sources.Validin.State != engine.StateNotRequested {
		t.Fatalf("sources = %+v", r.Sources)
	}
	if len(r.Issuances) == 0 || r.Summary.Issuances != len(r.Issuances) || r.Truncated != "" {
		t.Fatalf("summary = %+v, %d issuances, truncated %q", r.Summary, len(r.Issuances), r.Truncated)
	}
	for _, is := range r.Issuances {
		covers := false
		for _, n := range is.Names {
			if domain.Inside(n, example) && (n == example || n == "*."+example) {
				covers = true
			}
		}
		if !covers || is.Issuer.Name == "" || len(is.CAADomains) == 0 || is.Expired {
			t.Errorf("issuance = %+v", is)
		}
		if s := is.Revocation.Status; s != issuance.Revoked && s != issuance.NotRevoked && s != issuance.Unknown {
			t.Errorf("revocation status %q", s)
		}
		if strings.Join(is.SeenBy, ",") != issuance.SourceSSLMate || is.TBSSHA256 == "" {
			t.Errorf("seen_by %v tbs %q", is.SeenBy, is.TBSSHA256)
		}
	}
}

func TestLivePublicSuffixIsEmptyNotFailed(t *testing.T) {
	cfg := liveConfig(t)
	rep, err := app.NewEngine(cfg, "e2e").Lookup([]string{publicSuffix}, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Results[0]
	if r.Degraded || r.Summary.Issuances != 0 || !strings.Contains(strings.Join(r.Notes, " "), "not evidence that none was issued") {
		t.Fatalf("result = %+v", r)
	}
}

// Measured in Phase 0: a wrong key gets 401 bad_credentials whose message
// quotes the leading part of the key. None of it may come out.
func TestLiveBadKeyIsReportedWithoutEchoingIt(t *testing.T) {
	cfg := liveConfig(t)
	cfg.SSLMateKey = "999999_e2ewrongkeyvalue"
	rep, err := app.NewEngine(cfg, "e2e").Lookup([]string{example}, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	st := rep.Results[0].Sources.SSLMate
	if st.State != engine.StateFailed || st.Code != upstream.CodeInvalidAPIKey {
		t.Fatalf("state = %+v", st)
	}
	if strings.Contains(st.Message, "999999") || strings.Contains(st.Message, "e2ewrong") || strings.Contains(st.Message, "not recognized") {
		t.Fatalf("the message echoes the key or upstream's words: %s", st.Message)
	}
}

func TestLiveNetworkErrorCarriesNoURL(t *testing.T) {
	cfg := liveConfig(t)
	cfg.SSLMateBaseURL = "http://127.0.0.1:1"
	rep, err := app.NewEngine(cfg, "e2e").Lookup([]string{example}, engine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	st := rep.Results[0].Sources.SSLMate
	if st.State != engine.StateFailed || strings.Contains(st.Message, example) || strings.Contains(st.Message, cfg.SSLMateKey) {
		t.Fatalf("state = %+v", st)
	}
}

// One Validin query per run.
func TestLiveHistory(t *testing.T) {
	cfg := liveConfig(t)
	cfg.ValidinKey = os.Getenv("CERT_LOOKUP_VALIDIN_API_KEY")
	if cfg.ValidinKey == "" {
		t.Skip("CERT_LOOKUP_VALIDIN_API_KEY not set")
	}
	rep, err := app.NewEngine(cfg, "e2e").Lookup([]string{example}, engine.Options{History: true})
	if err != nil {
		t.Fatalf("%v (if quota_exhausted, Validin's 10 a day are spent — try tomorrow)", err)
	}
	r := rep.Results[0]
	if r.Degraded || r.Sources.Validin.State != engine.StateOK || r.History == nil || !r.History.Sample {
		t.Fatalf("result = %+v history = %+v", r.Sources, r.History)
	}
	if rep.ValidinRemaining == nil {
		t.Fatal("the quota check's result should be reported")
	}
	notes := strings.Join(r.Notes, " ")
	if !strings.Contains(notes, "is a sample") {
		t.Fatalf("notes = %v", r.Notes)
	}
	t.Logf("Validin: %d records; %d left today, %d this month (before the call)", r.History.Records, rep.ValidinRemaining.Daily, rep.ValidinRemaining.Monthly)
}

// The built binary, end to end: --version, a JSON lookup, a refusal, and the
// MCP server's lookup_certs answered from the cache the CLI filled.
func TestLiveBinary(t *testing.T) {
	bin := os.Getenv("CERT_LOOKUP_E2E_BINARY")
	if bin == "" {
		t.Skip("CERT_LOOKUP_E2E_BINARY not set (make e2e sets it)")
	}
	sslmateKey(t)
	dir := t.TempDir()
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"XDG_CONFIG_HOME=" + filepath.Join(dir, "config"),
		"XDG_CACHE_HOME=" + filepath.Join(dir, "cache"),
		"HOME=" + filepath.Join(dir, "home"),
		"CERT_LOOKUP_SSLMATE_API_KEY=" + os.Getenv("CERT_LOOKUP_SSLMATE_API_KEY"),
	}
	run := func(stdin string, args ...string) (string, string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return out.String(), errOut.String(), code
	}

	if out, _, code := run("", "--version"); code != 0 || !strings.HasPrefix(out, "cert-lookup ") {
		t.Fatalf("--version: code=%d out=%q", code, out)
	}
	out, errOut, code := run("", "--json", example)
	if code != 0 {
		t.Fatalf("lookup: code=%d err=%q", code, errOut)
	}
	var rep engine.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Results) != 1 || len(rep.Results[0].Issuances) == 0 {
		t.Fatalf("lookup: %v %.400s", err, out)
	}
	if _, errOut, code := run("", "https://example.com/"); code != 2 || !strings.Contains(errOut, "not a URL") {
		t.Fatalf("a URL must be refused: code=%d err=%q", code, errOut)
	}
	mcpIn := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_certs","arguments":{"domains":["` + example + `"]}}}` + "\n"
	out, errOut, code = run(mcpIn, "mcp")
	if code != 0 || !strings.Contains(out, `\"from_cache\":true`) || !strings.Contains(out, `\"provenance\"`) {
		t.Fatalf("mcp lookup_certs: code=%d out=%.400s err=%q", code, out, errOut)
	}
}
