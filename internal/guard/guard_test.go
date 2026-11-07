package guard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCleanStripsControlAndFormatCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"Let's\u001b[31mEncrypt\u0007": "Let's[31mEncrypt",
		"Sec\u202etigo\u200b":          "Sectigo",
		"  Amazon\r\n":                 "Amazon",
		"日本\u2066語\u2069":              "日本語",
		"plain":                        "plain",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCapIsCleanedAndCapped(t *testing.T) {
	long := strings.Repeat("あ", MaxText+50)
	got := Text(long)
	if r := []rune(got); len(r) != MaxText+1 || r[MaxText] != '…' {
		t.Fatalf("Text kept %d runes; want %d plus an ellipsis", len(r), MaxText)
	}
	if Text("Ex\u001bample") != "Example" {
		t.Fatal("Text must clean too")
	}
	if got := Cap("abcdef", 3); got != "abc…" {
		t.Fatalf("Cap = %q", got)
	}
	if got := Cap("abc", 3); got != "abc" {
		t.Fatalf("Cap at the limit must not cut: %q", got)
	}
}

// The URL must never reach an error message: Go's url.Error quotes the whole
// URL, which here carries the domain under investigation.
func TestScrubURLDropsTheURL(t *testing.T) {
	c := &http.Client{}
	_, err := c.Get("http://127.0.0.1:1/v1/issuances?domain=investigated.example")
	if err == nil {
		t.Skip("something is listening on 127.0.0.1:1")
	}
	if !strings.Contains(err.Error(), "investigated.example") {
		t.Fatalf("precondition: Go's error was expected to quote the URL: %v", err)
	}
	if s := ScrubURL(err).Error(); strings.Contains(s, "investigated.example") || strings.Contains(s, "domain=") {
		t.Fatalf("ScrubURL left the URL in: %s", s)
	}
}

func TestRefuseRedirectsKeepsTheKeyHome(t *testing.T) {
	var leaked string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
	}))
	defer elsewhere.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer origin.Close()

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/v1/issuances", nil)
	req.Header.Set("Authorization", "Bearer SECRET")
	resp, err := (&http.Client{CheckRedirect: RefuseRedirects}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || leaked != "" {
		t.Fatalf("status %d, leaked %q; the redirect must not be followed", resp.StatusCode, leaked)
	}
}
