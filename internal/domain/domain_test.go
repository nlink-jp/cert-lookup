package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeAccepts(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":                    "example.com",
		"  WWW.Example.COM.  ":           "www.example.com",
		"xn--wgv71a.jp":                  "xn--wgv71a.jp",
		"a-b.c-d.example":                "a-b.c-d.example",
		"1.example.com":                  "1.example.com",
		"co.jp":                          "co.jp", // public suffixes are not judged locally (RFP §2)
		strings.Repeat("a", 63) + ".com": strings.Repeat("a", 63) + ".com",
	} {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestNormalizeRefuses(t *testing.T) {
	for in, why := range map[string]string{
		"":                                "empty",
		"   ":                             "empty",
		"例え.jp":                           "not ASCII",
		"exa mple.com":                    "whitespace",
		"exa\u0007mple.com":               "control",
		"https://example.com":             "URL",
		"example.com/path":                "URL",
		"example.com:443":                 "URL",
		"user@example.com":                "URL",
		"*.example.com":                   "wildcard",
		"192.0.2.1":                       "IP",
		"2001:db8::1":                     "URL", // the colon is refused first; either way, not sent
		"[2001:db8::1]":                   "URL",
		"com":                             "single label",
		"example..com":                    "empty label",
		".example.com":                    "empty label",
		"-example.com":                    "hyphen",
		"example-.com":                    "hyphen",
		"exa_mple.com":                    "letters, digits",
		"example.123":                     "all digits",
		strings.Repeat("a", 64) + ".com":  "longer than 63",
		strings.Repeat("a.", 127) + "com": "longer than 253",
	} {
		_, err := Normalize(in)
		var ie *InvalidError
		if !errors.As(err, &ie) {
			t.Errorf("Normalize(%q) = %v; want an InvalidError (%s)", in, err, why)
		}
	}
}

func TestNonASCIIErrorSaysPunycode(t *testing.T) {
	_, err := Normalize("例え.jp")
	if err == nil || !strings.Contains(err.Error(), "punycode") {
		t.Fatalf("err = %v; the operator must be told to pass punycode", err)
	}
}

// The operator's input is echoed in the error, cleaned of control characters
// and capped.
func TestErrorEchoIsCleanedAndCapped(t *testing.T) {
	_, err := Normalize("bad\u001b[2J" + strings.Repeat("x", 300))
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), "\u001b") {
		t.Fatalf("the escape reached the message: %q", err)
	}
	if len(err.Error()) > 400 {
		t.Fatalf("the echo is not capped: %d bytes", len(err.Error()))
	}
}

func TestParseBatch(t *testing.T) {
	got, err := ParseBatch([]string{"Example.com", "example.com.", "www.example.com"}, 20)
	if err != nil || strings.Join(got, ",") != "example.com,www.example.com" {
		t.Fatalf("got %v, %v; want duplicates folded in input order", got, err)
	}
	if _, err := ParseBatch([]string{"example.com", "bad name"}, 20); err == nil {
		t.Fatal("one bad input must fail the whole batch")
	}
	var many []string
	for i := 0; i < 21; i++ {
		many = append(many, strings.Repeat("a", i+1)+".example.com")
	}
	var tm *TooManyError
	if _, err := ParseBatch(many, 20); !errors.As(err, &tm) || tm.Count != 21 {
		t.Fatalf("err = %v; want TooManyError for 21 distinct names", err)
	}
	dup := make([]string, 200)
	for i := range dup {
		dup[i] = "example.com"
	}
	if got, err := ParseBatch(dup, 20); err != nil || len(got) != 1 {
		t.Fatalf("200 copies of one name is one lookup: %v %v", got, err)
	}
	if _, err := ParseBatch(append(dup, "example.org"), 20); err == nil {
		t.Fatal("more than ten times max raw inputs must be refused")
	}
}

func TestInside(t *testing.T) {
	for _, c := range []struct {
		name, d string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "www.example.com", true}, // covers the host
		{"*.www.example.com", "www.example.com", true},
		{"example.com", "www.example.com", false}, // the parent is outside the host's subtree
		{"*.example.com", "a.b.example.com", false},
		{"badexample.com", "example.com", false},
		{"example.org", "example.com", false},
		{"WWW.EXAMPLE.COM", "example.com", true},
	} {
		if got := Inside(c.name, c.d); got != c.want {
			t.Errorf("Inside(%q, %q) = %v, want %v", c.name, c.d, got, c.want)
		}
	}
}
