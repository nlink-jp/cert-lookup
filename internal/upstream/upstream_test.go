package upstream

import (
	"bytes"
	"strings"
	"testing"
)

func TestMachineCodeKeepsOnlyTokens(t *testing.T) {
	for in, want := range map[string]string{
		"rate_limited":          "rate_limited",
		"bad_credentials":       "bad_credentials",
		"has space":             "",
		"evil\u001b[2J":         "", // a bracket is not a token character
		strings.Repeat("a", 60): "", // capped, and the ellipsis is not a token character
	} {
		if got := MachineCode(in); got != want {
			t.Errorf("MachineCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestErrorMessageIsOurOwn(t *testing.T) {
	e := &Error{Source: "SSLMate", Code: CodeRateLimited, Status: 429, UpstreamCode: "rate_limited", RetryAfter: 264, Detail: "the query allowance is used up"}
	want := "SSLMate: the query allowance is used up (HTTP 429, rate_limited); retry after 264 seconds"
	if e.Error() != want {
		t.Fatalf("Error() = %q", e.Error())
	}
}

func TestReadBodyRefusesOversize(t *testing.T) {
	if _, err := ReadBody(bytes.NewReader(make([]byte, MaxBody+1))); err == nil {
		t.Fatal("an oversize body must be refused, not parsed cut")
	}
	b, err := ReadBody(strings.NewReader("[]"))
	if err != nil || string(b) != "[]" {
		t.Fatalf("ReadBody = %q, %v", b, err)
	}
}
